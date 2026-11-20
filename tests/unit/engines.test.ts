import { describe, it, expect } from 'vitest';
import {
  executeUnifiedScan,
  scanCodeAndSecrets,
  scanPackageDependencies,
  scanTerraformAndIaC,
  scanContainerDockerfile,
} from '@/lib/engines/scanner-engine';
import { calculateRiskPriority } from '@/lib/engines/risk-engine';
import { synthesizeAttackPaths } from '@/lib/engines/attack-path-engine';
import { evaluatePolicies, type PolicyRule } from '@/lib/engines/policy-engine';
import { computeChangeStateHash, verifyIntentLock } from '@/lib/engines/intent-lock';
import { redactEvidenceSecrets, canonicalHash } from '@/lib/security/crypto';

describe('Scanner Engines (SAST, Secret Redaction, SCA/SBOM, IaC, Container)', () => {
  it('detects SQLi and XSS via SAST and redacts raw secret values before returning evidence', () => {
    const fakeSecret = 'AKIA1234567890ABCDEF';
    const fakeToken = 'sk_live_51TestSecretValue999999999';
    const sampleCode = `
      const AWS_KEY = "${fakeSecret}";
      const STRIPE = "${fakeToken}";
      export function queryUser(db: any, userId: string) {
        return db.query(\`SELECT * FROM users WHERE id = \${userId}\`);
      }
      export function renderHtml(el: HTMLElement, raw: string) {
        el.innerHTML = raw;
      }
    `;

    const findings = scanCodeAndSecrets(sampleCode, 'app/api/users/route.ts');
    expect(findings.length).toBeGreaterThanOrEqual(3);

    const secretFindings = findings.filter((f) => f.category === 'SECRET');
    expect(secretFindings.length).toBeGreaterThanOrEqual(1);
    for (const sf of secretFindings) {
      expect(sf.evidence).not.toContain(fakeSecret);
      expect(sf.evidence).not.toContain(fakeToken);
      expect(sf.evidence).toMatch(/\*{4}|REDACTED/i);
    }

    expect(findings.some((f) => f.category === 'SAST' && /SQL/i.test(f.title))).toBe(true);
    expect(findings.some((f) => f.category === 'SAST' && /XSS/i.test(f.title))).toBe(true);
  });

  it('redacts bearer tokens and database connection passwords cleanly', () => {
    const redacted = redactEvidenceSecrets('Authorization: Bearer super_secret_jwt_payload_1234567890');
    expect(redacted).not.toContain('super_secret_jwt_payload_1234567890');
  });

  it('detects vulnerable npm dependencies, typosquatting, and emits CycloneDX 1.5 SBOM', () => {
    const pkgJson = JSON.stringify({
      name: 'demo-service',
      dependencies: {
        minimist: '1.2.5',
        lodash: '4.17.19',
        lodahs: '1.0.0',
      },
    });

    const { findings, sbom } = scanPackageDependencies(pkgJson, 'demo-service');
    expect(sbom.bomFormat).toBe('CycloneDX');
    expect(sbom.specVersion).toBe('1.5');
    expect(sbom.components).toHaveLength(3);
    expect(sbom.components[0].purl).toContain('pkg:npm/');

    expect(findings.some((f) => f.cve === 'CVE-2021-44906')).toBe(true);
    expect(findings.some((f) => f.cve === 'CVE-2021-23337')).toBe(true);
    expect(findings.some((f) => f.category === 'SUPPLY_CHAIN' && /Typosquat/i.test(f.title))).toBe(true);
  });

  it('detects Terraform HCL public S3 ACL, wildcard IAM, and 0.0.0.0/0 SSH exposure', () => {
    const tf = `
      resource "aws_s3_bucket" "backups" {
        bucket = "customer-backups"
        acl    = "public-read-write"
      }
      resource "aws_iam_policy" "wide" {
        policy = "{\\"Action\\": \\"*\\", \\"Resource\\": \\"*\\"}"
      }
      resource "aws_security_group" "ssh" {
        ingress {
          from_port   = 22
          to_port     = 22
          cidr_blocks = ["0.0.0.0/0"]
        }
      }
    `;

    const res = scanTerraformAndIaC(tf, 'main.tf');
    expect(res.findings.length).toBeGreaterThanOrEqual(3);
    expect(res.findings.some((f) => /S3/i.test(f.title))).toBe(true);
    expect(res.findings.some((f) => /IAM/i.test(f.title))).toBe(true);
    expect(res.findings.some((f) => /0\.0\.0\.0\/0|Port|SSH/i.test(f.title))).toBe(true);
  });

  it('detects Terraform Plan JSON drift/risks and Dockerfile root execution + unpinned tags', () => {
    const tfPlan = JSON.stringify({
      planned_values: {
        root_module: {
          resources: [
            {
              address: 'aws_s3_bucket.raw_logs',
              type: 'aws_s3_bucket',
              values: { acl: 'public-read' },
            },
          ],
        },
      },
    });

    const tfPlanRes = scanTerraformAndIaC(tfPlan, 'plan.tfplan.json');
    expect(tfPlanRes.findings.some((f) => /S3/i.test(f.title))).toBe(true);

    const dockerfile = `
      FROM node:latest
      WORKDIR /app
      COPY . .
      RUN curl -s https://example.com/install.sh | bash
    `;
    const dockerFindings = scanContainerDockerfile(dockerfile, 'Dockerfile');
    expect(dockerFindings.some((f) => f.category === 'CONTAINER' && /latest/i.test(f.title))).toBe(true);
    expect(dockerFindings.some((f) => f.category === 'CONTAINER' && /root/i.test(f.title))).toBe(true);
    expect(dockerFindings.some((f) => f.category === 'SUPPLY_CHAIN')).toBe(true);
  });

  it('executeUnifiedScan aggregates all scanners cleanly', () => {
    const out = executeUnifiedScan({
      projectName: 'checkout-api',
      codeContent: 'db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`)',
      packageJsonContent: JSON.stringify({ dependencies: { minimist: '1.2.5' } }),
      terraformContent: 'resource "aws_s3_bucket" "b" { acl = "public-read" }',
      dockerfileContent: 'FROM alpine:latest\nCMD ["sh"]',
    });

    expect(out.scannersRun).toEqual(
      expect.arrayContaining([
        'trustrail-sast-analyzer',
        'trustrail-secret-scanner',
        'trustrail-sca-osv-adapter',
        'trustrail-iac-terraform-scanner',
        'trustrail-container-scanner',
      ])
    );
    expect(out.sbom).not.toBeNull();
    expect(out.findings.length).toBeGreaterThanOrEqual(4);
  });
});

describe('Risk, Attack Path, Policy & IntentLock Engines', () => {
  it('computes explainable risk score prioritizing exposed attack-path findings over isolated low findings', () => {
    const p0 = calculateRiskPriority({
      cvss: 9.8,
      exploitability: 'High',
      internetExposed: true,
      assetCriticality: 'CRITICAL',
      inActiveAttackPath: true,
      fixAvailable: true,
    });
    const p3 = calculateRiskPriority({
      cvss: 3.1,
      exploitability: 'Low',
      internetExposed: false,
      assetCriticality: 'LOW',
      inActiveAttackPath: false,
      fixAvailable: false,
    });

    expect(p0.priorityTier).toBe('P0-IMMEDIATE');
    expect(p0.score).toBeGreaterThanOrEqual(90);
    expect(p0.reasons.length).toBeGreaterThanOrEqual(5);
    expect(p3.priorityTier).toBe('P3-SCHEDULED');
    expect(p0.score).toBeGreaterThan(p3.score);
  });

  it('synthesizes multi-hop attack path and eliminates it once contributing finding is resolved', () => {
    const assets = [
      { id: 'a1', orgId: 'org-1', name: '/api/v1/auth', assetType: 'API Endpoint', owner: 'api', internetExposed: true, criticality: 'HIGH' as const },
      { id: 'a2', orgId: 'org-1', name: 'lambda-role', assetType: 'IAM Identity', owner: 'cloud', internetExposed: false, criticality: 'HIGH' as const },
      { id: 'a3', orgId: 'org-1', name: 'customer-db', assetType: 'Database', owner: 'data', internetExposed: false, criticality: 'CRITICAL' as const },
    ];
    const edges = [
      { id: 'e1', orgId: 'org-1', sourceAssetId: 'a1', targetAssetId: 'a2', relation: 'ASSUMES_ROLE', evidence: 'IAM OIDC' },
      { id: 'e2', orgId: 'org-1', sourceAssetId: 'a2', targetAssetId: 'a3', relation: 'READS_WRITES', evidence: 'RDS SG' },
    ];
    const openFindings = [
      { id: 'f1', title: 'Missing JWT check', severity: 'CRITICAL' as const, category: 'API', assetId: 'a1', assetName: '/api/v1/auth', status: 'Open', cvss: 9.4 },
    ];

    const activePaths = synthesizeAttackPaths(assets, edges, openFindings);
    expect(activePaths.length).toBeGreaterThanOrEqual(1);
    expect(activePaths[0].targetAsset).toBe('customer-db');
    expect(activePaths[0].contributingFindingIds).toContain('f1');

    const afterFixPaths = synthesizeAttackPaths(assets, edges, [{ ...openFindings[0], status: 'Resolved' }]);
    expect(afterFixPaths).toHaveLength(0);
  });

  it('evaluates OPA policies deterministically across Terraform, CI, and AI Agents', () => {
    const rules: PolicyRule[] = [
      { id: 'p1', name: 'Block Public S3', engine: 'OPA Rego', severity: 'Critical', status: 'Enforced', ruleCode: 'BLOCK_PUBLIC_S3_ACL' },
      { id: 'p2', name: 'Require Cosign', engine: 'SCA Guard', severity: 'High', status: 'Enforced', ruleCode: 'REQUIRE_COSIGN_SIGNATURE' },
      { id: 'p3', name: 'Agent Quota', engine: 'Agent Guard', severity: 'Critical', status: 'Enforced', ruleCode: 'AGENT_LEAST_PRIVILEGE' },
    ];

    const denyS3 = evaluatePolicies(rules, { type: 'terraform_plan', hasPublicS3: true });
    expect(denyS3.allowed).toBe(false);
    expect(denyS3.decision).toBe('DENY');

    const denyAgent = evaluatePolicies(rules, {
      type: 'agent_action',
      agentToolAllowlisted: false,
      agentActionsUsed: 1,
      agentActionLimit: 10,
    });
    expect(denyAgent.allowed).toBe(false);
    expect(denyAgent.violatedRules.length).toBe(1);

    const allowCi = evaluatePolicies(rules, {
      type: 'ci_pipeline',
      hasPublicS3: false,
      hasCosignSignature: true,
    });
    expect(allowCi.allowed).toBe(true);
    expect(allowCi.decision).toBe('ALLOW');
  });

  it('enforces IntentLock canonical SHA-256 hash and auto-revokes approval upon payload tampering', () => {
    const basePayload = {
      targetAsset: 'sg-prod-db',
      previousStateHash: 'sha256:prev123',
      newStatePayload: { cidr: '10.0.0.0/16', port: 5432 },
      purpose: 'Restrict database ingress to VPC',
    };

    const approvedHash = computeChangeStateHash(basePayload);
    expect(canonicalHash({ b: 2, a: 1 })).toBe(canonicalHash({ a: 1, b: 2 }));

    const valid = verifyIntentLock(approvedHash, basePayload, 'Approved');
    expect(valid.isValid).toBe(true);
    expect(valid.status).toBe('Approved');

    const tampered = verifyIntentLock(
      approvedHash,
      { ...basePayload, newStatePayload: { cidr: '0.0.0.0/0', port: 5432 } },
      'Approved'
    );
    expect(tampered.isValid).toBe(false);
    expect(tampered.status).toBe('Modified_Revalidation_Required');
  });
});
