import crypto from 'node:crypto';
import { redactEvidenceSecrets } from '@/lib/security/crypto';

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type FindingCategory =
  | 'SAST'
  | 'SCA'
  | 'SECRET'
  | 'IAC'
  | 'CLOUD'
  | 'CONTAINER'
  | 'API'
  | 'SUPPLY_CHAIN';

export interface NormalizedFindingInput {
  fingerprint: string;
  title: string;
  severity: FindingSeverity;
  category: FindingCategory;
  scanner: string;
  filePath?: string;
  line?: number;
  cve?: string;
  cvss: number;
  exploitability: 'High' | 'Medium' | 'Low' | 'Proof-of-Concept';
  evidence: string;
  suggestedFix: string;
  confidence: number;
}

export interface CycloneDxComponent {
  type: 'library';
  name: string;
  version: string;
  purl: string;
  license?: string;
}

export interface CycloneDxSbom {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: 1;
  metadata: {
    timestamp: string;
    component: { name: string; type: 'application' };
  };
  components: CycloneDxComponent[];
}

export interface ScanRequestInput {
  projectName: string;
  codeContent?: string;
  filePath?: string;
  packageJsonContent?: string;
  packageLockContent?: string;
  requirementsTxtContent?: string;
  goModContent?: string;
  pomXmlContent?: string;
  githubWorkflowContent?: string;
  terraformContent?: string;
  dockerfileContent?: string;
}

export interface ScanExecutionResult {
  findings: NormalizedFindingInput[];
  sbom: CycloneDxSbom | null;
  scannersRun: string[];
  filesScanned: number;
  errors: string[];
}

const KNOWN_VULNERABLE_PACKAGES: Record<
  string,
  { belowMajorMinorPatch: string; cve: string; severity: FindingSeverity; cvss: number; fixVersion: string }
> = {
  lodash: { belowMajorMinorPatch: '4.17.21', cve: 'CVE-2021-23337', severity: 'HIGH', cvss: 8.6, fixVersion: '4.17.21' },
  minimist: { belowMajorMinorPatch: '1.2.6', cve: 'CVE-2021-44906', severity: 'CRITICAL', cvss: 9.8, fixVersion: '1.2.8' },
  axios: { belowMajorMinorPatch: '1.6.0', cve: 'CVE-2023-45857', severity: 'HIGH', cvss: 7.5, fixVersion: '1.7.7' },
  express: { belowMajorMinorPatch: '4.19.2', cve: 'CVE-2024-29041', severity: 'MEDIUM', cvss: 6.1, fixVersion: '4.21.1' },
  jsonwebtoken: { belowMajorMinorPatch: '9.0.0', cve: 'CVE-2022-23529', severity: 'HIGH', cvss: 7.6, fixVersion: '9.0.2' },
  'node-fetch': { belowMajorMinorPatch: '2.6.7', cve: 'CVE-2022-0235', severity: 'HIGH', cvss: 8.1, fixVersion: '2.7.0' },
};

const TYPOSQUAT_SUSPECTS: Record<string, string> = {
  lodahs: 'lodash',
  reqeusts: 'requests',
  crossenv: 'cross-env',
  'express-js': 'express',
  'colourama': 'colorama',
};

function compareSemver(aRaw: string, bRaw: string): number {
  const clean = (s: string) => s.replace(/^[^0-9]*/, '').split('-')[0].split('.').map((n) => parseInt(n, 10) || 0);
  const a = clean(aRaw);
  const b = clean(bRaw);
  for (let i = 0; i < 3; i++) {
    const diff = (a[i] || 0) - (b[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function makeFingerprint(parts: string[]): string {
  return crypto.createHash('sha256').update(parts.join('|')).digest('hex').slice(0, 16);
}

export function scanCodeAndSecrets(
  code: string,
  filePath = 'src/app.ts',
  projectName = 'target'
): NormalizedFindingInput[] {
  const findings: NormalizedFindingInput[] = [];
  const lines = code.split(/\r?\n/);

  lines.forEach((lineText, idx) => {
    const lineNum = idx + 1;

    // 1. Secret Detection (AWS Key, GitHub Token, Private Key, Hardcoded JWT/API Secrets)
    const awsMatch = lineText.match(/AKIA[0-9A-Z]{16}/);
    if (awsMatch) {
      findings.push({
        fingerprint: makeFingerprint([projectName, 'SECRET', 'AWS_KEY', filePath, String(lineNum)]),
        title: 'Exposed AWS Access Key ID Detected',
        severity: 'CRITICAL',
        category: 'SECRET',
        scanner: 'trustrail-secret-scanner',
        filePath,
        line: lineNum,
        cvss: 9.8,
        exploitability: 'High',
        evidence: redactEvidenceSecrets(`Matched AWS Key in ${filePath}:${lineNum} -> ${lineText.trim()}`),
        suggestedFix: 'Revoke key in AWS IAM immediately and load temporary credentials via IAM Role Assumption.',
        confidence: 0.98,
      });
    }

    const ghMatch = lineText.match(/gh[pousr]_[A-Za-z0-9_]{16,}/);
    if (ghMatch) {
      findings.push({
        fingerprint: makeFingerprint([projectName, 'SECRET', 'GH_TOKEN', filePath, String(lineNum)]),
        title: 'Exposed GitHub Personal/App Token Detected',
        severity: 'CRITICAL',
        category: 'SECRET',
        scanner: 'trustrail-secret-scanner',
        filePath,
        line: lineNum,
        cvss: 9.6,
        exploitability: 'High',
        evidence: redactEvidenceSecrets(`Matched GitHub token in ${filePath}:${lineNum} -> ${lineText.trim()}`),
        suggestedFix: 'Revoke exposed GitHub token and store secret inside encrypted CI/CD repository secrets.',
        confidence: 0.99,
      });
    }

    const genericSecretMatch = lineText.match(
      /(?:jwt_secret|api_key|apikey|secret_key|db_password|passwd|stripe)\s*[:=]\s*["']([^"']{8,})["']|sk_(?:live|test)_[A-Za-z0-9]{12,}/i
    );
    if (genericSecretMatch && !lineText.includes('process.env') && !lineText.includes('os.environ')) {
      findings.push({
        fingerprint: makeFingerprint([projectName, 'SECRET', 'HARDCODED_CRED', filePath, String(lineNum)]),
        title: 'Hardcoded Credential / Secret Literal in Source Code',
        severity: 'CRITICAL',
        category: 'SECRET',
        scanner: 'trustrail-secret-scanner',
        filePath,
        line: lineNum,
        cvss: 9.4,
        exploitability: 'High',
        evidence: redactEvidenceSecrets(`Hardcoded secret at ${filePath}:${lineNum} -> ${lineText.trim()}`),
        suggestedFix: 'Externalize credential to environment secrets manager (process.env / AWS Secrets Manager) and rotate value.',
        confidence: 0.95,
      });
    }

    if (/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(lineText)) {
      findings.push({
        fingerprint: makeFingerprint([projectName, 'SECRET', 'PRIVATE_KEY', filePath, String(lineNum)]),
        title: 'Embedded Private Key Material in Repository',
        severity: 'CRITICAL',
        category: 'SECRET',
        scanner: 'trustrail-secret-scanner',
        filePath,
        line: lineNum,
        cvss: 9.9,
        exploitability: 'High',
        evidence: `PEM private key header detected at ${filePath}:${lineNum} (key body redacted)`,
        suggestedFix: 'Remove private key from source tree, purge git history, and rotate certificate.',
        confidence: 0.99,
      });
    }

    // 2. SAST Rules
    if (
      /(?:query|execute)\s*\(\s*[`'"]\s*(?:SELECT|INSERT|UPDATE|DELETE)\b[^`'"]*\$\{|\+\s*req\.(?:query|body|params)/i.test(
        lineText
      )
    ) {
      findings.push({
        fingerprint: makeFingerprint([projectName, 'SAST', 'SQLI', filePath, String(lineNum)]),
        title: 'Potential SQL Injection via Unparameterized Query Concatenation',
        severity: 'HIGH',
        category: 'SAST',
        scanner: 'trustrail-sast-analyzer',
        filePath,
        line: lineNum,
        cvss: 8.6,
        exploitability: 'High',
        evidence: `Dynamic SQL string construction at ${filePath}:${lineNum} -> ${lineText.trim().slice(0, 120)}`,
        suggestedFix: 'Replace string interpolation/concatenation with parameterized SQL placeholders (?, $1).',
        confidence: 0.92,
      });
    }

    if (/\beval\s*\(|new\s+Function\s*\(/.test(lineText)) {
      findings.push({
        fingerprint: makeFingerprint([projectName, 'SAST', 'CODE_EVAL', filePath, String(lineNum)]),
        title: 'Unsafe Dynamic Code Evaluation (eval / new Function)',
        severity: 'HIGH',
        category: 'SAST',
        scanner: 'trustrail-sast-analyzer',
        filePath,
        line: lineNum,
        cvss: 8.1,
        exploitability: 'Medium',
        evidence: `Unsafe dynamic evaluation at ${filePath}:${lineNum} -> ${lineText.trim().slice(0, 120)}`,
        suggestedFix: 'Eliminate eval()/new Function() and use safe JSON parsing or deterministic dispatch tables.',
        confidence: 0.94,
      });
    }

    if (/child_process.*\bexec\s*\(.*(?:\$\{|req\.)/.test(lineText)) {
      findings.push({
        fingerprint: makeFingerprint([projectName, 'SAST', 'CMD_INJ', filePath, String(lineNum)]),
        title: 'OS Command Injection via Unsanitized Shell Execution',
        severity: 'CRITICAL',
        category: 'SAST',
        scanner: 'trustrail-sast-analyzer',
        filePath,
        line: lineNum,
        cvss: 9.3,
        exploitability: 'High',
        evidence: `Shell command interpolation at ${filePath}:${lineNum} -> ${lineText.trim().slice(0, 120)}`,
        suggestedFix: 'Use execFile/spawn with an explicit argument array and shell: false.',
        confidence: 0.93,
      });
    }

    if (/dangerouslySetInnerHTML|\.innerHTML\s*=/.test(lineText)) {
      findings.push({
        fingerprint: makeFingerprint([projectName, 'SAST', 'XSS', filePath, String(lineNum)]),
        title: 'Potential Cross-Site Scripting (XSS) via Unsanitized HTML Sink',
        severity: 'MEDIUM',
        category: 'SAST',
        scanner: 'trustrail-sast-analyzer',
        filePath,
        line: lineNum,
        cvss: 6.1,
        exploitability: 'Medium',
        evidence: `Direct HTML injection sink at ${filePath}:${lineNum} -> ${lineText.trim().slice(0, 120)}`,
        suggestedFix: 'Sanitize HTML content with DOMPurify or use textContent / structured React JSX instead.',
        confidence: 0.85,
      });
    }
  });

  return findings;
}

export function scanPackageDependencies(
  packageJsonRaw: string,
  projectName = 'target'
): { findings: NormalizedFindingInput[]; sbom: CycloneDxSbom; error?: string } {
  const findings: NormalizedFindingInput[] = [];
  const components: CycloneDxComponent[] = [];

  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(packageJsonRaw) as Record<string, unknown>;
  } catch (err) {
    return {
      findings: [],
      sbom: {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        serialNumber: `urn:uuid:${crypto.randomUUID()}`,
        version: 1,
        metadata: {
          timestamp: new Date().toISOString(),
          component: { name: projectName, type: 'application' },
        },
        components: [],
      },
      error: `Invalid package.json format: ${(err as Error).message}`,
    };
  }

  const allDeps: Record<string, string> = {
    ...((parsed.dependencies as Record<string, string>) || {}),
    ...((parsed.devDependencies as Record<string, string>) || {}),
  };

  for (const [pkg, versionSpec] of Object.entries(allDeps)) {
    const cleanVersion = String(versionSpec).replace(/^[^0-9]*/, '');
    components.push({
      type: 'library',
      name: pkg,
      version: cleanVersion || String(versionSpec),
      purl: `pkg:npm/${pkg}@${cleanVersion || versionSpec}`,
    });

    // Unpinned wildcard check
    if (versionSpec === '*' || versionSpec === 'latest') {
      findings.push({
        fingerprint: makeFingerprint([projectName, 'SUPPLY_CHAIN', 'UNPINNED', pkg]),
        title: `Unpinned Dependency Version Range for "${pkg}"`,
        severity: 'MEDIUM',
        category: 'SUPPLY_CHAIN',
        scanner: 'trustrail-supply-chain-scanner',
        filePath: 'package.json',
        cvss: 5.3,
        exploitability: 'Low',
        evidence: `Dependency "${pkg}": "${versionSpec}" permits arbitrary major upgrades.`,
        suggestedFix: `Pin "${pkg}" to an explicit tested semver version and verify lockfile integrity.`,
        confidence: 0.99,
      });
    }

    // Typosquatting check
    if (TYPOSQUAT_SUSPECTS[pkg]) {
      findings.push({
        fingerprint: makeFingerprint([projectName, 'SUPPLY_CHAIN', 'TYPOSQUAT', pkg]),
        title: `Potential Typosquatting Package "${pkg}" (mimics "${TYPOSQUAT_SUSPECTS[pkg]}")`,
        severity: 'CRITICAL',
        category: 'SUPPLY_CHAIN',
        scanner: 'trustrail-supply-chain-scanner',
        filePath: 'package.json',
        cvss: 9.1,
        exploitability: 'High',
        evidence: `Package "${pkg}" closely matches popular package "${TYPOSQUAT_SUSPECTS[pkg]}".`,
        suggestedFix: `Remove "${pkg}" immediately and replace with verified "${TYPOSQUAT_SUSPECTS[pkg]}".`,
        confidence: 0.95,
      });
    }

    // Known CVE vulnerability check
    const advisory = KNOWN_VULNERABLE_PACKAGES[pkg];
    if (advisory && cleanVersion && compareSemver(cleanVersion, advisory.belowMajorMinorPatch) < 0) {
      findings.push({
        fingerprint: makeFingerprint([projectName, 'SCA', advisory.cve, pkg]),
        title: `Vulnerable Dependency ${pkg}@${cleanVersion} (${advisory.cve})`,
        severity: advisory.severity,
        category: 'SCA',
        scanner: 'trustrail-sca-osv-adapter',
        filePath: 'package.json',
        cve: advisory.cve,
        cvss: advisory.cvss,
        exploitability: advisory.severity === 'CRITICAL' ? 'High' : 'Medium',
        evidence: `Installed ${pkg}@${versionSpec} is below patched version ${advisory.belowMajorMinorPatch} (${advisory.cve}).`,
        suggestedFix: `Upgrade ${pkg} to ^${advisory.fixVersion} and regenerate package-lock.json.`,
        confidence: 0.97,
      });
    }
  }

  return {
    findings,
    sbom: {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        component: { name: String(parsed.name || projectName), type: 'application' },
      },
      components,
    },
  };
}

export function scanTerraformAndIaC(
  rawContent: string,
  projectName = 'target'
): { findings: NormalizedFindingInput[]; resourcesEvaluated: number } {
  const findings: NormalizedFindingInput[] = [];
  let resourcesEvaluated = 0;

  // Support both Terraform JSON plans (resource_changes + planned_values) and HCL files
  const trimmed = rawContent.trim();
  if (trimmed.startsWith('{')) {
    try {
      const plan = JSON.parse(trimmed) as {
        resource_changes?: Array<{
          address: string;
          type: string;
          change?: { actions?: string[]; after?: Record<string, unknown> };
        }>;
        planned_values?: {
          root_module?: {
            resources?: Array<{
              address: string;
              type: string;
              values?: Record<string, unknown>;
            }>;
          };
        };
      };
      const changes = [
        ...(plan.resource_changes || []).map((rc) => ({
          address: rc.address,
          type: rc.type,
          after: rc.change?.after || {},
        })),
        ...(plan.planned_values?.root_module?.resources || []).map((r) => ({
          address: r.address,
          type: r.type,
          after: r.values || {},
        })),
      ];
      resourcesEvaluated = changes.length;

      for (const rc of changes) {
        const after = rc.after;
        const afterStr = JSON.stringify(after);

        if (rc.type === 'aws_s3_bucket_acl' || rc.type === 'aws_s3_bucket') {
          if (after.acl === 'public-read' || after.acl === 'public-read-write') {
            findings.push({
              fingerprint: makeFingerprint([projectName, 'IAC', 'S3_PUBLIC_ACL', rc.address]),
              title: `Terraform Plan Exposes S3 Bucket Publicly (${rc.address})`,
              severity: 'CRITICAL',
              category: 'IAC',
              scanner: 'trustrail-iac-terraform-scanner',
              filePath: 'terraform.tfplan.json',
              cvss: 9.1,
              exploitability: 'High',
              evidence: `Resource ${rc.address} sets acl="${String(after.acl)}" in planned state.`,
              suggestedFix: 'Set acl = "private" and attach aws_s3_bucket_public_access_block.',
              confidence: 0.99,
            });
          }
        }

        if (rc.type === 'aws_security_group' || rc.type === 'aws_security_group_rule') {
          if (afterStr.includes('0.0.0.0/0') && (afterStr.includes('22') || afterStr.includes('3389'))) {
            findings.push({
              fingerprint: makeFingerprint([projectName, 'IAC', 'SG_OPEN_ADMIN_PORT', rc.address]),
              title: `Terraform Plan Opens Admin Port (22/3389) to 0.0.0.0/0 (${rc.address})`,
              severity: 'HIGH',
              category: 'IAC',
              scanner: 'trustrail-iac-terraform-scanner',
              filePath: 'terraform.tfplan.json',
              cvss: 8.2,
              exploitability: 'High',
              evidence: `Security group ${rc.address} permits 0.0.0.0/0 ingress on management port.`,
              suggestedFix: 'Restrict cidr_blocks to corporate VPN CIDR or remove public SSH/RDP ingress.',
              confidence: 0.97,
            });
          }
        }

        if (rc.type === 'aws_iam_policy' || rc.type === 'aws_iam_role_policy') {
          if (afterStr.includes('"Action":"*"') || afterStr.includes('"Action":["*"]') || afterStr.includes('"*"')) {
            findings.push({
              fingerprint: makeFingerprint([projectName, 'IAC', 'IAM_WILDCARD', rc.address]),
              title: `Over-Privileged Wildcard IAM Policy Detected (${rc.address})`,
              severity: 'HIGH',
              category: 'IAC',
              scanner: 'trustrail-iac-terraform-scanner',
              filePath: 'terraform.tfplan.json',
              cvss: 8.4,
              exploitability: 'Medium',
              evidence: `IAM policy ${rc.address} includes wildcard "*" action/resource permissions.`,
              suggestedFix: 'Scope IAM Action and Resource ARNs strictly to required least-privilege operations.',
              confidence: 0.94,
            });
          }
        }
      }
      return { findings, resourcesEvaluated };
    } catch {
      // Fall through to HCL line scanner
    }
  }

  // HCL text scanning
  resourcesEvaluated = (rawContent.match(/resource\s+"/g) || []).length || 1;
  if (/acl\s*=\s*["']public-read(?:-write)?["']/i.test(rawContent)) {
    findings.push({
      fingerprint: makeFingerprint([projectName, 'IAC', 'HCL_S3_PUBLIC']),
      title: 'HCL Configuration Grants Public S3 Bucket Access',
      severity: 'CRITICAL',
      category: 'IAC',
      scanner: 'trustrail-iac-terraform-scanner',
      filePath: 'main.tf',
      cvss: 9.1,
      exploitability: 'High',
      evidence: 'Detected acl = "public-read" or "public-read-write" in Terraform HCL.',
      suggestedFix: 'Change acl to "private" and enforce S3 Public Access Block.',
      confidence: 0.96,
    });
  }
  if (/0\.0\.0\.0\/0/.test(rawContent) && /(?:from_port|to_port)\s*=\s*(?:22|3389)/.test(rawContent)) {
    findings.push({
      fingerprint: makeFingerprint([projectName, 'IAC', 'HCL_OPEN_SSH']),
      title: 'HCL Security Group Exposes SSH/RDP (22/3389) to Internet',
      severity: 'HIGH',
      category: 'IAC',
      scanner: 'trustrail-iac-terraform-scanner',
      filePath: 'security_groups.tf',
      cvss: 8.2,
      exploitability: 'High',
      evidence: 'Detected 0.0.0.0/0 CIDR paired with port 22 or 3389 in Terraform HCL.',
      suggestedFix: 'Restrict ingress cidr_blocks to corporate Bastion/VPN subnet.',
      confidence: 0.94,
    });
  }
  if (/aws_iam_(?:policy|role_policy)/.test(rawContent) && /\\?"Action\\?"\s*:\s*\\?"\*\\?"/i.test(rawContent)) {
    findings.push({
      fingerprint: makeFingerprint([projectName, 'IAC', 'HCL_IAM_WILDCARD']),
      title: 'HCL IAM Policy Grants Over-Privileged Wildcard (*) Permissions',
      severity: 'HIGH',
      category: 'IAC',
      scanner: 'trustrail-iac-terraform-scanner',
      filePath: 'iam.tf',
      cvss: 8.4,
      exploitability: 'Medium',
      evidence: 'Detected wildcard Action: "*" inside Terraform HCL IAM policy definition.',
      suggestedFix: 'Restrict IAM actions and resource ARNs to explicit least-privilege scopes.',
      confidence: 0.94,
    });
  }
  return { findings, resourcesEvaluated };
}

export function scanContainerDockerfile(
  dockerfileRaw: string,
  projectName = 'target'
): NormalizedFindingInput[] {
  const findings: NormalizedFindingInput[] = [];
  if (/^\s*FROM\s+[^\s:]+(?::latest)?\s*$/im.test(dockerfileRaw)) {
    findings.push({
      fingerprint: makeFingerprint([projectName, 'CONTAINER', 'UNPINNED_BASE']),
      title: 'Container Base Image Uses Unpinned or :latest Tag',
      severity: 'MEDIUM',
      category: 'CONTAINER',
      scanner: 'trustrail-container-scanner',
      filePath: 'Dockerfile',
      cvss: 5.5,
      exploitability: 'Low',
      evidence: 'Dockerfile FROM instruction lacks an immutable SHA256 digest or pinned tag.',
      suggestedFix: 'Pin FROM image with explicit version and @sha256:... digest.',
      confidence: 0.95,
    });
  }
  if (!/^\s*USER\s+(?!root\b)\S+/im.test(dockerfileRaw)) {
    findings.push({
      fingerprint: makeFingerprint([projectName, 'CONTAINER', 'ROOT_USER']),
      title: 'Container Runs as Root User (Missing Non-Root USER Directive)',
      severity: 'HIGH',
      category: 'CONTAINER',
      scanner: 'trustrail-container-scanner',
      filePath: 'Dockerfile',
      cvss: 7.4,
      exploitability: 'Medium',
      evidence: 'Dockerfile does not switch to a non-root USER prior to ENTRYPOINT/CMD.',
      suggestedFix: 'Add "USER nonroot" or create a dedicated unprivileged UID in Dockerfile.',
      confidence: 0.92,
    });
  }
  if (/(?:curl|wget)\s+[^\n]*\|\s*(?:bash|sh)\b/i.test(dockerfileRaw)) {
    findings.push({
      fingerprint: makeFingerprint([projectName, 'SUPPLY_CHAIN', 'CURL_PIPE_SHELL']),
      title: 'Untrusted Remote Script Execution in Container Build (curl | bash)',
      severity: 'HIGH',
      category: 'SUPPLY_CHAIN',
      scanner: 'trustrail-container-scanner',
      filePath: 'Dockerfile',
      cvss: 8.0,
      exploitability: 'Medium',
      evidence: 'Dockerfile pipes remote HTTP download directly into shell interpreter without SHA-256 verification.',
      suggestedFix: 'Download artifact with pinned checksum verification (sha256sum -c) before execution.',
      confidence: 0.95,
    });
  }
  return findings;
}

const COPYLEFT_OR_RESTRICTED_LICENSES = new Set(['AGPL-3.0', 'GPL-3.0', 'GPL-2.0', 'SSPL-1.0']);

export function scanMultiEcosystemManifests(
  input: {
    packageLockContent?: string;
    requirementsTxtContent?: string;
    goModContent?: string;
    pomXmlContent?: string;
  },
  projectName = 'target'
): { findings: NormalizedFindingInput[]; components: CycloneDxComponent[]; filesScanned: number } {
  const findings: NormalizedFindingInput[] = [];
  const components: CycloneDxComponent[] = [];
  let filesScanned = 0;

  // 1. npm package-lock.json (v2/v3 packages + license risk)
  if (input.packageLockContent?.trim()) {
    filesScanned += 1;
    try {
      const lock = JSON.parse(input.packageLockContent) as {
        packages?: Record<string, { version?: string; license?: string }>;
        dependencies?: Record<string, { version?: string }>;
      };
      if (lock.packages) {
        for (const [pkgPath, meta] of Object.entries(lock.packages)) {
          if (!pkgPath || !meta.version) continue;
          const pkgName = pkgPath.replace(/^node_modules\//, '').split('node_modules/').pop() || pkgPath;
          components.push({
            type: 'library',
            name: pkgName,
            version: meta.version,
            purl: `pkg:npm/${pkgName}@${meta.version}`,
            license: meta.license,
          });
          if (meta.license && COPYLEFT_OR_RESTRICTED_LICENSES.has(meta.license.toUpperCase())) {
            findings.push({
              fingerprint: makeFingerprint([projectName, 'SUPPLY_CHAIN', 'LICENSE_RISK', pkgName]),
              title: `Restrictive Copyleft License (${meta.license}) on Transitive Package "${pkgName}"`,
              severity: 'MEDIUM',
              category: 'SUPPLY_CHAIN',
              scanner: 'trustrail-license-compliance-scanner',
              filePath: 'package-lock.json',
              cvss: 4.8,
              exploitability: 'Low',
              evidence: `Transitive npm package ${pkgName}@${meta.version} declares ${meta.license} license in lockfile.`,
              suggestedFix: `Review legal compliance policy or substitute with MIT/Apache-2.0 licensed alternative.`,
              confidence: 0.96,
            });
          }
          const advisory = KNOWN_VULNERABLE_PACKAGES[pkgName];
          if (advisory && compareSemver(meta.version, advisory.belowMajorMinorPatch) < 0) {
            findings.push({
              fingerprint: makeFingerprint([projectName, 'SCA', 'LOCKFILE', advisory.cve, pkgName]),
              title: `Vulnerable Transitive Dependency ${pkgName}@${meta.version} (${advisory.cve})`,
              severity: advisory.severity,
              category: 'SCA',
              scanner: 'trustrail-sca-lockfile-scanner',
              filePath: 'package-lock.json',
              cve: advisory.cve,
              cvss: advisory.cvss,
              exploitability: advisory.severity === 'CRITICAL' ? 'High' : 'Medium',
              evidence: `Resolved lockfile dependency ${pkgName}@${meta.version} < ${advisory.belowMajorMinorPatch}.`,
              suggestedFix: `Run npm update ${pkgName} or add npm overrides to >= ${advisory.fixVersion}.`,
              confidence: 0.98,
            });
          }
        }
      }
    } catch {
      // ignore malformed lockfile JSON
    }
  }

  // 2. Python requirements.txt
  if (input.requirementsTxtContent?.trim()) {
    filesScanned += 1;
    for (const rawLine of input.requirementsTxtContent.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;
      const m = line.match(/^([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|!=)?\s*([A-Za-z0-9_.-]+)?/);
      if (!m) continue;
      const pkg = m[1].toLowerCase();
      const op = m[2] || '';
      const ver = m[3] || 'unpinned';
      components.push({
        type: 'library',
        name: pkg,
        version: ver,
        purl: `pkg:pypi/${pkg}@${ver}`,
      });
      if (!op || op === '>=') {
        findings.push({
          fingerprint: makeFingerprint([projectName, 'SUPPLY_CHAIN', 'PYPI_UNPINNED', pkg]),
          title: `Unpinned Python Dependency "${pkg}" in requirements.txt`,
          severity: 'MEDIUM',
          category: 'SUPPLY_CHAIN',
          scanner: 'trustrail-pypi-scanner',
          filePath: 'requirements.txt',
          cvss: 5.0,
          exploitability: 'Low',
          evidence: `Requirement "${line}" is not pinned with exact == version specifier or SHA-256 hash.`,
          suggestedFix: `Pin exact version (${pkg}==<version>) using pip-compile --generate-hashes.`,
          confidence: 0.95,
        });
      }
      if ((pkg === 'pyyaml' && ver !== 'unpinned' && compareSemver(ver, '5.4') < 0) || (pkg === 'urllib3' && ver !== 'unpinned' && compareSemver(ver, '1.26.18') < 0)) {
        findings.push({
          fingerprint: makeFingerprint([projectName, 'SCA', 'PYPI_CVE', pkg]),
          title: `Vulnerable Python Package ${pkg}@${ver}`,
          severity: 'HIGH',
          category: 'SCA',
          scanner: 'trustrail-pypi-scanner',
          filePath: 'requirements.txt',
          cve: pkg === 'pyyaml' ? 'CVE-2020-14343' : 'CVE-2023-45803',
          cvss: pkg === 'pyyaml' ? 9.8 : 7.5,
          exploitability: 'High',
          evidence: `Python package ${pkg}==${ver} contains known high-severity CVE.`,
          suggestedFix: `Upgrade ${pkg} to latest patched release.`,
          confidence: 0.96,
        });
      }
    }
  }

  // 3. Go go.mod
  if (input.goModContent?.trim()) {
    filesScanned += 1;
    const goRegex = /^\s*([A-Za-z0-9.-]+\/[A-Za-z0-9._/-]+)\s+(v[0-9]+\.[0-9]+\.[0-9][^\s]*)/gm;
    let m: RegExpExecArray | null;
    while ((m = goRegex.exec(input.goModContent)) !== null) {
      const mod = m[1];
      const ver = m[2];
      components.push({
        type: 'library',
        name: mod,
        version: ver,
        purl: `pkg:golang/${mod}@${ver}`,
      });
      if (mod === 'golang.org/x/net' && compareSemver(ver.replace(/^v/, ''), '0.17.0') < 0) {
        findings.push({
          fingerprint: makeFingerprint([projectName, 'SCA', 'GO_CVE', mod]),
          title: `Vulnerable Go Module ${mod}@${ver} (CVE-2023-44487 HTTP/2 Rapid Reset)`,
          severity: 'HIGH',
          category: 'SCA',
          scanner: 'trustrail-gomod-scanner',
          filePath: 'go.mod',
          cve: 'CVE-2023-44487',
          cvss: 7.5,
          exploitability: 'High',
          evidence: `go.mod specifies ${mod} ${ver} which is below patched v0.17.0.`,
          suggestedFix: 'Run go get golang.org/x/net@latest && go mod tidy.',
          confidence: 0.96,
        });
      }
    }
  }

  // 4. Maven pom.xml
  if (input.pomXmlContent?.trim()) {
    filesScanned += 1;
    const depRegex = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>[\s\S]*?<version>([^<]+)<\/version>[\s\S]*?<\/dependency>/g;
    let m: RegExpExecArray | null;
    while ((m = depRegex.exec(input.pomXmlContent)) !== null) {
      const groupId = m[1].trim();
      const artifactId = m[2].trim();
      const version = m[3].trim();
      components.push({
        type: 'library',
        name: `${groupId}:${artifactId}`,
        version,
        purl: `pkg:maven/${groupId}/${artifactId}@${version}`,
      });
      if (groupId === 'org.apache.logging.log4j' && artifactId === 'log4j-core' && compareSemver(version, '2.17.1') < 0) {
        findings.push({
          fingerprint: makeFingerprint([projectName, 'SCA', 'LOG4SHELL', groupId, artifactId]),
          title: `Critical Log4Shell RCE in ${groupId}:${artifactId}@${version} (CVE-2021-44228)`,
          severity: 'CRITICAL',
          category: 'SCA',
          scanner: 'trustrail-maven-scanner',
          filePath: 'pom.xml',
          cve: 'CVE-2021-44228',
          cvss: 10.0,
          exploitability: 'High',
          evidence: `Maven dependency ${groupId}:${artifactId} version ${version} is vulnerable to Log4Shell.`,
          suggestedFix: 'Upgrade log4j-core immediately to >= 2.17.1.',
          confidence: 0.99,
        });
      }
    }
  }

  return { findings, components, filesScanned };
}

export function scanGithubWorkflow(
  yamlContent: string,
  projectName = 'target',
  filePath = '.github/workflows/ci.yml'
): NormalizedFindingInput[] {
  const findings: NormalizedFindingInput[] = [];

  if (/permissions\s*:\s*write-all/i.test(yamlContent)) {
    findings.push({
      fingerprint: makeFingerprint([projectName, 'SUPPLY_CHAIN', 'GHA_WRITE_ALL', filePath]),
      title: `GitHub Actions Workflow Grants Excessive "permissions: write-all"`,
      severity: 'HIGH',
      category: 'SUPPLY_CHAIN',
      scanner: 'trustrail-cicd-workflow-scanner',
      filePath,
      cvss: 8.1,
      exploitability: 'Medium',
      evidence: `${filePath} grants broad write-all GITHUB_TOKEN scope across all jobs.`,
      suggestedFix: 'Set top-level "permissions: read-all" and grant minimal write scopes per job.',
      confidence: 0.98,
    });
  }

  const unpinnedAction = yamlContent.match(/uses:\s*([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@(?:main|master|latest))/i);
  if (unpinnedAction) {
    findings.push({
      fingerprint: makeFingerprint([projectName, 'SUPPLY_CHAIN', 'GHA_UNPINNED_ACTION', filePath]),
      title: `Unpinned Mutable GitHub Action Reference (${unpinnedAction[1]})`,
      severity: 'MEDIUM',
      category: 'SUPPLY_CHAIN',
      scanner: 'trustrail-cicd-workflow-scanner',
      filePath,
      cvss: 6.4,
      exploitability: 'Medium',
      evidence: `Workflow pins third-party action to mutable branch ref "${unpinnedAction[1]}" instead of 40-char commit SHA.`,
      suggestedFix: 'Pin all third-party GitHub Actions to full 40-character commit SHA digests.',
      confidence: 0.96,
    });
  }

  if (
    /on:\s*(?:[\s\S]{0,120})pull_request_target/i.test(yamlContent) &&
    /\$\{\{\s*github\.event\.(?:pull_request|comment|issue|head_commit)\./i.test(yamlContent)
  ) {
    findings.push({
      fingerprint: makeFingerprint([projectName, 'SUPPLY_CHAIN', 'GHA_PRT_INJECTION', filePath]),
      title: 'GitHub Actions Script Injection Risk via pull_request_target + Untrusted Context',
      severity: 'CRITICAL',
      category: 'SUPPLY_CHAIN',
      scanner: 'trustrail-cicd-workflow-scanner',
      filePath,
      cvss: 9.3,
      exploitability: 'High',
      evidence: `Workflow combines pull_request_target trigger with untrusted \${{ github.event.* }} interpolation.`,
      suggestedFix: 'Replace pull_request_target or pass untrusted fields through sanitized environment variables.',
      confidence: 0.95,
    });
  }

  return findings;
}

export function executeUnifiedScan(input: ScanRequestInput): ScanExecutionResult {
  const findings: NormalizedFindingInput[] = [];
  const scannersRun: string[] = [];
  const errors: string[] = [];
  let sbom: CycloneDxSbom | null = null;
  let filesScanned = 0;

  if (input.codeContent && input.codeContent.trim().length > 0) {
    scannersRun.push('trustrail-sast-analyzer', 'trustrail-secret-scanner');
    filesScanned += 1;
    findings.push(...scanCodeAndSecrets(input.codeContent, input.filePath || 'src/index.ts', input.projectName));
  }

  if (input.packageJsonContent && input.packageJsonContent.trim().length > 0) {
    scannersRun.push('trustrail-sca-osv-adapter', 'trustrail-supply-chain-scanner');
    filesScanned += 1;
    const sca = scanPackageDependencies(input.packageJsonContent, input.projectName);
    if (sca.error) errors.push(sca.error);
    findings.push(...sca.findings);
    sbom = sca.sbom;
  }

  const multi = scanMultiEcosystemManifests(
    {
      packageLockContent: input.packageLockContent,
      requirementsTxtContent: input.requirementsTxtContent,
      goModContent: input.goModContent,
      pomXmlContent: input.pomXmlContent,
    },
    input.projectName
  );
  if (multi.filesScanned > 0) {
    scannersRun.push('trustrail-multi-ecosystem-sca');
    filesScanned += multi.filesScanned;
    findings.push(...multi.findings);
    if (!sbom) {
      sbom = {
        bomFormat: 'CycloneDX',
        specVersion: '1.5',
        serialNumber: `urn:uuid:${crypto.randomUUID()}`,
        version: 1,
        metadata: {
          timestamp: new Date().toISOString(),
          component: { name: input.projectName, type: 'application' },
        },
        components: multi.components,
      };
    } else if (multi.components.length > 0) {
      const seen = new Set(sbom.components.map((c) => c.purl));
      for (const comp of multi.components) {
        if (!seen.has(comp.purl)) {
          sbom.components.push(comp);
          seen.add(comp.purl);
        }
      }
    }
  }

  if (input.githubWorkflowContent && input.githubWorkflowContent.trim().length > 0) {
    scannersRun.push('trustrail-cicd-workflow-scanner');
    filesScanned += 1;
    findings.push(...scanGithubWorkflow(input.githubWorkflowContent, input.projectName));
  }

  if (input.terraformContent && input.terraformContent.trim().length > 0) {
    scannersRun.push('trustrail-iac-terraform-scanner');
    filesScanned += 1;
    const iac = scanTerraformAndIaC(input.terraformContent, input.projectName);
    findings.push(...iac.findings);
  }

  if (input.dockerfileContent && input.dockerfileContent.trim().length > 0) {
    scannersRun.push('trustrail-container-scanner');
    filesScanned += 1;
    findings.push(...scanContainerDockerfile(input.dockerfileContent, input.projectName));
  }

  // Deduplicate by fingerprint and enforce universal secret redaction across ALL scanner findings
  const uniqueMap = new Map<string, NormalizedFindingInput>();
  for (const f of findings) {
    if (!uniqueMap.has(f.fingerprint)) {
      uniqueMap.set(f.fingerprint, {
        ...f,
        evidence: redactEvidenceSecrets(f.evidence),
      });
    }
  }

  return {
    findings: Array.from(uniqueMap.values()),
    sbom,
    scannersRun,
    filesScanned,
    errors,
  };
}

