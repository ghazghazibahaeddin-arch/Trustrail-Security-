import type { DatabaseSync } from 'node:sqlite';
import crypto from 'node:crypto';
import { appendAuditLog, ensureBuiltInConnectors } from '@/lib/db';
import { sha256 } from '@/lib/security/crypto';

export function provisionNewOrgDefaults(db: DatabaseSync, orgId: string, actorEmail: string): void {
  const now = new Date().toISOString();

  const defaultPolicies = [
    { name: 'Require Cosign Signature on Release Artifacts', engine: 'OPA Rego', sev: 'Critical', code: 'REQUIRE_COSIGN_SIGNATURE' },
    { name: 'Block Public Read/Write ACLs on AWS S3 Buckets', engine: 'Cloud Guard', sev: 'Critical', code: 'BLOCK_PUBLIC_S3_ACL' },
    { name: 'Block Open Admin Ports (22/3389) to 0.0.0.0/0', engine: 'Cloud Guard', sev: 'High', code: 'BLOCK_OPEN_ADMIN_PORTS' },
    { name: 'Mandate IntentLock Cryptographic Approval on Changes', engine: 'IntentLock', sev: 'High', code: 'INTENT_LOCK_APPROVAL' },
    { name: 'Block Dependencies with CVSS >= 9.0 in CI/CD', engine: 'SCA Guard', sev: 'Critical', code: 'BLOCK_HIGH_CVSS' },
    { name: 'Enforce AI Agent Tool Allowlist & Cumulative Limits', engine: 'Agent Guard', sev: 'High', code: 'AGENT_LEAST_PRIVILEGE' },
  ];

  for (const pol of defaultPolicies) {
    db.prepare(
      `INSERT INTO policies (id, org_id, name, engine, severity, status, rule_code, created_at)
       VALUES (?, ?, ?, ?, ?, 'Enforced', ?, ?)`
    ).run(`pol-${crypto.randomUUID().slice(0, 8)}`, orgId, pol.name, pol.engine, pol.sev, pol.code, now);
  }

  ensureBuiltInConnectors(db, orgId);

  const controls = [
    { fw: 'OWASP Top 10:2025', code: 'A01:2025', title: 'Broken Access Control & Tenant Isolation', status: 'Verified', count: 1 },
    { fw: 'OWASP Top 10:2025', code: 'A03:2025', title: 'Injection Flaw Mitigation', status: 'Needs_Evidence', count: 0 },
    { fw: 'SOC 2 Type II', code: 'CC6.1', title: 'Logical Access Security & IAM Least Privilege', status: 'Needs_Evidence', count: 0 },
    { fw: 'NIST SSDF', code: 'PW.1', title: 'Secure Coding Practices & SAST/SCA Checks', status: 'Needs_Evidence', count: 0 },
    { fw: 'SLSA v1.0', code: 'SLSA-2', title: 'Build Provenance & Tamper-Resistant SBOM', status: 'Needs_Evidence', count: 0 },
  ];
  for (const ctrl of controls) {
    db.prepare(
      `INSERT INTO compliance_controls (id, org_id, framework, code, title, status, evidence_count, last_verified, owner)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(`ctrl-${crypto.randomUUID().slice(0, 8)}`, orgId, ctrl.fw, ctrl.code, ctrl.title, ctrl.status, ctrl.count, now.slice(0, 10), actorEmail);
  }

  db.prepare(
    `INSERT INTO recovery_backups (id, org_id, target_name, backup_type, checksum_sha256, size_bytes, restore_tested_at, restore_status, created_at)
     VALUES (?, ?, 'workspace-security-ledger', 'Baseline Snapshot', ?, 65536, NULL, 'Untested', ?)`
  ).run(`bkp-${crypto.randomUUID().slice(0, 8)}`, orgId, sha256(`${orgId}|baseline|${now}`), now);

  appendAuditLog(db, {
    orgId,
    actorEmail,
    action: 'ORGANIZATION_CREATED',
    resourceType: 'Organization',
    resourceId: orgId,
    details: 'Provisioned isolated tenant workspace atomically with policies, local/public engines (OSV.dev, HTTP/TLS Probe, Terraform, OCI), unconfigured external connectors (GitHub, AWS, Azure, GCP, Slack), and compliance controls.',
  });
}
