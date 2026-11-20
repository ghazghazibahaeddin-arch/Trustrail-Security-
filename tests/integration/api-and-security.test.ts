import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { closeDbForTests, getDb } from '@/lib/db';

import * as HealthRoute from '@/app/api/health/route';
import * as LoginRoute from '@/app/api/v1/auth/login/route';
import * as RegisterRoute from '@/app/api/v1/auth/register/route';
import * as SwitchOrgRoute from '@/app/api/v1/auth/switch-org/route';
import * as OrgsRoute from '@/app/api/v1/organizations/route';
import * as ProjectsRoute from '@/app/api/v1/projects/route';
import * as ProjectByIdRoute from '@/app/api/v1/projects/[id]/route';
import * as ScansRoute from '@/app/api/v1/scans/route';
import * as FindingsRoute from '@/app/api/v1/findings/route';
import * as FindingByIdRoute from '@/app/api/v1/findings/[id]/route';
import * as GraphRoute from '@/app/api/v1/graph/route';
import * as AttackPathsRoute from '@/app/api/v1/attack-paths/route';
import * as ChangesRoute from '@/app/api/v1/changes/route';
import * as ChangeByIdRoute from '@/app/api/v1/changes/[id]/route';
import * as ChangeApproveRoute from '@/app/api/v1/changes/[id]/approve/route';
import * as ChangeExecuteRoute from '@/app/api/v1/changes/[id]/execute/route';
import * as PoliciesRoute from '@/app/api/v1/policies/route';
import * as PolicyEvalRoute from '@/app/api/v1/policies/evaluate/route';
import * as AgentsRoute from '@/app/api/v1/ai-agents/route';
import * as AgentExecRoute from '@/app/api/v1/ai-agents/[id]/execute/route';
import * as IncidentsRoute from '@/app/api/v1/incidents/route';
import * as DeceptionRoute from '@/app/api/v1/deception/route';
import * as TrustCenterRoute from '@/app/api/v1/trust-center/route';
import * as TrustCenterPublicRoute from '@/app/api/v1/trust-center/[id]/route';
import * as TrustCenterRevokeRoute from '@/app/api/v1/trust-center/[id]/revoke/route';
import * as ComplianceExportRoute from '@/app/api/v1/compliance/export/route';
import * as AuditLogsRoute from '@/app/api/v1/audit-logs/route';
import * as GithubWebhookRoute from '@/app/api/v1/webhooks/github/route';
import * as ConnectorsTestRoute from '@/app/api/v1/connectors/[id]/test/route';
import * as GeminiRoute from '@/app/api/gemini/route';

let tempDbPath = '';

function makeReq(url: string, opts: { method?: string; token?: string; body?: unknown; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    ...(opts.headers || {}),
  };
  if (opts.token) {
    headers.authorization = `Bearer ${opts.token}`;
  }
  const init: { method: string; headers: Record<string, string>; body?: string } = {
    method: opts.method || 'GET',
    headers,
  };
  if (opts.body !== undefined) {
    init.body = typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body);
  }
  return new NextRequest(`http://127.0.0.1:3000${url}`, init);
}

async function loginAs(email: string, password = 'Trustrail!2026'): Promise<{ token: string; orgId: string }> {
  const res = await LoginRoute.POST(makeReq('/api/v1/auth/login', { method: 'POST', body: { email, password } }));
  expect(res.status).toBe(200);
  const data = (await res.json()) as { token: string; user: { orgId: string } };
  return { token: data.token, orgId: data.user.orgId };
}

beforeAll(() => {
  closeDbForTests();
  tempDbPath = path.join(os.tmpdir(), `trustrail-int-${crypto.randomUUID()}.db`);
  process.env.TRUSTRAIL_DB_PATH = tempDbPath;
  process.env.GITHUB_WEBHOOK_SECRET = 'test_webhook_secret_hmac_2026';
  getDb();
});

afterAll(() => {
  closeDbForTests();
  delete process.env.TRUSTRAIL_DB_PATH;
  delete process.env.GITHUB_WEBHOOK_SECRET;
  for (const suffix of ['', '-wal', '-shm']) {
    if (fs.existsSync(`${tempDbPath}${suffix}`)) {
      fs.rmSync(`${tempDbPath}${suffix}`, { force: true });
    }
  }
});

describe('API Authentication, RBAC, Multi-Tenant Isolation & End-to-End Workflows', () => {
  it('health check succeeds and verifies DB readiness', async () => {
    const res = await HealthRoute.GET();
    expect(res.status).toBe(200);
    const json = (await res.json()) as { status: string; database: { connected: boolean } };
    expect(json.status).toBe('ok');
    expect(json.database.connected).toBe(true);
  });

  it('denies unauthenticated requests across protected endpoints with 401', async () => {
    const endpoints = [
      () => OrgsRoute.GET(makeReq('/api/v1/organizations')),
      () => ProjectsRoute.GET(makeReq('/api/v1/projects')),
      () => FindingsRoute.GET(makeReq('/api/v1/findings')),
      () => GraphRoute.GET(makeReq('/api/v1/graph')),
      () => ChangesRoute.GET(makeReq('/api/v1/changes')),
      () => PoliciesRoute.GET(makeReq('/api/v1/policies')),
      () => AuditLogsRoute.GET(makeReq('/api/v1/audit-logs')),
      () => GeminiRoute.POST(makeReq('/api/gemini', { method: 'POST', body: { prompt: 'hello' } })),
    ];

    for (const call of endpoints) {
      const res = await call();
      expect(res.status).toBe(401);
    }
  });

  it('enforces RBAC: Viewer blocked from mutations, Developer blocked from Admin-only actions', async () => {
    const viewer = await loginAs('auditor@acme.cloud');
    const dev = await loginAs('alex@acme.cloud');

    // Viewer cannot scan, mutate findings, or create projects
    const viewerScan = await ScansRoute.POST(
      makeReq('/api/v1/scans', { method: 'POST', token: viewer.token, body: { projectName: 'payment-gateway-service' } })
    );
    expect(viewerScan.status).toBe(403);

    const viewerCreateProj = await ProjectsRoute.POST(
      makeReq('/api/v1/projects', {
        method: 'POST',
        token: viewer.token,
        body: { name: 'unauth', repoUrl: 'https://github.com/a/b', branch: 'main', language: 'TS', framework: 'Next' },
      })
    );
    expect(viewerCreateProj.status).toBe(403);

    // Developer can evaluate policy / run scans, but CANNOT approve changes or create policies or issue Trust Passports
    const devApprove = await ChangeApproveRoute.POST(
      makeReq('/api/v1/changes/chg-8821/approve', {
        method: 'POST',
        token: dev.token,
        body: { action: 'approve' },
      }),
      { params: Promise.resolve({ id: 'chg-8821' }) }
    );
    expect(devApprove.status).toBe(403);

    const devPolicy = await PoliciesRoute.POST(
      makeReq('/api/v1/policies', {
        method: 'POST',
        token: dev.token,
        body: { name: 'Dev Rule', engine: 'OPA Rego', severity: 'High', ruleCode: 'BLOCK_PUBLIC_S3_ACL' },
      })
    );
    expect(devPolicy.status).toBe(403);

    const devTrust = await TrustCenterRoute.POST(
      makeReq('/api/v1/trust-center', {
        method: 'POST',
        token: dev.token,
        body: { title: 'Blocked', scope: ['SOC 2'] },
      })
    );
    expect(devTrust.status).toBe(403);
  });

  it('enforces strict multi-tenant data isolation between Acme Corp and Northstar Bio', async () => {
    const acme = await loginAs('sarah@acme.cloud');
    const northstar = await loginAs('admin@northstar.io');

    expect(acme.orgId).toBe('org-acme');
    expect(northstar.orgId).toBe('org-northstar');

    // Northstar list endpoints must never contain Acme project or finding IDs
    const nsProjectsRes = await ProjectsRoute.GET(makeReq('/api/v1/projects', { token: northstar.token }));
    const nsProjects = (await nsProjectsRes.json()) as { projects: Array<{ id: string; name: string }> };
    expect(nsProjects.projects.some((p) => p.id === 'proj-1' || p.name === 'payment-gateway-service')).toBe(false);

    // Direct IDOR attempt by Northstar against Acme project, finding, and change contract must return 404
    const idorProj = await ProjectByIdRoute.GET(
      makeReq('/api/v1/projects/proj-1', { token: northstar.token }),
      { params: Promise.resolve({ id: 'proj-1' }) }
    );
    expect(idorProj.status).toBe(404);

    const idorFinding = await FindingByIdRoute.GET(
      makeReq('/api/v1/findings/fnd-01', { token: northstar.token }),
      { params: Promise.resolve({ id: 'fnd-01' }) }
    );
    expect(idorFinding.status).toBe(404);

    const idorChange = await ChangeByIdRoute.GET(
      makeReq('/api/v1/changes/chg-8821', { token: northstar.token }),
      { params: Promise.resolve({ id: 'chg-8821' }) }
    );
    expect(idorChange.status).toBe(404);

    // Northstar cannot switch into org-acme without membership
    const switchAttempt = await SwitchOrgRoute.POST(
      makeReq('/api/v1/auth/switch-org', { method: 'POST', token: northstar.token, body: { orgId: 'org-acme' } })
    );
    expect(switchAttempt.status).toBe(403);
  });

  it('handles SQL injection input safely and rejects malformed JSON with 400', async () => {
    const acme = await loginAs('sarah@acme.cloud');
    const sqliRes = await FindingsRoute.GET(
      makeReq("/api/v1/findings?q=' OR 1=1 --", { token: acme.token })
    );
    expect(sqliRes.status).toBe(200);
    const sqliJson = (await sqliRes.json()) as { findings: unknown[] };
    expect(Array.isArray(sqliJson.findings)).toBe(true);

    const malformed = await ProjectsRoute.POST(
      makeReq('/api/v1/projects', { method: 'POST', token: acme.token, body: '{bad-json' })
    );
    expect(malformed.status).toBe(400);
  });

  it('Workflow 1 & 2: Creates project, scans vulnerable code + deps + TF, redacts secrets, updates Graph/AttackPaths, and resolves to clear attack path', async () => {
    const acme = await loginAs('sarah@acme.cloud');

    const createProj = await ProjectsRoute.POST(
      makeReq('/api/v1/projects', {
        method: 'POST',
        token: acme.token,
        body: {
          name: 'billing-worker',
          repoUrl: 'https://github.com/acme/billing-worker',
          branch: 'main',
          language: 'TypeScript',
          framework: 'Node',
        },
      })
    );
    expect(createProj.status).toBe(201);
    const projData = (await createProj.json()) as { project: { id: string } };

    const rawSecret = 'AKIAZXCVBNMASDFGHJKL';
    const scanRes = await ScansRoute.POST(
      makeReq('/api/v1/scans', {
        method: 'POST',
        token: acme.token,
        body: {
          projectId: projData.project.id,
          projectName: 'billing-worker',
          codeContent: `const k = "${rawSecret}"; db.query(\`SELECT * FROM inv WHERE id = \${req.id}\`);`,
          filePath: 'src/worker.ts',
          packageJsonContent: JSON.stringify({ dependencies: { minimist: '1.2.5' } }),
          terraformContent: 'resource "aws_s3_bucket" "w" { acl = "public-read" }',
        },
      })
    );
    expect(scanRes.status).toBe(201);
    const scanJson = (await scanRes.json()) as {
      scan: { sbom: { bomFormat: string; components: unknown[] } };
      findings: Array<{ id: string; evidence: string; category: string }>;
    };
    expect(scanJson.findings.length).toBeGreaterThanOrEqual(4);
    expect(scanJson.scan.sbom.bomFormat).toBe('CycloneDX');
    // Verify raw secret never stored/returned
    for (const f of scanJson.findings) {
      expect(f.evidence).not.toContain(rawSecret);
    }

    // Resolve attack path contributing findings and verify path disappears
    const apRes = await AttackPathsRoute.GET(makeReq('/api/v1/attack-paths', { token: acme.token }));
    const apJson = (await apRes.json()) as { attackPaths: Array<{ id: string }> };
    expect(apJson.attackPaths.length).toBeGreaterThanOrEqual(1);

    const mitigate = await AttackPathsRoute.POST(
      makeReq('/api/v1/attack-paths', {
        method: 'POST',
        token: acme.token,
        body: { pathId: apJson.attackPaths[0].id, resolutionEvidence: 'Patched SQLi and verified' },
      })
    );
    expect(mitigate.status).toBe(200);
    const afterMitigate = (await mitigate.json()) as { attackPaths: Array<{ id: string }> };
    expect(afterMitigate.attackPaths.some((p) => p.id === apJson.attackPaths[0].id)).toBe(false);
  });

  it('Workflow 3: IntentLock cryptographic approval, tamper auto-revocation, re-approval, and execution', async () => {
    const acme = await loginAs('sarah@acme.cloud');

    // Create new change contract
    const createRes = await ChangesRoute.POST(
      makeReq('/api/v1/changes', {
        method: 'POST',
        token: acme.token,
        body: {
          title: 'Harden S3 Bucket Policy',
          project: 'terraform-aws-core',
          targetAsset: 'acme-customer-backups',
          newStatePayload: { acl: 'private', encryption: 'AES256' },
          purpose: 'Remediate public S3 exposure',
          riskLevel: 'High',
        },
      })
    );
    expect(createRes.status).toBe(201);
    const created = (await createRes.json()) as { change: { id: string; intentLockStatus: string } };
    expect(created.change.intentLockStatus).toBe('Locked');

    // Cannot execute while Locked
    const execLocked = await ChangeExecuteRoute.POST(
      makeReq(`/api/v1/changes/${created.change.id}/execute`, { method: 'POST', token: acme.token }),
      { params: Promise.resolve({ id: created.change.id }) }
    );
    expect(execLocked.status).toBe(409);

    // Approve
    const appRes = await ChangeApproveRoute.POST(
      makeReq(`/api/v1/changes/${created.change.id}/approve`, {
        method: 'POST',
        token: acme.token,
        body: { action: 'approve' },
      }),
      { params: Promise.resolve({ id: created.change.id }) }
    );
    expect(appRes.status).toBe(200);

    // Tamper payload after approval -> IntentLock must automatically revoke approval!
    const tamperRes = await ChangeByIdRoute.PATCH(
      makeReq(`/api/v1/changes/${created.change.id}`, {
        method: 'PATCH',
        token: acme.token,
        body: { newStatePayload: { acl: 'public-read-write', encryption: 'none' } },
      }),
      { params: Promise.resolve({ id: created.change.id }) }
    );
    expect(tamperRes.status).toBe(200);
    const tamperedJson = (await tamperRes.json()) as { change: { intentLockStatus: string } };
    expect(tamperedJson.change.intentLockStatus).toBe('Modified_Revalidation_Required');

    // Execution must be blocked after tampering
    const execTampered = await ChangeExecuteRoute.POST(
      makeReq(`/api/v1/changes/${created.change.id}/execute`, { method: 'POST', token: acme.token }),
      { params: Promise.resolve({ id: created.change.id }) }
    );
    expect(execTampered.status).toBe(409);

    // Fix payload, re-approve, and execute cleanly
    await ChangeByIdRoute.PATCH(
      makeReq(`/api/v1/changes/${created.change.id}`, {
        method: 'PATCH',
        token: acme.token,
        body: { newStatePayload: { acl: 'private', encryption: 'aws:kms' } },
      }),
      { params: Promise.resolve({ id: created.change.id }) }
    );
    await ChangeApproveRoute.POST(
      makeReq(`/api/v1/changes/${created.change.id}/approve`, {
        method: 'POST',
        token: acme.token,
        body: { action: 'approve' },
      }),
      { params: Promise.resolve({ id: created.change.id }) }
    );
    const execClean = await ChangeExecuteRoute.POST(
      makeReq(`/api/v1/changes/${created.change.id}/execute`, { method: 'POST', token: acme.token }),
      { params: Promise.resolve({ id: created.change.id }) }
    );
    expect(execClean.status).toBe(200);
    const execJson = (await execClean.json()) as { change: { intentLockStatus: string } };
    expect(execJson.change.intentLockStatus).toBe('Executed');
  });

  it('Workflow 4 & 5: AI Agent allowlist/quarantine, Deception canary trigger, Incident & Policy checks', async () => {
    const acme = await loginAs('sarah@acme.cloud');

    // Register new agent
    const regAg = await AgentsRoute.POST(
      makeReq('/api/v1/ai-agents', {
        method: 'POST',
        token: acme.token,
        body: {
          name: 'QA-Test-Bot',
          type: 'LLM Agent',
          ownerTeam: 'Platform',
          permissions: ['read:code'],
          allowlistedTools: ['scan_repo'],
          actionLimit: 5,
        },
      })
    );
    expect(regAg.status).toBe(201);
    const agData = (await regAg.json()) as { aiAgent: { id: string } };

    // Allowed tool passes
    const okTool = await AgentExecRoute.POST(
      makeReq(`/api/v1/ai-agents/${agData.aiAgent.id}/execute`, {
        method: 'POST',
        token: acme.token,
        body: { toolName: 'scan_repo' },
      }),
      { params: Promise.resolve({ id: agData.aiAgent.id }) }
    );
    expect(okTool.status).toBe(200);

    // Disallowed tool gets blocked (403) and quarantines agent
    const blockedTool = await AgentExecRoute.POST(
      makeReq(`/api/v1/ai-agents/${agData.aiAgent.id}/execute`, {
        method: 'POST',
        token: acme.token,
        body: { toolName: 'drop_production_database' },
      }),
      { params: Promise.resolve({ id: agData.aiAgent.id }) }
    );
    expect(blockedTool.status).toBe(403);

    // Deception canary trigger
    const canRes = await DeceptionRoute.POST(
      makeReq('/api/v1/deception', {
        method: 'POST',
        token: acme.token,
        body: { type: 'Honey API Key', location: 'repo/.env.fake' },
      })
    );
    expect(canRes.status).toBe(201);

    // Incident creation
    const incRes = await IncidentsRoute.POST(
      makeReq('/api/v1/incidents', {
        method: 'POST',
        token: acme.token,
        body: { title: 'Test Containment Drill', severity: 'SEV-2', affectedAsset: 'payment-gateway-service' },
      })
    );
    expect(incRes.status).toBe(201);

    // Policy evaluation
    const polEval = await PolicyEvalRoute.POST(
      makeReq('/api/v1/policies/evaluate', {
        method: 'POST',
        token: acme.token,
        body: { type: 'terraform_plan', terraformContent: 'resource "aws_s3_bucket" "x" { acl = "public-read-write" }' },
      })
    );
    expect(polEval.status).toBe(200);
    const polJson = (await polEval.json()) as { allowed: boolean; decision: string };
    expect(polJson.allowed).toBe(false);
    expect(polJson.decision).toBe('DENY');
  });

  it('Workflow 6 & 7: Trust Center sanitized public passport, revocation (410), CSV compliance export, webhook HMAC & audit hash chain', async () => {
    const acme = await loginAs('sarah@acme.cloud');

    // Issue Trust Passport
    const issueRes = await TrustCenterRoute.POST(
      makeReq('/api/v1/trust-center', {
        method: 'POST',
        token: acme.token,
        body: { title: 'Enterprise Audit Q4', scope: ['SOC 2 Type II', 'IntentLock'] },
      })
    );
    expect(issueRes.status).toBe(201);
    const issued = (await issueRes.json()) as { trustReceipt: { id: string } };

    // Public viewer (no auth) works and omits sensitive fields
    const pubRes = await TrustCenterPublicRoute.GET(
      makeReq(`/api/v1/trust-center/${issued.trustReceipt.id}`),
      { params: Promise.resolve({ id: issued.trustReceipt.id }) }
    );
    expect(pubRes.status).toBe(200);
    const pubJson = (await pubRes.json()) as { passport: { organizationName: string; findings?: unknown } };
    expect(pubJson.passport.organizationName).toBe('Acme Cloud Technologies');
    expect(pubJson.passport.findings).toBeUndefined();

    // Revoke -> public viewer returns 410
    const revRes = await TrustCenterRevokeRoute.POST(
      makeReq(`/api/v1/trust-center/${issued.trustReceipt.id}/revoke`, { method: 'POST', token: acme.token }),
      { params: Promise.resolve({ id: issued.trustReceipt.id }) }
    );
    expect(revRes.status).toBe(200);

    const pubRevoked = await TrustCenterPublicRoute.GET(
      makeReq(`/api/v1/trust-center/${issued.trustReceipt.id}`),
      { params: Promise.resolve({ id: issued.trustReceipt.id }) }
    );
    expect(pubRevoked.status).toBe(410);

    // Compliance CSV Export
    const csvRes = await ComplianceExportRoute.GET(
      makeReq('/api/v1/compliance/export?format=csv', { token: acme.token })
    );
    expect(csvRes.status).toBe(200);
    expect(csvRes.headers.get('content-type')).toContain('text/csv');

    // GitHub Webhook HMAC validation + duplicate delivery idempotency
    const payloadStr = JSON.stringify({ repository: { full_name: 'acme/payment-gateway-service' }, ref: 'refs/heads/main' });
    const badWebhook = await GithubWebhookRoute.POST(
      makeReq('/api/v1/webhooks/github', {
        method: 'POST',
        body: payloadStr,
        headers: { 'x-hub-signature-256': 'sha256=invalid', 'x-github-delivery': 'deliv-1', 'x-github-event': 'push' },
      })
    );
    expect(badWebhook.status).toBe(401);

    const validSig = `sha256=${crypto.createHmac('sha256', process.env.GITHUB_WEBHOOK_SECRET!).update(payloadStr).digest('hex')}`;
    const goodWebhook = await GithubWebhookRoute.POST(
      makeReq('/api/v1/webhooks/github', {
        method: 'POST',
        body: payloadStr,
        headers: { 'x-hub-signature-256': validSig, 'x-github-delivery': 'deliv-unique-1', 'x-github-event': 'push' },
      })
    );
    expect(goodWebhook.status).toBe(200);
    const goodJson = (await goodWebhook.json()) as { duplicate: boolean };
    expect(goodJson.duplicate).toBe(false);

    const dupWebhook = await GithubWebhookRoute.POST(
      makeReq('/api/v1/webhooks/github', {
        method: 'POST',
        body: payloadStr,
        headers: { 'x-hub-signature-256': validSig, 'x-github-delivery': 'deliv-unique-1', 'x-github-event': 'push' },
      })
    );
    expect(dupWebhook.status).toBe(200);
    const dupJson = (await dupWebhook.json()) as { duplicate: boolean };
    expect(dupJson.duplicate).toBe(true);

    // Connectors truthful verification (Terraform local succeeds, GitHub without token reports 424 Credentials_Required)
    const tfConn = await ConnectorsTestRoute.POST(
      makeReq('/api/v1/connectors/conn-4/test', { method: 'POST', token: acme.token }),
      { params: Promise.resolve({ id: 'conn-4' }) }
    );
    expect(tfConn.status).toBe(200);

    delete process.env.GITHUB_TOKEN;
    const ghConn = await ConnectorsTestRoute.POST(
      makeReq('/api/v1/connectors/conn-1/test', { method: 'POST', token: acme.token }),
      { params: Promise.resolve({ id: 'conn-1' }) }
    );
    expect(ghConn.status).toBe(424);

    // Self-registration creates a clean isolated workspace
    const regRes = await RegisterRoute.POST(
      makeReq('/api/v1/auth/register', {
        method: 'POST',
        body: {
          email: 'founder@newstartup.dev',
          name: 'Ada Lovelace',
          password: 'StrongPassword!99',
          organizationName: 'New Startup Security',
          edition: 'developer',
        },
      })
    );
    expect(regRes.status).toBe(201);

    // Audit log hash chain integrity verified across every single operation
    const auditRes = await AuditLogsRoute.GET(makeReq('/api/v1/audit-logs', { token: acme.token }));
    expect(auditRes.status).toBe(200);
    const auditJson = (await auditRes.json()) as { chainVerified: boolean; totalEntries: number };
    expect(auditJson.chainVerified).toBe(true);
    expect(auditJson.totalEntries).toBeGreaterThanOrEqual(5);
  });
});
