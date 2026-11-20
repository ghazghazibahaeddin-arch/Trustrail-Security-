import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { closeDbForTests, getDb } from '@/lib/db';
import { decryptSecretPayload, isEncryptedEnvelope } from '@/lib/security/vault';

import * as LoginRoute from '@/app/api/v1/auth/login/route';
import * as ConnectorsRoute from '@/app/api/v1/connectors/route';
import * as ConnectorConfigureRoute from '@/app/api/v1/connectors/[id]/configure/route';
import * as RotateSecretsRoute from '@/app/api/v1/connectors/rotate-secrets/route';
import * as ProjectsRoute from '@/app/api/v1/projects/route';
import * as ScansRoute from '@/app/api/v1/scans/route';
import * as SbomRoute from '@/app/api/v1/projects/[id]/sbom/route';
import * as FindingsRoute from '@/app/api/v1/findings/route';
import * as RemediationRoute from '@/app/api/v1/remediation/route';
import * as RecoveryBackupsRoute from '@/app/api/v1/recovery/backups/route';
import * as JobsRoute from '@/app/api/v1/jobs/route';
import * as CloudResourcesRoute from '@/app/api/v1/cloud/resources/route';
import * as SystemMetricsRoute from '@/app/api/v1/system/metrics/route';

let tempDbPath = '';
let tempBackupDir = '';

function makeReq(url: string, opts: { method?: string; token?: string; body?: unknown } = {}) {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'x-forwarded-for': '203.0.113.77',
  };
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  return new NextRequest(`http://127.0.0.1:3000${url}`, {
    method: opts.method || 'GET',
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
}

beforeAll(() => {
  closeDbForTests();
  tempDbPath = path.join(os.tmpdir(), `trustrail-vault-int-${crypto.randomUUID()}.db`);
  tempBackupDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustrail-backup-test-'));
  process.env.TRUSTRAIL_DB_PATH = tempDbPath;
  process.env.TRUSTRAIL_BACKUP_DIR = tempBackupDir;
  getDb();
});

afterAll(() => {
  closeDbForTests();
  delete process.env.TRUSTRAIL_DB_PATH;
  delete process.env.TRUSTRAIL_BACKUP_DIR;
  delete process.env.TRUSTRAIL_VAULT_KEY_VERSION;
  for (const suffix of ['', '-wal', '-shm']) {
    if (fs.existsSync(`${tempDbPath}${suffix}`)) {
      fs.rmSync(`${tempDbPath}${suffix}`, { force: true });
    }
  }
  if (tempBackupDir && fs.existsSync(tempBackupDir)) {
    fs.rmSync(tempBackupDir, { recursive: true, force: true });
  }
});

describe('Connector Secret Vaulting, Polyglot Scanners, SBOM/SLSA, Gated Remediation, Recovery, Jobs & CSPM', () => {
  it('vaults connector credentials with AES-256-GCM (zero plaintext in SQLite) and rotates vault key versions', async () => {
    const loginRes = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email: 'sarah@acme.cloud', password: 'Trustrail!2026' },
      })
    );
    expect(loginRes.status).toBe(200);
    const { token, user } = (await loginRes.json()) as {
      token: string;
      user: { orgId: string };
    };

    const connRes = await ConnectorsRoute.GET(makeReq('/api/v1/connectors', { token }));
    const connJson = (await connRes.json()) as {
      connectors: Array<{ id: string; providerKey: string }>;
    };
    const awsConn = connJson.connectors.find((c) => c.providerKey === 'aws');
    expect(awsConn).toBeTruthy();

    const secretAccessKey = 'SecretAwsKeyNeverPlaintext2026!';
    const configRes = await ConnectorConfigureRoute.POST(
      makeReq(`/api/v1/connectors/${awsConn!.id}/configure`, {
        method: 'POST',
        token,
        body: {
          awsAccessKeyId: 'AKIAVAULTTEST1234567',
          awsSecretAccessKey: secretAccessKey,
          awsRoleArn: 'arn:aws:iam::123456789012:role/TrustrailAuditor',
          awsRegion: 'us-east-1',
          verifyNow: false,
        },
      }),
      { params: Promise.resolve({ id: awsConn!.id }) }
    );
    expect(configRes.status).toBe(200);
    const configJson = (await configRes.json()) as {
      config: { encrypted: boolean; configured: boolean; awsAccessKeyIdHint?: string };
    };
    expect(configJson.config.encrypted).toBe(true);
    expect(configJson.config.configured).toBe(true);
    expect(configJson.config.awsAccessKeyIdHint).toContain('****');
    expect(JSON.stringify(configJson.config)).not.toContain(secretAccessKey);

    // Inspect raw SQLite row directly to guarantee ZERO plaintext secret storage
    const db = getDb();
    const rawRow = db
      .prepare('SELECT config_json FROM connectors WHERE id = ? AND org_id = ?')
      .get(awsConn!.id, user.orgId) as { config_json: string };

    expect(isEncryptedEnvelope(rawRow.config_json)).toBe(true);
    expect(rawRow.config_json).not.toContain('AKIAVAULTTEST1234567');
    expect(rawRow.config_json).not.toContain(secretAccessKey);

    // Rotate vault secrets to v2
    process.env.TRUSTRAIL_VAULT_KEY_VERSION = '2';
    const rotRes = await RotateSecretsRoute.POST(
      makeReq('/api/v1/connectors/rotate-secrets', { method: 'POST', token })
    );
    expect(rotRes.status).toBe(200);
    const rotJson = (await rotRes.json()) as { rotatedCount: number; activeKeyVersion: number };
    expect(rotJson.rotatedCount).toBeGreaterThanOrEqual(1);
    expect(rotJson.activeKeyVersion).toBe(2);

    const rotatedRow = db
      .prepare('SELECT config_json FROM connectors WHERE id = ? AND org_id = ?')
      .get(awsConn!.id, user.orgId) as { config_json: string };
    const decrypted = decryptSecretPayload<{ awsSecretAccessKey: string }>(rotatedRow.config_json, {
      aad: `${user.orgId}:${awsConn!.id}`,
    });
    expect(decrypted.keyVersion).toBe(2);
    expect(decrypted.data?.awsSecretAccessKey).toBe(secretAccessKey);
  });

  it('executes polyglot manifest/workflow scans, exports & validates SPDX 2.3 SBOM, and verifies SLSA 3 attestation', async () => {
    const loginRes = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email: 'sarah@acme.cloud', password: 'Trustrail!2026' },
      })
    );
    const { token } = (await loginRes.json()) as { token: string };

    const projRes = await ProjectsRoute.GET(makeReq('/api/v1/projects', { token }));
    const projJson = (await projRes.json()) as { projects: Array<{ id: string; name: string }> };
    const project = projJson.projects[0];
    expect(project).toBeTruthy();

    const scanRes = await ScansRoute.POST(
      makeReq('/api/v1/scans', {
        method: 'POST',
        token,
        body: {
          projectId: project.id,
          requirementsTxtContent: 'PyYAML==5.3.1\n',
          goModContent: 'module github.com/acme/svc\nrequire golang.org/x/net v0.12.0\n',
          pomXmlContent: `<dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies>`,
          githubWorkflowContent: 'on:\n  pull_request_target:\npermissions: write-all\nsteps:\n  - uses: actions/checkout@main\n  - run: echo "${{ github.event.pull_request.title }}"',
        },
      })
    );
    expect(scanRes.status).toBe(201);
    const scanJson = (await scanRes.json()) as {
      scan: { scannersRun: string[]; filesScanned: number; findingsDetected: number; sbomGenerated: boolean };
    };
    expect(scanJson.scan.scannersRun).toContain('trustrail-multi-ecosystem-sca');
    expect(scanJson.scan.scannersRun).toContain('trustrail-cicd-workflow-scanner');
    expect(scanJson.scan.findingsDetected).toBeGreaterThanOrEqual(5);
    expect(scanJson.scan.sbomGenerated).toBe(true);

    // Export SPDX 2.3 with validation
    const sbomRes = await SbomRoute.GET(
      makeReq(`/api/v1/projects/${project.id}/sbom?format=spdx&validate=true`, { token }),
      { params: Promise.resolve({ id: project.id }) }
    );
    expect(sbomRes.status).toBe(200);
    const sbomJson = (await sbomRes.json()) as {
      format: string;
      sbom: { spdxVersion: string };
      validation: { valid: boolean; format: string };
    };
    expect(sbomJson.format).toBe('spdx');
    expect(sbomJson.sbom.spdxVersion).toBe('SPDX-2.3');
    expect(sbomJson.validation.valid).toBe(true);

    // Cryptographic SLSA 3 Attestation verification
    const artifactContent = 'build-bundle-acme-payment-gateway';
    const digest = crypto.createHash('sha256').update(artifactContent, 'utf8').digest('hex');
    const signingSecret = 'acme-cosign-kms-hmac-secret';
    const hmacSignature = crypto.createHmac('sha256', signingSecret).update(digest, 'utf8').digest('hex');

    const attestRes = await SbomRoute.POST(
      makeReq(`/api/v1/projects/${project.id}/sbom`, {
        method: 'POST',
        token,
        body: {
          expectedDigestSha256: digest,
          artifactContent,
          hmacSignature,
          signingSecret,
        },
      }),
      { params: Promise.resolve({ id: project.id }) }
    );
    expect(attestRes.status).toBe(200);
    const attestJson = (await attestRes.json()) as { slsaLevel: string };
    expect(attestJson.slsaLevel).toBe('SLSA 3');
  });

  it('enforces gated remediation (blocks premature closure 409), checksummed recovery restore checks, background job DLQ/retry, CSPM, and audit chain integrity', async () => {
    const loginRes = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email: 'sarah@acme.cloud', password: 'Trustrail!2026' },
      })
    );
    const { token } = (await loginRes.json()) as { token: string };

    // 1. Gated Remediation Workflow
    const findingsRes = await FindingsRoute.GET(makeReq('/api/v1/findings', { token }));
    const findingsJson = (await findingsRes.json()) as {
      findings: Array<{ id: string; status: string }>;
    };
    const targetFinding = findingsJson.findings.find((f) => f.status === 'Open');
    expect(targetFinding).toBeTruthy();

    const startRemRes = await RemediationRoute.POST(
      makeReq('/api/v1/remediation', {
        method: 'POST',
        token,
        body: { findingId: targetFinding!.id },
      })
    );
    expect(startRemRes.status).toBe(201);
    const startRemJson = (await startRemRes.json()) as { run: { id: string; status: string } };
    expect(startRemJson.run.status).toBe('Patch_Generated');

    // Premature closure must be blocked (409 VERIFICATION_GATE_BLOCKED)
    const blockedClosure = await RemediationRoute.PATCH(
      makeReq('/api/v1/remediation', {
        method: 'PATCH',
        token,
        body: { runId: startRemJson.run.id, action: 'rescan_and_resolve' },
      })
    );
    expect(blockedClosure.status).toBe(409);
    expect(((await blockedClosure.json()) as { code: string }).code).toBe('VERIFICATION_GATE_BLOCKED');

    // Verification with insecure sample fails cleanly (422)
    const badPatch = await RemediationRoute.PATCH(
      makeReq('/api/v1/remediation', {
        method: 'PATCH',
        token,
        body: {
          runId: startRemJson.run.id,
          action: 'run_verification',
          patchedCodeSample: 'const key = "AKIAIOSFODNN7EXAMPLE";',
        },
      })
    );
    expect(badPatch.status).toBe(422);

    // Clean verification passes, then final rescan closes finding
    const cleanPatch = await RemediationRoute.PATCH(
      makeReq('/api/v1/remediation', {
        method: 'PATCH',
        token,
        body: {
          runId: startRemJson.run.id,
          action: 'run_verification',
          patchedCodeSample: 'export const key = process.env.AWS_SECRET_KEY;',
        },
      })
    );
    expect(cleanPatch.status).toBe(200);

    const resolvedRes = await RemediationRoute.PATCH(
      makeReq('/api/v1/remediation', {
        method: 'PATCH',
        token,
        body: {
          runId: startRemJson.run.id,
          action: 'rescan_and_resolve',
          patchedCodeSample: 'export const key = process.env.AWS_SECRET_KEY;',
        },
      })
    );
    expect(resolvedRes.status).toBe(200);
    expect(((await resolvedRes.json()) as { resolved: boolean }).resolved).toBe(true);

    // 2. Recovery Snapshot + Restore Integrity Verification
    const snapRes = await RecoveryBackupsRoute.POST(
      makeReq('/api/v1/recovery/backups', {
        method: 'POST',
        token,
        body: { action: 'create_snapshot', targetName: 'acme-prod-db', backupType: 'Full Snapshot' },
      })
    );
    expect(snapRes.status).toBe(201);
    const snapJson = (await snapRes.json()) as { backupId: string; checksum: string };
    expect(snapJson.checksum.startsWith('sha256:')).toBe(true);

    const restoreRes = await RecoveryBackupsRoute.POST(
      makeReq('/api/v1/recovery/backups', {
        method: 'POST',
        token,
        body: { action: 'verify_restore', backupId: snapJson.backupId },
      })
    );
    expect(restoreRes.status).toBe(200);
    expect(((await restoreRes.json()) as { restoreStatus: string }).restoreStatus).toBe('Verified');

    // 3. Background Job Queue DLQ & Retry
    const enqRes = await JobsRoute.POST(
      makeReq('/api/v1/jobs', {
        method: 'POST',
        token,
        body: { action: 'enqueue', jobType: 'cloud_inventory_sync', simulateFailure: true },
      })
    );
    expect(enqRes.status).toBe(201);
    const { jobId } = (await enqRes.json()) as { jobId: string };

    await JobsRoute.POST(
      makeReq('/api/v1/jobs', { method: 'POST', token, body: { action: 'retry', jobId, simulateFailure: true } })
    );
    const dlqRes = await JobsRoute.POST(
      makeReq('/api/v1/jobs', { method: 'POST', token, body: { action: 'retry', jobId, simulateFailure: true } })
    );
    const dlqJson = (await dlqRes.json()) as { result: { status: string; attempts: number } };
    expect(dlqJson.result.status).toBe('Dead_Letter');
    expect(dlqJson.result.attempts).toBe(3);

    const recoverJob = await JobsRoute.POST(
      makeReq('/api/v1/jobs', { method: 'POST', token, body: { action: 'retry', jobId, simulateFailure: false } })
    );
    expect(((await recoverJob.json()) as { result: { status: string } }).result.status).toBe('Completed');

    // 4. CSPM Resource Evaluation + System Metrics + Tamper-Evident Audit Chain
    const cspmRes = await CloudResourcesRoute.POST(
      makeReq('/api/v1/cloud/resources', {
        method: 'POST',
        token,
        body: {
          provider: 'aws',
          accountId: '123456789012',
          region: 'us-east-1',
          resources: [
            {
              resourceType: 'aws_s3_bucket',
              resourceArn: 'arn:aws:s3:::acme-unencrypted-public-dump',
              exposure: 'Public',
              publicAccessBlock: false,
              encryptionEnabled: false,
            },
          ],
        },
      })
    );
    expect(cspmRes.status).toBe(201);
    const cspmJson = (await cspmRes.json()) as { nonCompliantCount: number; newFindingsCount: number };
    expect(cspmJson.nonCompliantCount).toBe(1);
    expect(cspmJson.newFindingsCount).toBe(1);

    const metricsRes = await SystemMetricsRoute.GET(makeReq('/api/v1/system/metrics', { token }));
    expect(metricsRes.status).toBe(200);
    const metricsJson = (await metricsRes.json()) as {
      auditChain: { valid: boolean; totalEntries: number };
      vaultKeyVersion: number;
    };
    expect(metricsJson.auditChain.valid).toBe(true);
    expect(metricsJson.auditChain.totalEntries).toBeGreaterThan(0);
    expect(metricsJson.vaultKeyVersion).toBe(2);
  });
});
