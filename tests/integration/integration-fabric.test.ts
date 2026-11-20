import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { closeDbForTests, getDb } from '@/lib/db';
import { calculateRiskPriority } from '@/lib/engines/risk-engine';
import { createGithubAppJwt } from '@/lib/integrations/github-app';

import * as LoginRoute from '@/app/api/v1/auth/login/route';
import * as ConnectorsRoute from '@/app/api/v1/connectors/route';
import * as ConnectorConfigureRoute from '@/app/api/v1/connectors/[id]/configure/route';
import * as ConnectorTestRoute from '@/app/api/v1/connectors/[id]/test/route';
import * as ConnectorSyncRoute from '@/app/api/v1/connectors/[id]/sync/route';
import * as ConnectorDeleteRoute from '@/app/api/v1/connectors/[id]/route';
import * as FabricEventsRoute from '@/app/api/v1/fabric/events/route';
import * as K8sAnalyzeRoute from '@/app/api/v1/integrations/kubernetes/analyze/route';
import * as RunnerRoute from '@/app/api/v1/runner/route';
import * as RunnerEnrollRoute from '@/app/api/v1/runner/enroll/route';
import * as RunnerHeartbeatRoute from '@/app/api/v1/runner/heartbeat/route';
import * as RunnerJobsRoute from '@/app/api/v1/runner/jobs/route';
import * as RunnerDeleteRoute from '@/app/api/v1/runner/[id]/route';
import * as EventsIngestRoute from '@/app/api/v1/events/ingest/route';
import * as SiemExportRoute from '@/app/api/v1/siem/export/route';
import * as SsoRoute from '@/app/api/v1/sso/route';
import * as ScimUsersRoute from '@/app/api/v1/scim/v2/Users/route';
import * as ScansRoute from '@/app/api/v1/scans/route';

let tempDbPath = '';
let adminToken = '';

function makeReq(url: string, opts: { method?: string; token?: string; body?: unknown } = {}) {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  return new NextRequest(`http://127.0.0.1:3000${url}`, {
    method: opts.method || 'GET',
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
}

beforeAll(async () => {
  closeDbForTests();
  tempDbPath = path.join(os.tmpdir(), `trustrail-fabric-${crypto.randomUUID()}.db`);
  process.env.TRUSTRAIL_DB_PATH = tempDbPath;
  getDb();

  const loginRes = await LoginRoute.POST(
    makeReq('/api/v1/auth/login', {
      method: 'POST',
      body: { email: 'sarah@acme.cloud', password: 'Trustrail!2026' },
    })
  );
  const json = (await loginRes.json()) as { token: string };
  adminToken = json.token;
});

afterAll(() => {
  closeDbForTests();
  delete process.env.TRUSTRAIL_DB_PATH;
  for (const suffix of ['', '-wal', '-shm']) {
    if (fs.existsSync(`${tempDbPath}${suffix}`)) {
      fs.rmSync(`${tempDbPath}${suffix}`, { force: true });
    }
  }
});

describe('TRUSTRAIL Master Integration Fabric', () => {
  it('verifies transactional outbox idempotency, failure -> Dead_Letter -> replay recovery, and scan event emission', async () => {
    const idemp = `idem-${crypto.randomUUID()}`;
    const first = await FabricEventsRoute.POST(
      makeReq('/api/v1/fabric/events', {
        method: 'POST',
        token: adminToken,
        body: {
          action: 'publish',
          eventType: 'scan.completed',
          sourceConnector: 'github',
          sourceResourceId: 'acme/core-api',
          idempotencyKey: idemp,
          simulateFailure: true,
          payload: { findingsCount: 2 },
        },
      })
    );
    expect(first.status).toBe(201);
    const firstJson = (await first.json()) as { event: { eventId: string; processingStatus: string }; deduplicated: boolean };
    expect(firstJson.deduplicated).toBe(false);
    expect(firstJson.event.processingStatus).toBe('Failed');

    // Duplicate idempotencyKey must deduplicate cleanly
    const dup = await FabricEventsRoute.POST(
      makeReq('/api/v1/fabric/events', {
        method: 'POST',
        token: adminToken,
        body: {
          action: 'publish',
          eventType: 'scan.completed',
          sourceConnector: 'github',
          sourceResourceId: 'acme/core-api',
          idempotencyKey: idemp,
          payload: { findingsCount: 2 },
        },
      })
    );
    const dupJson = (await dup.json()) as { deduplicated: boolean; event: { eventId: string } };
    expect(dupJson.deduplicated).toBe(true);
    expect(dupJson.event.eventId).toBe(firstJson.event.eventId);

    // Replay with failure twice -> transitions Failed -> Dead_Letter at attempt 3
    await FabricEventsRoute.POST(
      makeReq('/api/v1/fabric/events', {
        method: 'POST',
        token: adminToken,
        body: { action: 'replay', eventId: firstJson.event.eventId, simulateFailure: true },
      })
    );
    const dlqRes = await FabricEventsRoute.POST(
      makeReq('/api/v1/fabric/events', {
        method: 'POST',
        token: adminToken,
        body: { action: 'replay', eventId: firstJson.event.eventId, simulateFailure: true },
      })
    );
    const dlqJson = (await dlqRes.json()) as { event: { processingStatus: string; attempts: number } };
    expect(dlqJson.event.processingStatus).toBe('Dead_Letter');
    expect(dlqJson.event.attempts).toBe(3);

    // Replay cleanly -> Processed
    const recoveredRes = await FabricEventsRoute.POST(
      makeReq('/api/v1/fabric/events', {
        method: 'POST',
        token: adminToken,
        body: { action: 'replay', eventId: firstJson.event.eventId, simulateFailure: false },
      })
    );
    const recoveredJson = (await recoveredRes.json()) as { event: { processingStatus: string } };
    expect(recoveredJson.event.processingStatus).toBe('Processed');

    // Executing a scan emits events into the outbox
    const scanRes = await ScansRoute.POST(
      makeReq('/api/v1/scans', {
        method: 'POST',
        token: adminToken,
        body: {
          projectName: 'fabric-scan-target',
          codeContent: `const key = "ghp_1234567890abcdef1234567890abcdef1234";`,
        },
      })
    );
    expect(scanRes.status).toBe(201);
    const listEventsRes = await FabricEventsRoute.GET(makeReq('/api/v1/fabric/events?limit=50', { token: adminToken }));
    const listEventsJson = (await listEventsRes.json()) as { events: Array<{ eventType: string }> };
    expect(listEventsJson.events.some((e) => e.eventType === 'secret.detected')).toBe(true);
  });

  it('verifies 19-connector lifecycle, fail-closed 424 on missing creds, encrypted config, sync history, and purge', async () => {
    const connListRes = await ConnectorsRoute.GET(makeReq('/api/v1/connectors', { token: adminToken }));
    expect(connListRes.status).toBe(200);
    const connList = (await connListRes.json()) as {
      connectors: Array<{ id: string; providerKey: string; lifecycleState: string }>;
      dependencyMap: unknown[];
    };
    expect(connList.connectors.length).toBeGreaterThanOrEqual(19);
    expect(connList.dependencyMap.length).toBeGreaterThanOrEqual(19);

    const gitlabConn = connList.connectors.find((c) => c.providerKey === 'gitlab')!;
    expect(gitlabConn).toBeDefined();

    // Fail-closed HTTP 424 when testing unconfigured credentialed connector
    const unconfTest = await ConnectorTestRoute.POST(
      makeReq(`/api/v1/connectors/${gitlabConn.id}/test`, { method: 'POST', token: adminToken }),
      { params: Promise.resolve({ id: gitlabConn.id }) }
    );
    expect(unconfTest.status).toBe(424);

    // Save encrypted GitLab credentials (without verifyNow so no outbound network dependency)
    const cfgRes = await ConnectorConfigureRoute.POST(
      makeReq(`/api/v1/connectors/${gitlabConn.id}/configure`, {
        method: 'POST',
        token: adminToken,
        body: {
          gitlabUrl: 'https://gitlab.com',
          gitlabToken: 'glpat-supersecret-token-12345',
          verifyNow: false,
        },
      }),
      { params: Promise.resolve({ id: gitlabConn.id }) }
    );
    expect(cfgRes.status).toBe(200);
    const cfgJson = (await cfgRes.json()) as {
      lifecycleState: string;
      config: { encrypted: boolean; gitlabTokenHint: string };
    };
    expect(cfgJson.lifecycleState).toBe('CONFIGURING');
    expect(cfgJson.config.encrypted).toBe(true);
    expect(cfgJson.config.gitlabTokenHint).not.toContain('supersecret');

    // Sync local Terraform connector and verify sync run persistence
    const tfConn = connList.connectors.find((c) => c.providerKey === 'terraform')!;
    const syncRes = await ConnectorSyncRoute.POST(
      makeReq(`/api/v1/connectors/${tfConn.id}/sync`, {
        method: 'POST',
        token: adminToken,
        body: { mode: 'incremental' },
      }),
      { params: Promise.resolve({ id: tfConn.id }) }
    );
    expect(syncRes.status).toBe(200);
    const runsRes = await ConnectorSyncRoute.GET(
      makeReq(`/api/v1/connectors/${tfConn.id}/sync`, { token: adminToken }),
      { params: Promise.resolve({ id: tfConn.id }) }
    );
    const runsJson = (await runsRes.json()) as { syncRuns: Array<{ mode: string; status: string }> };
    expect(runsJson.syncRuns.length).toBeGreaterThanOrEqual(1);
    expect(runsJson.syncRuns[0].status).toBe('Completed');

    // Delete/purge GitLab connector configuration
    const delRes = await ConnectorDeleteRoute.DELETE(
      makeReq(`/api/v1/connectors/${gitlabConn.id}`, { method: 'DELETE', token: adminToken }),
      { params: Promise.resolve({ id: gitlabConn.id }) }
    );
    expect(delRes.status).toBe(200);
    const delJson = (await delRes.json()) as { deleted: boolean; clearedCredentials: boolean };
    expect(delJson.deleted).toBe(true);
    expect(delJson.clearedCredentials).toBe(true);

    const afterDelRes = await ConnectorsRoute.GET(makeReq('/api/v1/connectors', { token: adminToken }));
    const afterDelList = (await afterDelRes.json()) as {
      connectors: Array<{ id: string; availabilityState: string; lifecycleState: string }>;
    };
    const purgedGitlab = afterDelList.connectors.find((c) => c.id === gitlabConn.id)!;
    expect(purgedGitlab.availabilityState).toBe('NOT_CONFIGURED');
    expect(purgedGitlab.lifecycleState).toBe('DISCONNECTED');
  });

  it('signs GitHub App RS256 JWTs, analyzes Kubernetes manifests into graph & findings, and uplifts KEV/EPSS risk', async () => {
    const { privateKey } = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });
    const jwt = createGithubAppJwt('12345', privateKey);
    expect(jwt.split('.')).toHaveLength(3);

    const k8sRes = await K8sAnalyzeRoute.POST(
      makeReq('/api/v1/integrations/kubernetes/analyze', {
        method: 'POST',
        token: adminToken,
        body: {
          clusterName: 'prod-k8s-eu-west',
          manifestYaml: `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-worker
spec:
  template:
    spec:
      hostNetwork: true
      containers:
      - name: worker
        securityContext:
          privileged: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: overly-broad-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
`,
        },
      })
    );
    expect(k8sRes.status).toBe(201);
    const k8sJson = (await k8sRes.json()) as { findingsCount: number; newFindingsInserted: number };
    expect(k8sJson.findingsCount).toBeGreaterThanOrEqual(2);

    const baseRisk = calculateRiskPriority({
      cvss: 7.5,
      exploitability: 'Medium',
      internetExposed: false,
      assetCriticality: 'HIGH',
      inActiveAttackPath: false,
      fixAvailable: true,
    });
    const kevRisk = calculateRiskPriority({
      cvss: 7.5,
      exploitability: 'Medium',
      internetExposed: false,
      assetCriticality: 'HIGH',
      inActiveAttackPath: false,
      fixAvailable: true,
      kevListed: true,
      epssScore: 0.96,
    });
    expect(kevRisk.score).toBeGreaterThan(baseRisk.score);
    expect(kevRisk.reasons.some((r) => r.includes('CISA KEV'))).toBe(true);
    expect(kevRisk.reasons.some((r) => r.includes('EPSS'))).toBe(true);
  });

  it('runs complete TRUSTRAIL Runner lifecycle, Runtime Telemetry auto-incident correlation, SIEM export & SCIM 2.0 provisioning', async () => {
    // 1. Issue Runner token
    const createRunnerRes = await RunnerRoute.POST(
      makeReq('/api/v1/runner', {
        method: 'POST',
        token: adminToken,
        body: { action: 'create_runner', name: 'ci-agent-1', mode: 'cicd', environment: 'staging' },
      })
    );
    expect(createRunnerRes.status).toBe(201);
    const { runner, enrollmentToken } = (await createRunnerRes.json()) as {
      runner: { id: string };
      enrollmentToken: string;
    };
    expect(enrollmentToken.startsWith('tr_run_')).toBe(true);

    // 2. Enroll + Heartbeat using runner token
    const enrollRes = await RunnerEnrollRoute.POST(
      makeReq('/api/v1/runner/enroll', {
        method: 'POST',
        token: enrollmentToken,
        body: { deviceFingerprint: 'ubuntu-24.04-x86_64-runner01', version: '1.2.0' },
      })
    );
    expect(enrollRes.status).toBe(200);

    const hbRes = await RunnerHeartbeatRoute.POST(
      makeReq('/api/v1/runner/heartbeat', {
        method: 'POST',
        token: enrollmentToken,
        body: { status: 'Online', stats: { cpuPct: 14 } },
      })
    );
    expect(hbRes.status).toBe(200);

    // 3. Queue a job as Admin, claim it as Runner, and submit signed results
    const queueRes = await RunnerRoute.POST(
      makeReq('/api/v1/runner', {
        method: 'POST',
        token: adminToken,
        body: {
          action: 'queue_job',
          runnerId: runner.id,
          jobType: 'repo_scan',
          target: { repo: 'acme/private-billing' },
        },
      })
    );
    const { job } = (await queueRes.json()) as { job: { id: string } };

    const pollRes = await RunnerJobsRoute.GET(
      makeReq('/api/v1/runner/jobs', { token: enrollmentToken })
    );
    const pollJson = (await pollRes.json()) as { job: { id: string; status: string } };
    expect(pollJson.job.id).toBe(job.id);
    expect(pollJson.job.status).toBe('Dispatched');

    const submitRes = await RunnerJobsRoute.POST(
      makeReq('/api/v1/runner/jobs', {
        method: 'POST',
        token: enrollmentToken,
        body: {
          jobId: job.id,
          status: 'Completed',
          findings: [
            {
              title: 'Runner Detected Hardcoded JWT Secret',
              severity: 'CRITICAL',
              category: 'SECRET',
              filePath: 'src/auth.ts',
              line: 18,
              cvss: 9.1,
              evidence: 'Redacted JWT signing key in runner scan.',
              suggestedFix: 'Move JWT signing key to KMS/Vault.',
            },
          ],
        },
      })
    );
    expect(submitRes.status).toBe(200);
    const submitJson = (await submitRes.json()) as { newFindingsInserted: number; signature: string };
    expect(submitJson.newFindingsInserted).toBe(1);
    expect(submitJson.signature).toContain('sha256:');

    // 4. Runtime telemetry ingested via Runner token triggers auto-incident on CRITICAL anomaly
    const rtRes = await EventsIngestRoute.POST(
      makeReq('/api/v1/events/ingest', {
        method: 'POST',
        token: enrollmentToken,
        body: {
          source: 'falco',
          severity: 'CRITICAL',
          eventType: 'container_escape_attempt',
          actor: 'pod/billing-worker',
          resource: 'prod-k8s/billing',
          summary: 'Unexpected privileged namespace mount detected.',
        },
      })
    );
    expect(rtRes.status).toBe(201);
    const rtJson = (await rtRes.json()) as { correlatedIncidentId: string | null };
    expect(rtJson.correlatedIncidentId).toBeTruthy();

    // 5. Revoke runner -> subsequent runner heartbeat must return 401
    const revokeRes = await RunnerDeleteRoute.DELETE(
      makeReq(`/api/v1/runner/${runner.id}`, { method: 'DELETE', token: adminToken }),
      { params: Promise.resolve({ id: runner.id }) }
    );
    expect(revokeRes.status).toBe(200);

    const postRevokeHb = await RunnerHeartbeatRoute.POST(
      makeReq('/api/v1/runner/heartbeat', {
        method: 'POST',
        token: enrollmentToken,
        body: { status: 'Online' },
      })
    );
    expect(postRevokeHb.status).toBe(401);

    // 6. SSO + SCIM 2.0 User Provisioning & SIEM export tracking
    const ssoSave = await SsoRoute.POST(
      makeReq('/api/v1/sso', {
        method: 'POST',
        token: adminToken,
        body: {
          action: 'configure_sso',
          provider: 'okta',
          issuerUrl: 'https://acme.okta.com/oauth2/default',
          clientId: 'trustrail-sso-client',
          roleMapping: { security_admins: 'Admin' },
          enabled: true,
        },
      })
    );
    expect(ssoSave.status).toBe(200);

    const scimTokRes = await SsoRoute.POST(
      makeReq('/api/v1/sso', {
        method: 'POST',
        token: adminToken,
        body: { action: 'issue_scim_token', name: 'Okta SCIM' },
      })
    );
    const { secret: scimSecret } = (await scimTokRes.json()) as { secret: string };
    expect(scimSecret.startsWith('tr_scim_')).toBe(true);

    const scimCreateUser = await ScimUsersRoute.POST(
      makeReq('/api/v1/scim/v2/Users', {
        method: 'POST',
        token: scimSecret,
        body: {
          userName: 'scim.engineer@acme.cloud',
          displayName: 'SCIM Engineer',
          active: true,
          groups: ['security_admins'],
        },
      })
    );
    expect(scimCreateUser.status).toBe(201);
    const scimUserJson = (await scimCreateUser.json()) as { roles: Array<{ value: string }> };
    expect(scimUserJson.roles[0].value).toBe('Admin');

    const siemRes = await SiemExportRoute.POST(
      makeReq('/api/v1/siem/export', {
        method: 'POST',
        token: adminToken,
        body: {
          destination: 'splunk',
          resourceType: 'SecurityIncident',
          resourceId: rtJson.correlatedIncidentId!,
          eventData: { severity: 'CRITICAL' },
        },
      })
    );
    expect(siemRes.status).toBe(202);
    const siemJson = (await siemRes.json()) as { exportId: string; status: string };
    expect(siemJson.exportId).toBeTruthy();
    expect(siemJson.status).toBe('Queued');
  });
});
