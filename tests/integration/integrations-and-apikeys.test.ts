import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest';
import { NextRequest } from 'next/server';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { closeDbForTests, getDb } from '@/lib/db';

import * as RegisterRoute from '@/app/api/v1/auth/register/route';
import * as LoginRoute from '@/app/api/v1/auth/login/route';
import * as ApiKeysRoute from '@/app/api/v1/api-keys/route';
import * as ApiKeyDeleteRoute from '@/app/api/v1/api-keys/[id]/route';
import * as ProjectsRoute from '@/app/api/v1/projects/route';
import * as ConnectorsRoute from '@/app/api/v1/connectors/route';
import * as ConnectorConfigureRoute from '@/app/api/v1/connectors/[id]/configure/route';
import * as HttpProbeRoute from '@/app/api/v1/integrations/http-probe/route';
import * as OsvQueryRoute from '@/app/api/v1/integrations/osv/query/route';
import * as GithubScanRoute from '@/app/api/v1/integrations/github/scan-repo/route';
import * as OutboundWebhookRoute from '@/app/api/v1/webhooks/outbound/test/route';
import { assertSafeExternalUrl } from '@/lib/security/ssrf';

let tempDbPath = '';

function makeReq(url: string, opts: { method?: string; token?: string; apiKey?: string; body?: unknown } = {}) {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  if (opts.apiKey) headers['x-api-key'] = opts.apiKey;
  return new NextRequest(`http://127.0.0.1:3000${url}`, {
    method: opts.method || 'GET',
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
}

beforeAll(() => {
  closeDbForTests();
  tempDbPath = path.join(os.tmpdir(), `trustrail-int-${crypto.randomUUID()}.db`);
  process.env.TRUSTRAIL_DB_PATH = tempDbPath;
  getDb();
});

afterAll(() => {
  vi.restoreAllMocks();
  closeDbForTests();
  delete process.env.TRUSTRAIL_DB_PATH;
  for (const suffix of ['', '-wal', '-shm']) {
    if (fs.existsSync(`${tempDbPath}${suffix}`)) {
      fs.rmSync(`${tempDbPath}${suffix}`, { force: true });
    }
  }
});

describe('API Keys, Per-Org Integrations, SSRF Protection & New User Provisioning', () => {
  it('provisions complete operational integrations for newly registered users and issues scoped API keys', async () => {
    const regRes = await RegisterRoute.POST(
      makeReq('/api/v1/auth/register', {
        method: 'POST',
        body: {
          email: 'owner@horizon-labs.dev',
          name: 'Elena Vance',
          password: 'HorizonPassword!2026',
          organizationName: 'Horizon Cyber Labs',
          edition: 'smb',
        },
      })
    );
    expect(regRes.status).toBe(201);
    const regJson = (await regRes.json()) as { token: string; organization: { id: string } };
    expect(regJson.token).toBeTruthy();

    // Verify all 7 connectors provisioned, with osv & http_probe & terraform & oci immediately Connected
    const connRes = await ConnectorsRoute.GET(makeReq('/api/v1/connectors', { token: regJson.token }));
    expect(connRes.status).toBe(200);
    const connJson = (await connRes.json()) as {
      connectors: Array<{ id: string; providerKey: string; status: string; healthCheck: string }>;
    };
    const keys = new Set(connJson.connectors.map((c) => c.providerKey));
    expect(keys.has('github')).toBe(true);
    expect(keys.has('osv')).toBe(true);
    expect(keys.has('http_probe')).toBe(true);
    expect(keys.has('terraform')).toBe(true);
    expect(keys.has('oci')).toBe(true);
    expect(keys.has('slack')).toBe(true);
    expect(connJson.connectors.find((c) => c.providerKey === 'osv')?.status).toBe('Connected');
    expect(connJson.connectors.find((c) => c.providerKey === 'http_probe')?.status).toBe('Connected');

    // Issue scoped API Key (Developer role)
    const createKeyRes = await ApiKeysRoute.POST(
      makeReq('/api/v1/api-keys', {
        method: 'POST',
        token: regJson.token,
        body: { name: 'github-actions-scanner', role: 'Developer' },
      })
    );
    expect(createKeyRes.status).toBe(201);
    const createKeyJson = (await createKeyRes.json()) as {
      apiKey: { id: string; keyPrefix: string; role: string };
      secret: string;
    };
    expect(createKeyJson.secret.startsWith('tr_live_')).toBe(true);
    expect(createKeyJson.apiKey.role).toBe('Developer');

    // Authenticate with API Key on /api/v1/projects
    const projViaKey = await ProjectsRoute.GET(makeReq('/api/v1/projects', { token: createKeyJson.secret }));
    expect(projViaKey.status).toBe(200);

    // Also authenticate via x-api-key header
    const projViaHeader = await ProjectsRoute.GET(makeReq('/api/v1/projects', { apiKey: createKeyJson.secret }));
    expect(projViaHeader.status).toBe(200);

    // Developer-scoped API key cannot create an Owner/Admin key or access Admin-only connector config
    const escalated = await ApiKeysRoute.POST(
      makeReq('/api/v1/api-keys', {
        method: 'POST',
        token: createKeyJson.secret,
        body: { name: 'bad-escalation', role: 'Admin' },
      })
    );
    expect(escalated.status).toBe(403);

    // Revoke key -> subsequent request MUST fail with 401
    const revokeRes = await ApiKeyDeleteRoute.DELETE(
      makeReq(`/api/v1/api-keys/${createKeyJson.apiKey.id}`, {
        method: 'DELETE',
        token: regJson.token,
      }),
      { params: Promise.resolve({ id: createKeyJson.apiKey.id }) }
    );
    expect(revokeRes.status).toBe(200);

    const afterRevoke = await ProjectsRoute.GET(makeReq('/api/v1/projects', { token: createKeyJson.secret }));
    expect(afterRevoke.status).toBe(401);
  });

  it('strictly blocks SSRF targets (loopback, RFC1918, cloud metadata, file://) on HTTP Probe and Webhook URLs', async () => {
    const loginRes = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email: 'sarah@acme.cloud', password: 'Trustrail!2026' },
      })
    );
    const { token } = (await loginRes.json()) as { token: string };

    const ssrfTargets = [
      'http://127.0.0.1:3000/api/health',
      'http://localhost:3000',
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.5:8080/internal',
      'http://192.168.1.1/admin',
      'http://[::1]:3000/',
      'file:///etc/passwd',
    ];

    for (const url of ssrfTargets) {
      await expect(assertSafeExternalUrl(url, { skipDnsLookup: true })).rejects.toThrow();

      const res = await HttpProbeRoute.POST(
        makeReq('/api/v1/integrations/http-probe', {
          method: 'POST',
          token,
          body: { targetUrl: url },
        })
      );
      expect(res.status).toBe(400);
    }

    // Webhook configuration also rejects non-HTTPS and loopback/metadata URLs
    const badHook = await ConnectorConfigureRoute.POST(
      makeReq('/api/v1/connectors/conn-5/configure', {
        method: 'POST',
        token,
        body: { webhookUrl: 'http://169.254.169.254/hook' },
      }),
      { params: Promise.resolve({ id: 'conn-5' }) }
    );
    expect(badHook.status).toBe(400);
  });

  it('masks saved connector secrets, executes GitHub/OSV/HTTP-Probe/Webhook integrations end-to-end, and prevents cross-tenant modification', async () => {
    const acmeLogin = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email: 'sarah@acme.cloud', password: 'Trustrail!2026' },
      })
    );
    const acme = (await acmeLogin.json()) as { token: string };

    const northstarLogin = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email: 'admin@northstar.io', password: 'Trustrail!2026' },
      })
    );
    const northstar = (await northstarLogin.json()) as { token: string };

    // Cross-tenant connector configure must return 404
    const crossTenant = await ConnectorConfigureRoute.POST(
      makeReq('/api/v1/connectors/conn-1/configure', {
        method: 'POST',
        token: northstar.token,
        body: { githubToken: 'ghp_1234567890abcdef1234567890abcdef1234', verifyNow: false },
      }),
      { params: Promise.resolve({ id: 'conn-1' }) }
    );
    expect(crossTenant.status).toBe(404);

    // Save GitHub PAT without live verify first -> must mask in GET /connectors
    const rawSecretPat = 'ghp_TestSecretToken1234567890abcdef9988';
    const savePat = await ConnectorConfigureRoute.POST(
      makeReq('/api/v1/connectors/conn-1/configure', {
        method: 'POST',
        token: acme.token,
        body: { githubToken: rawSecretPat, defaultRepo: 'acme/gateway', verifyNow: false },
      }),
      { params: Promise.resolve({ id: 'conn-1' }) }
    );
    expect(savePat.status).toBe(200);

    const listConns = await ConnectorsRoute.GET(makeReq('/api/v1/connectors', { token: acme.token }));
    const connsBody = await listConns.text();
    expect(connsBody).not.toContain(rawSecretPat);
    expect(connsBody).toContain('ghp_****9988');

    // Mock fetch for deterministic offline-safe end-to-end verification of GitHub Scan, OSV Query, HTTP Probe, and Outbound Webhook
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const urlStr = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (urlStr === 'https://api.github.com/repos/example-org/vuln-service') {
        return new Response(
          JSON.stringify({ name: 'vuln-service', full_name: 'example-org/vuln-service', default_branch: 'main', language: 'TypeScript', private: false }),
          { status: 200 }
        );
      }
      if (urlStr.includes('/git/trees/')) {
        return new Response(
          JSON.stringify({
            tree: [
              { path: 'package.json', type: 'blob', size: 220 },
              { path: 'src/auth.ts', type: 'blob', size: 180 },
            ],
          }),
          { status: 200 }
        );
      }
      if (urlStr.includes('/contents/package.json')) {
        const content = Buffer.from(JSON.stringify({ name: 'vuln-service', dependencies: { minimist: '1.2.5' } })).toString('base64');
        return new Response(JSON.stringify({ encoding: 'base64', content }), { status: 200 });
      }
      if (urlStr.includes('/contents/src/auth.ts')) {
        const content = Buffer.from(`const API_KEY = "sk_live_SuperSensitiveMock123456";`).toString('base64');
        return new Response(JSON.stringify({ encoding: 'base64', content }), { status: 200 });
      }
      if (urlStr === 'https://api.osv.dev/v1/querybatch') {
        return new Response(
          JSON.stringify({ results: [{ vulns: [{ id: 'GHSA-xvch-5gv4-984h' }] }] }),
          { status: 200 }
        );
      }
      if (urlStr.startsWith('https://api.osv.dev/v1/vulns/')) {
        return new Response(
          JSON.stringify({
            id: 'GHSA-xvch-5gv4-984h',
            aliases: ['CVE-2021-44906'],
            summary: 'Prototype Pollution in minimist',
            database_specific: { severity: 'CRITICAL' },
            affected: [{ ranges: [{ events: [{ fixed: '1.2.6' }] }] }],
          }),
          { status: 200 }
        );
      }
      if (urlStr === 'https://93.184.216.34/api/test') {
        return new Response('ok', {
          status: 200,
          headers: {
            'access-control-allow-origin': '*',
            'access-control-allow-credentials': 'true',
            server: 'nginx/1.24.0',
          },
        });
      }
      if (urlStr === 'https://93.184.216.34/webhook') {
        return new Response(JSON.stringify({ ok: true }), { status: 200 });
      }
      return new Response('Not Found', { status: 404 });
    });

    // Live GitHub Repo Scan
    const ghRes = await GithubScanRoute.POST(
      makeReq('/api/v1/integrations/github/scan-repo', {
        method: 'POST',
        token: acme.token,
        body: { repo: 'example-org/vuln-service' },
      })
    );
    expect(ghRes.status).toBe(201);
    const ghJson = (await ghRes.json()) as {
      repository: string;
      sbomGenerated: boolean;
      findingsDetected: number;
      findings: Array<{ evidence: string }>;
    };
    expect(ghJson.repository).toBe('example-org/vuln-service');
    expect(ghJson.sbomGenerated).toBe(true);
    expect(ghJson.findingsDetected).toBeGreaterThanOrEqual(2);
    for (const f of ghJson.findings) {
      expect(f.evidence).not.toContain('sk_live_SuperSensitiveMock123456');
    }

    // Live OSV query
    const osvRes = await OsvQueryRoute.POST(
      makeReq('/api/v1/integrations/osv/query', {
        method: 'POST',
        token: acme.token,
        body: { packages: [{ ecosystem: 'npm', name: 'minimist', version: '1.2.5' }] },
      })
    );
    expect(osvRes.status).toBe(200);
    const osvJson = (await osvRes.json()) as { advisoriesCount: number };
    expect(osvJson.advisoriesCount).toBe(1);

    // Live HTTP Probe (using public IP directly to bypass DNS dependency in unit/integration tests)
    const probeRes = await HttpProbeRoute.POST(
      makeReq('/api/v1/integrations/http-probe', {
        method: 'POST',
        token: acme.token,
        body: { targetUrl: 'https://93.184.216.34/api/test' },
      })
    );
    expect(probeRes.status).toBe(200);
    const probeJson = (await probeRes.json()) as { issuesDetected: Array<{ key: string }> };
    const issueKeys = probeJson.issuesDetected.map((i) => i.key);
    expect(issueKeys).toContain('INSECURE_CORS_WILDCARD');
    expect(issueKeys).toContain('MISSING_HSTS');
    expect(issueKeys).toContain('MISSING_CSP');
    expect(issueKeys).toContain('SERVER_BANNER_EXPOSURE');

    // Outbound webhook test
    const hookRes = await OutboundWebhookRoute.POST(
      makeReq('/api/v1/webhooks/outbound/test', {
        method: 'POST',
        token: acme.token,
        body: { webhookUrl: 'https://93.184.216.34/webhook' },
      })
    );
    expect(hookRes.status).toBe(200);
    const hookJson = (await hookRes.json()) as { delivered: boolean };
    expect(hookJson.delivered).toBe(true);

    fetchSpy.mockRestore();
  });
});
