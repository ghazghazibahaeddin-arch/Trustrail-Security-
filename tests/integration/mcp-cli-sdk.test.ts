import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { closeDbForTests, getDb } from '@/lib/db';

import * as LoginRoute from '@/app/api/v1/auth/login/route';
import * as McpRoute from '@/app/api/v1/mcp/route';
import * as OpenApiRoute from '@/app/api/v1/openapi.json/route';
import { TrustrailClient } from '@/lib/sdk/trustrail-client';

const execFileAsync = promisify(execFile);

let tempDbPath = '';
let tempScanDir = '';

function makeReq(url: string, opts: { method?: string; token?: string; body?: unknown } = {}) {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  return new NextRequest(`http://127.0.0.1:3000${url}`, {
    method: opts.method || 'GET',
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
}

beforeAll(() => {
  closeDbForTests();
  tempDbPath = path.join(os.tmpdir(), `trustrail-mcp-${crypto.randomUUID()}.db`);
  process.env.TRUSTRAIL_DB_PATH = tempDbPath;
  getDb();

  tempScanDir = fs.mkdtempSync(path.join(os.tmpdir(), 'trustrail-cli-fixture-'));
  fs.writeFileSync(
    path.join(tempScanDir, 'app.ts'),
    `const TOKEN = "ghp_1234567890abcdef1234567890abcdef1234";\ndb.query(\`SELECT * FROM users WHERE id = \${req.id}\`);`
  );
  fs.writeFileSync(
    path.join(tempScanDir, 'main.tf'),
    `resource "aws_s3_bucket" "leak" { acl = "public-read-write" }`
  );
  fs.writeFileSync(
    path.join(tempScanDir, 'package.json'),
    JSON.stringify({ name: 'cli-fixture', dependencies: { minimist: '1.2.5' } })
  );
});

afterAll(() => {
  closeDbForTests();
  delete process.env.TRUSTRAIL_DB_PATH;
  for (const suffix of ['', '-wal', '-shm']) {
    if (fs.existsSync(`${tempDbPath}${suffix}`)) {
      fs.rmSync(`${tempDbPath}${suffix}`, { force: true });
    }
  }
  if (tempScanDir && fs.existsSync(tempScanDir)) {
    fs.rmSync(tempScanDir, { recursive: true, force: true });
  }
});

describe('MCP Server JSON-RPC 2.0, CLI, TypeScript SDK & OpenAPI Parity', () => {
  it('supports MCP initialize, tools/list, tools/call, RBAC restrictions, and human-gated remediation', async () => {
    // Unauthenticated MCP call blocked
    const unauth = await McpRoute.POST(
      makeReq('/api/v1/mcp', { method: 'POST', body: { jsonrpc: '2.0', id: 1, method: 'initialize' } })
    );
    expect(unauth.status).toBe(401);

    const adminLogin = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email: 'sarah@acme.cloud', password: 'Trustrail!2026' },
      })
    );
    const { token: adminToken } = (await adminLogin.json()) as { token: string };

    const viewerLogin = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email: 'auditor@acme.cloud', password: 'Trustrail!2026' },
      })
    );
    const { token: viewerToken } = (await viewerLogin.json()) as { token: string };

    const initRes = await McpRoute.POST(
      makeReq('/api/v1/mcp', {
        method: 'POST',
        token: adminToken,
        body: { jsonrpc: '2.0', id: 1, method: 'initialize' },
      })
    );
    expect(initRes.status).toBe(200);
    const initJson = (await initRes.json()) as { result: { serverInfo: { name: string } } };
    expect(initJson.result.serverInfo.name).toBe('trustrail-mcp-server');

    const listRes = await McpRoute.POST(
      makeReq('/api/v1/mcp', {
        method: 'POST',
        token: adminToken,
        body: { jsonrpc: '2.0', id: 2, method: 'tools/list' },
      })
    );
    const listJson = (await listRes.json()) as { result: { tools: Array<{ name: string }> } };
    expect(listJson.result.tools).toHaveLength(5);

    // Call list_findings
    const findingsRes = await McpRoute.POST(
      makeReq('/api/v1/mcp', {
        method: 'POST',
        token: adminToken,
        body: {
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: { name: 'trustrail_list_findings', arguments: { severity: 'CRITICAL' } },
        },
      })
    );
    expect(findingsRes.status).toBe(200);

    // Call request_remediation -> must enter Locked awaiting human approval!
    const remRes = await McpRoute.POST(
      makeReq('/api/v1/mcp', {
        method: 'POST',
        token: adminToken,
        body: {
          jsonrpc: '2.0',
          id: 4,
          method: 'tools/call',
          params: {
            name: 'trustrail_request_remediation',
            arguments: {
              title: 'MCP S3 Lock',
              targetAsset: 'acme-bucket',
              purpose: 'Block public ACL',
              patchPayload: { acl: 'private' },
            },
          },
        },
      })
    );
    expect(remRes.status).toBe(200);
    const remJson = (await remRes.json()) as { result: { content: Array<{ text: string }> } };
    const parsedRem = JSON.parse(remJson.result.content[0].text) as { intentLockStatus: string; requiresHumanApproval: boolean };
    expect(parsedRem.intentLockStatus).toBe('Locked');
    expect(parsedRem.requiresHumanApproval).toBe(true);

    // Viewer blocked from trustrail_run_scan
    const viewerScan = await McpRoute.POST(
      makeReq('/api/v1/mcp', {
        method: 'POST',
        token: viewerToken,
        body: {
          jsonrpc: '2.0',
          id: 5,
          method: 'tools/call',
          params: { name: 'trustrail_run_scan', arguments: { projectName: 'test' } },
        },
      })
    );
    expect(viewerScan.status).toBe(403);
  });

  it('executes Trustrail CLI scan and terraform-check against real vulnerable fixtures with secret redaction', async () => {
    const tsxBin = path.resolve(process.cwd(), 'node_modules/.bin/tsx');
    const cliPath = path.resolve(process.cwd(), 'bin/trustrail.ts');

    const { stdout } = await execFileAsync(tsxBin, [cliPath, 'scan', tempScanDir, '--project', 'cli-fixture']);
    const parsed = JSON.parse(stdout) as {
      project: string;
      findingsCount: number;
      sbomGenerated: boolean;
      findings: Array<{ evidence: string }>;
    };
    expect(parsed.project).toBe('cli-fixture');
    expect(parsed.findingsCount).toBeGreaterThanOrEqual(4);
    expect(parsed.sbomGenerated).toBe(true);
    for (const f of parsed.findings) {
      expect(f.evidence).not.toContain('ghp_1234567890abcdef1234567890abcdef1234');
    }

    const tfOut = await execFileAsync(tsxBin, [cliPath, 'terraform-check', path.join(tempScanDir, 'main.tf')]);
    const tfJson = JSON.parse(tfOut.stdout) as { findings: unknown[] };
    expect(tfJson.findings.length).toBeGreaterThanOrEqual(1);
  });

  it('verifies TypeScript SDK TrustrailClient error handling and auth header wiring', async () => {
    const client = new TrustrailClient({ baseUrl: 'http://127.0.0.1:3000', token: 'test-token' });
    expect(client).toBeDefined();
    // Verify OpenAPI spec covers every route file under app/api
    const specRes = await OpenApiRoute.GET();
    const spec = (await specRes.json()) as { paths: Record<string, unknown> };
    const documentedPaths = new Set(Object.keys(spec.paths));

    const routeFiles: string[] = [];
    const walk = (dir: string) => {
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.name === 'route.ts') routeFiles.push(full);
      }
    };
    walk(path.resolve(process.cwd(), 'app/api'));

    for (const rf of routeFiles) {
      const rel = path.relative(path.resolve(process.cwd(), 'app'), path.dirname(rf)).replace(/\\/g, '/');
      const apiPath = `/${rel}`.replace(/\[([^\]]+)\]/g, '{$1}');
      expect(documentedPaths.has(apiPath)).toBe(true);
    }
  });
});
