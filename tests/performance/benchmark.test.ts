import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { closeDbForTests, getDb } from '@/lib/db';
import { executeUnifiedScan } from '@/lib/engines/scanner-engine';
import { synthesizeAttackPaths } from '@/lib/engines/attack-path-engine';
import * as LoginRoute from '@/app/api/v1/auth/login/route';
import * as FindingsRoute from '@/app/api/v1/findings/route';
import * as GraphRoute from '@/app/api/v1/graph/route';

let tempDbPath = '';

function percentile(sorted: number[], p: number): number {
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

beforeAll(() => {
  closeDbForTests();
  tempDbPath = path.join(os.tmpdir(), `trustrail-perf-${crypto.randomUUID()}.db`);
  process.env.TRUSTRAIL_DB_PATH = tempDbPath;
  getDb();
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

describe('Performance & Latency Benchmarks', () => {
  it('measures unified scanner, graph attack-path solver, and API handler p95 latency', async () => {
    const scanTimes: number[] = [];
    for (let i = 0; i < 50; i++) {
      const t0 = performance.now();
      executeUnifiedScan({
        projectName: `perf-${i}`,
        codeContent: `const k="AKIA1234567890ABCDEF"; db.query(\`SELECT * FROM t WHERE id=\${x}\`);`,
        packageJsonContent: JSON.stringify({ dependencies: { minimist: '1.2.5', lodash: '4.17.19' } }),
        terraformContent: 'resource "aws_s3_bucket" "b" { acl = "public-read" }',
      });
      scanTimes.push(performance.now() - t0);
    }
    scanTimes.sort((a, b) => a - b);
    const scanP95 = percentile(scanTimes, 95);
    expect(scanP95).toBeLessThan(50);

    // Large synthetic graph (100 nodes, 150 edges)
    const nodes = Array.from({ length: 100 }, (_, i) => ({
      id: `n-${i}`,
      orgId: 'org-perf',
      name: `asset-${i}`,
      assetType: i === 0 ? 'API Endpoint' : i === 99 ? 'Database' : 'Microservice',
      owner: 'team',
      internetExposed: i < 5,
      criticality: (i === 99 ? 'CRITICAL' : 'HIGH') as 'CRITICAL' | 'HIGH',
    }));
    const edges = Array.from({ length: 99 }, (_, i) => ({
      id: `e-${i}`,
      orgId: 'org-perf',
      sourceAssetId: `n-${i}`,
      targetAssetId: `n-${i + 1}`,
      relation: 'CALLS',
      evidence: 'mesh',
    }));
    const graphFindings = [
      { id: 'gf-1', title: 'RCE', severity: 'CRITICAL' as const, category: 'API', assetId: 'n-0', assetName: 'asset-0', status: 'Open', cvss: 9.8 },
    ];

    const graphTimes: number[] = [];
    for (let i = 0; i < 50; i++) {
      const t0 = performance.now();
      synthesizeAttackPaths(nodes, edges, graphFindings);
      graphTimes.push(performance.now() - t0);
    }
    graphTimes.sort((a, b) => a - b);
    const graphP95 = percentile(graphTimes, 95);
    expect(graphP95).toBeLessThan(50);

    // API latency
    const loginRes = await LoginRoute.POST(
      new NextRequest('http://127.0.0.1:3000/api/v1/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'sarah@acme.cloud', password: 'Trustrail!2026' }),
      })
    );
    const { token } = (await loginRes.json()) as { token: string };

    const apiTimes: number[] = [];
    for (let i = 0; i < 30; i++) {
      const t0 = performance.now();
      await FindingsRoute.GET(
        new NextRequest('http://127.0.0.1:3000/api/v1/findings', {
          headers: { authorization: `Bearer ${token}` },
        })
      );
      await GraphRoute.GET(
        new NextRequest('http://127.0.0.1:3000/api/v1/graph', {
          headers: { authorization: `Bearer ${token}` },
        })
      );
      apiTimes.push(performance.now() - t0);
    }
    apiTimes.sort((a, b) => a - b);
    const apiP95 = percentile(apiTimes, 95);
    expect(apiP95).toBeLessThan(150);

    console.info(
      `[BENCHMARK] scan_p95=${scanP95.toFixed(2)}ms graph_100nodes_p95=${graphP95.toFixed(2)}ms api_findings_graph_p95=${apiP95.toFixed(2)}ms`
    );
  });
});
