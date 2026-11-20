import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb } from '@/lib/db';
import { jsonError, jsonOk } from '@/lib/api-response';
import { authenticateRunnerRequest } from '@/lib/runner/runner-auth';

const HeartbeatSchema = z.object({
  status: z.enum(['Online', 'Degraded']).default('Online'),
  stats: z.record(z.string(), z.unknown()).optional(),
});

export async function POST(req: NextRequest) {
  const runner = authenticateRunnerRequest(req);
  if (!runner) {
    return jsonError('Valid runner token (Bearer tr_run_...) required.', 401, 'RUNNER_UNAUTHORIZED');
  }

  let body: unknown = {};
  try {
    const txt = await req.text();
    if (txt.trim()) body = JSON.parse(txt);
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = HeartbeatSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid heartbeat payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const now = new Date().toISOString();

  db.prepare(
    `UPDATE runners
     SET status = ?,
         last_heartbeat_at = ?,
         stats_json = COALESCE(?, stats_json)
     WHERE id = ? AND org_id = ?`
  ).run(
    parsed.data.status,
    now,
    parsed.data.stats ? JSON.stringify(parsed.data.stats) : null,
    runner.id,
    runner.orgId
  );

  return jsonOk({
    runnerId: runner.id,
    status: parsed.data.status,
    heartbeatAt: now,
  });
}
