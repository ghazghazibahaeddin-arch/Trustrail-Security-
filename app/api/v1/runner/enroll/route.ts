import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk } from '@/lib/api-response';
import { authenticateRunnerRequest } from '@/lib/runner/runner-auth';
import { publishEvent } from '@/lib/fabric/event-bus';

const EnrollSchema = z.object({
  deviceFingerprint: z.string().min(4).max(180),
  environment: z.string().min(2).max(60).optional(),
  version: z.string().min(1).max(32).default('1.2.0'),
  capabilities: z.array(z.string().min(1).max(60)).optional(),
});

export async function POST(req: NextRequest) {
  const runner = authenticateRunnerRequest(req);
  if (!runner) {
    return jsonError('Valid runner enrollment token (Bearer tr_run_...) required.', 401, 'RUNNER_UNAUTHORIZED');
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = EnrollSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid runner enrollment payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const now = new Date().toISOString();

  db.prepare(
    `UPDATE runners
     SET device_fingerprint = ?,
         environment = COALESCE(?, environment),
         version = ?,
         capabilities_json = COALESCE(?, capabilities_json),
         status = 'Online',
         last_heartbeat_at = ?
     WHERE id = ? AND org_id = ?`
  ).run(
    parsed.data.deviceFingerprint.trim(),
    parsed.data.environment?.trim() || null,
    parsed.data.version.trim(),
    parsed.data.capabilities ? JSON.stringify(parsed.data.capabilities) : null,
    now,
    runner.id,
    runner.orgId
  );

  const evt = publishEvent(db, {
    orgId: runner.orgId,
    eventType: 'runner.enrolled',
    actorId: `runner:${runner.id}`,
    sourceConnector: 'trustrail_runner',
    sourceResourceId: runner.id,
    payload: {
      runnerName: runner.name,
      mode: runner.mode,
      deviceFingerprint: parsed.data.deviceFingerprint,
      version: parsed.data.version,
    },
  });

  appendAuditLog(db, {
    orgId: runner.orgId,
    actorEmail: `runner:${runner.id}`,
    action: 'RUNNER_ENROLLED',
    resourceType: 'Runner',
    resourceId: runner.id,
    details: `Runner "${runner.name}" enrolled (${parsed.data.deviceFingerprint}, v${parsed.data.version}).`,
  });

  return jsonOk({
    enrolled: true,
    runnerId: runner.id,
    orgId: runner.orgId,
    status: 'Online',
    heartbeatAt: now,
    eventId: evt.event.eventId,
  });
}
