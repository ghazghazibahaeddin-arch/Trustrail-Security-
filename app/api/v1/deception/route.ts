import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';

const CreateCanarySchema = z.object({
  type: z.enum(['Canary Token URL', 'Honey API Key', 'Decoy Database User', 'Honeypot Endpoint']),
  location: z.string().min(3).max(200),
});

const TriggerCanarySchema = z.object({
  canaryId: z.string().min(1),
  sourceIp: z.string().max(64).default('198.51.100.42'),
});

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const canaries = db
    .prepare(
      `SELECT id, type, location, token_hint as tokenHint, status, alerts_count as alertsCount, last_triggered_at as lastTriggeredAt
       FROM canaries WHERE org_id = ?`
    )
    .all(authResult.auth.orgId);

  return jsonOk({ canaries });
}

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  // Either trigger a canary simulation test or deploy a new decoy canary
  if (typeof body === 'object' && body !== null && 'canaryId' in body) {
    const parsed = TriggerCanarySchema.safeParse(body);
    if (!parsed.success) return jsonError('Invalid canary trigger payload.', 400, 'VALIDATION_ERROR');

    const db = getDb();
    const existing = db
      .prepare('SELECT id, type, location, alerts_count FROM canaries WHERE id = ? AND org_id = ?')
      .get(parsed.data.canaryId, authResult.auth.orgId) as
      | { id: string; type: string; location: string; alerts_count: number }
      | undefined;

    if (!existing) return jsonError('Canary not found.', 404, 'NOT_FOUND');

    const now = new Date().toISOString();
    db.prepare(
      `UPDATE canaries SET status = 'Triggered', alerts_count = alerts_count + 1, last_triggered_at = ? WHERE id = ? AND org_id = ?`
    ).run(now, existing.id, authResult.auth.orgId);

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'CANARY_TRIPWIRE_TRIGGERED',
      resourceType: 'Canary',
      resourceId: existing.id,
      details: `Canary "${existing.type}" at ${existing.location} tripped from ${parsed.data.sourceIp}.`,
    });

    const canaries = db
      .prepare(
        `SELECT id, type, location, token_hint as tokenHint, status, alerts_count as alertsCount, last_triggered_at as lastTriggeredAt
         FROM canaries WHERE org_id = ?`
      )
      .all(authResult.auth.orgId);

    return jsonOk({ triggered: true, canaries });
  }

  const parsed = CreateCanarySchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid canary deployment payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const id = `can-${crypto.randomUUID().slice(0, 8)}`;
  const hint =
    parsed.data.type === 'Honey API Key'
      ? `tr_decoy_****${crypto.randomBytes(2).toString('hex')}`
      : parsed.data.type === 'Canary Token URL'
      ? `https://canary.trustrail.internal/t/${crypto.randomBytes(4).toString('hex')}`
      : `decoy_${crypto.randomBytes(3).toString('hex')}`;

  db.prepare(
    `INSERT INTO canaries (id, org_id, type, location, token_hint, status, alerts_count)
     VALUES (?, ?, ?, ?, ?, 'Armed', 0)`
  ).run(id, authResult.auth.orgId, parsed.data.type, parsed.data.location.trim(), hint);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'CANARY_DEPLOYED',
    resourceType: 'Canary',
    resourceId: id,
    details: `Deployed ${parsed.data.type} at ${parsed.data.location}.`,
  });

  const canaries = db
    .prepare(
      `SELECT id, type, location, token_hint as tokenHint, status, alerts_count as alertsCount, last_triggered_at as lastTriggeredAt
       FROM canaries WHERE org_id = ?`
    )
    .all(authResult.auth.orgId);

  return jsonOk({ canaries }, 201);
}
