import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { authenticateRunnerRequest } from '@/lib/runner/runner-auth';
import { publishEvent } from '@/lib/fabric/event-bus';

const IngestRuntimeEventSchema = z.object({
  source: z.enum(['otel', 'kubernetes_audit', 'falco', 'cloudtrail', 'custom']),
  severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).default('MEDIUM'),
  eventType: z.string().min(2).max(100),
  actor: z.string().min(1).max(160),
  resource: z.string().min(1).max(240),
  summary: z.string().min(3).max(500),
  rawPayload: z.record(z.string(), z.unknown()).default({}),
  autoEscalateIncident: z.boolean().optional(),
});

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer', 'read');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const rows = db
    .prepare(
      `SELECT id, source, severity, event_type as eventType, asset_id as assetId, actor, resource,
              summary, correlated_finding_id as correlatedFindingId,
              correlated_incident_id as correlatedIncidentId, received_at as receivedAt
       FROM runtime_events WHERE org_id = ? ORDER BY received_at DESC LIMIT 100`
    )
    .all(authResult.auth.orgId);

  return jsonOk({ events: rows });
}

export async function POST(req: NextRequest) {
  // Accept EITHER authenticated user/API key (Developer+) OR authenticated TRUSTRAIL Runner (tr_run_...)
  const runner = authenticateRunnerRequest(req);
  let orgId = runner?.orgId;
  let actorEmail = runner ? `runner:${runner.name}` : '';

  if (!runner) {
    const authResult = requireAuth(req, 'Developer', 'write');
    if ('error' in authResult) return authResult.error;
    orgId = authResult.auth.orgId;
    actorEmail = authResult.auth.email;
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = IngestRuntimeEventSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid runtime telemetry payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const id = `rt-${crypto.randomUUID().slice(0, 8)}`;
  const now = new Date().toISOString();

  // Correlate against Security Graph assets and open findings
  const matchedAsset = db
    .prepare(
      `SELECT id, name FROM assets WHERE org_id = ? AND (? LIKE '%' || name || '%' OR name LIKE '%' || ? || '%') LIMIT 1`
    )
    .get(orgId!, parsed.data.resource, parsed.data.resource) as { id: string; name: string } | undefined;

  const matchedFinding = matchedAsset
    ? (db
        .prepare(`SELECT id FROM findings WHERE org_id = ? AND asset_id = ? AND status != 'Resolved' LIMIT 1`)
        .get(orgId!, matchedAsset.id) as { id: string } | undefined)
    : undefined;

  let correlatedIncidentId: string | null = null;
  const isCriticalAnomaly =
    parsed.data.severity === 'CRITICAL' ||
    parsed.data.autoEscalateIncident ||
    /privilege_escalation|container_escape|canary|unauthorized|exfiltration/i.test(parsed.data.eventType);

  if (isCriticalAnomaly) {
    correlatedIncidentId = `inc-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(
      `INSERT INTO incidents (id, org_id, title, severity, status, affected_asset, owner, summary, playbook_name, actions_taken_json, opened_at)
       VALUES (?, ?, ?, 'SEV-1', 'Open', ?, ?, ?, 'Runtime Anomaly Triage & Containment', ?, ?)`
    ).run(
      correlatedIncidentId,
      orgId!,
      `Runtime ${parsed.data.source.toUpperCase()} Anomaly: ${parsed.data.eventType}`,
      matchedAsset?.name || parsed.data.resource,
      actorEmail,
      parsed.data.summary,
      JSON.stringify([
        `Correlated from ${parsed.data.source} event ${id} (actor=${parsed.data.actor}).`,
        matchedFinding ? `Linked to open finding ${matchedFinding.id}.` : 'Created automated investigation timeline.',
      ]),
      now
    );
  }

  db.prepare(
    `INSERT INTO runtime_events
     (id, org_id, source, severity, event_type, asset_id, actor, resource, summary, raw_json, correlated_finding_id, correlated_incident_id, received_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    orgId!,
    parsed.data.source,
    parsed.data.severity,
    parsed.data.eventType,
    matchedAsset?.id || null,
    parsed.data.actor,
    parsed.data.resource,
    parsed.data.summary,
    JSON.stringify(parsed.data.rawPayload),
    matchedFinding?.id || null,
    correlatedIncidentId,
    now
  );

  publishEvent(db, {
    orgId: orgId!,
    eventType: isCriticalAnomaly ? 'anomaly.detected' : 'security_event.received',
    actorId: actorEmail,
    sourceConnector: parsed.data.source,
    sourceResourceId: parsed.data.resource,
    affectedAssetIds: matchedAsset ? [matchedAsset.id] : [],
    evidenceReference: id,
    payload: {
      severity: parsed.data.severity,
      eventType: parsed.data.eventType,
      correlatedFindingId: matchedFinding?.id || null,
      correlatedIncidentId,
    },
  });

  appendAuditLog(db, {
    orgId: orgId!,
    actorEmail,
    action: 'RUNTIME_EVENT_INGESTED',
    resourceType: 'RuntimeEvent',
    resourceId: id,
    details: `Ingested ${parsed.data.source} ${parsed.data.severity} event "${parsed.data.eventType}" on ${parsed.data.resource}.`,
  });

  return jsonOk(
    {
      eventId: id,
      correlatedAssetId: matchedAsset?.id || null,
      correlatedFindingId: matchedFinding?.id || null,
      correlatedIncidentId,
      receivedAt: now,
    },
    201
  );
}
