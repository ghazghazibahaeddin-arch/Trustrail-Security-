import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { computeOrganizationSnapshot } from '@/lib/domain-mappers';

const UpdateIncidentSchema = z.object({
  status: z.enum(['Open', 'Contained', 'Recovered', 'Closed']).optional(),
  appendAction: z.string().min(2).max(400).optional(),
});

export async function PATCH(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const row = db
    .prepare(
      `SELECT id, title, status, actions_taken_json, closed_at
       FROM incidents WHERE id = ? AND org_id = ?`
    )
    .get(id, authResult.auth.orgId) as
    | { id: string; title: string; status: string; actions_taken_json: string; closed_at: string | null }
    | undefined;

  if (!row) return jsonError('Incident not found.', 404, 'NOT_FOUND');

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = UpdateIncidentSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid incident update payload.', 400, 'VALIDATION_ERROR');
  }

  const actions = JSON.parse(row.actions_taken_json || '[]') as string[];
  const nextStatus = parsed.data.status || row.status;
  if (parsed.data.appendAction) {
    actions.push(`${parsed.data.appendAction.trim()} (${authResult.auth.email})`);
  } else if (parsed.data.status && parsed.data.status !== row.status) {
    actions.push(`Transitioned status ${row.status} → ${parsed.data.status} by ${authResult.auth.email}`);
  }

  const closedAt = nextStatus === 'Closed' ? new Date().toISOString() : row.closed_at;

  db.prepare(
    `UPDATE incidents SET status = ?, actions_taken_json = ?, closed_at = ? WHERE id = ? AND org_id = ?`
  ).run(nextStatus, JSON.stringify(actions), closedAt, id, authResult.auth.orgId);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: `INCIDENT_${nextStatus.toUpperCase()}`,
    resourceType: 'Incident',
    resourceId: id,
    details: `${row.title}: status=${nextStatus}${parsed.data.appendAction ? ` | ${parsed.data.appendAction}` : ''}`,
  });

  const updated = db
    .prepare(
      `SELECT id, title, severity, status, affected_asset as affectedAsset, owner, summary, playbook_name as playbookName, actions_taken_json as actionsTakenJson, opened_at as openedAt, closed_at as closedAt
       FROM incidents WHERE id = ? AND org_id = ?`
    )
    .get(id, authResult.auth.orgId) as Record<string, unknown>;

  return jsonOk({
    incident: {
      ...updated,
      actionsTaken: JSON.parse(String(updated.actionsTakenJson || '[]')),
    },
    organization: computeOrganizationSnapshot(db, authResult.auth.orgId),
  });
}
