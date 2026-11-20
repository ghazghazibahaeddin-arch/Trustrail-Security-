import { NextRequest } from 'next/server';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Admin');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const row = db
    .prepare('SELECT id, name FROM connectors WHERE id = ? AND org_id = ?')
    .get(id, authResult.auth.orgId) as { id: string; name: string } | undefined;

  if (!row) return jsonError('Connector not found.', 404, 'NOT_FOUND');

  db.prepare(
    `UPDATE connectors SET status = 'Disconnected', availability_state = 'DISCONNECTED', health_check = 'Offline' WHERE id = ? AND org_id = ?`
  ).run(id, authResult.auth.orgId);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'CONNECTOR_DISCONNECTED',
    resourceType: 'Connector',
    resourceId: id,
    details: `Disconnected connector ${row.name}.`,
  });

  return jsonOk({ id, status: 'Disconnected', availabilityState: 'DISCONNECTED', healthCheck: 'Offline' });
}
