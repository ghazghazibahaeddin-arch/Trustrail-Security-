import { NextRequest } from 'next/server';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';

export async function DELETE(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Admin', 'write');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const runner = db
    .prepare(`SELECT id, name FROM runners WHERE id = ? AND org_id = ?`)
    .get(id, authResult.auth.orgId) as { id: string; name: string } | undefined;

  if (!runner) {
    return jsonError('Runner not found in organization.', 404, 'RUNNER_NOT_FOUND');
  }

  db.prepare(`UPDATE runners SET status = 'Revoked' WHERE id = ? AND org_id = ?`).run(
    id,
    authResult.auth.orgId
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'RUNNER_REVOKED',
    resourceType: 'Runner',
    resourceId: id,
    details: `Revoked TRUSTRAIL Runner "${runner.name}".`,
  });

  return jsonOk({ id, revoked: true, status: 'Revoked' });
}
