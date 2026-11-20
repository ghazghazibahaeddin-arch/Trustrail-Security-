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
    .prepare('SELECT id, title, revoked FROM trust_receipts WHERE id = ? AND org_id = ?')
    .get(id, authResult.auth.orgId) as { id: string; title: string; revoked: number } | undefined;

  if (!row) return jsonError('Trust Passport not found.', 404, 'NOT_FOUND');

  const nextRevoked = row.revoked ? 0 : 1;
  db.prepare('UPDATE trust_receipts SET revoked = ? WHERE id = ? AND org_id = ?').run(
    nextRevoked,
    id,
    authResult.auth.orgId
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: nextRevoked ? 'TRUST_PASSPORT_REVOKED' : 'TRUST_PASSPORT_REINSTATED',
    resourceType: 'TrustReceipt',
    resourceId: id,
    details: `${nextRevoked ? 'Revoked' : 'Reinstated'} Trust Passport "${row.title}".`,
  });

  return jsonOk({ id, revoked: Boolean(nextRevoked) });
}
