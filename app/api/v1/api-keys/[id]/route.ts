import { NextRequest } from 'next/server';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';

export async function DELETE(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const row = db
    .prepare('SELECT id, name, key_prefix, user_id, revoked FROM api_keys WHERE id = ? AND org_id = ?')
    .get(id, authResult.auth.orgId) as
    | { id: string; name: string; key_prefix: string; user_id: string; revoked: number }
    | undefined;

  if (!row) {
    return jsonError('API key not found.', 404, 'NOT_FOUND');
  }

  // Developers can revoke their own keys; Admin/Owner can revoke any org key
  const isAdmin = authResult.auth.role === 'Owner' || authResult.auth.role === 'Admin';
  if (!isAdmin && row.user_id !== authResult.auth.userId) {
    return jsonError('Only Owners/Admins can revoke another user API key.', 403, 'FORBIDDEN');
  }

  db.prepare('UPDATE api_keys SET revoked = 1 WHERE id = ? AND org_id = ?').run(id, authResult.auth.orgId);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'API_KEY_REVOKED',
    resourceType: 'ApiKey',
    resourceId: id,
    details: `Revoked API key "${row.name}" (${row.key_prefix}).`,
  });

  return jsonOk({ id, revoked: true });
}
