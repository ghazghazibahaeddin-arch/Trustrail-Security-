import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, withDbTransaction, appendAuditLog } from '@/lib/db';
import { hashPassword, sha256 } from '@/lib/security/crypto';
import { jsonError, jsonOk } from '@/lib/api-response';

const ResetPasswordSchema = z.object({
  token: z.string().min(10),
  newPassword: z.string().min(8).max(128),
});

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = ResetPasswordSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Valid reset token and new password (min 8 chars) are required.', 400, 'VALIDATION_ERROR');
  }

  const db = getDb();
  const tokenHash = sha256(parsed.data.token.trim());
  const row = db
    .prepare(
      `SELECT vt.id, vt.user_id, vt.expires_at, vt.used_at, u.email
       FROM auth_verification_tokens vt
       JOIN users u ON u.id = vt.user_id
       WHERE vt.token_hash = ? AND vt.purpose = 'password_reset'`
    )
    .get(tokenHash) as
    | { id: string; user_id: string; expires_at: string; used_at: string | null; email: string }
    | undefined;

  if (!row || row.used_at || Date.parse(row.expires_at) < Date.now()) {
    return jsonError('Password reset token is invalid or expired.', 400, 'INVALID_OR_EXPIRED_TOKEN');
  }

  const now = new Date().toISOString();
  withDbTransaction(db, () => {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(
      hashPassword(parsed.data.newPassword),
      row.user_id
    );
    db.prepare('UPDATE auth_verification_tokens SET used_at = ? WHERE id = ?').run(now, row.id);
    db.prepare('DELETE FROM login_attempts WHERE email_key = ?').run(row.email.toLowerCase());
  });

  const mem = db
    .prepare("SELECT org_id FROM memberships WHERE user_id = ? AND status = 'Active' LIMIT 1")
    .get(row.user_id) as { org_id: string } | undefined;

  if (mem) {
    appendAuditLog(db, {
      orgId: mem.org_id,
      actorEmail: row.email,
      action: 'PASSWORD_RESET_COMPLETED',
      resourceType: 'User',
      resourceId: row.user_id,
      details: 'Password reset completed using verified single-use reset token and lockout cleared.',
    });
  }

  return jsonOk({ reset: true, email: row.email });
}
