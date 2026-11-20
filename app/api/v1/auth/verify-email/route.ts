import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { sha256 } from '@/lib/security/crypto';
import { authenticateRequest } from '@/lib/security/auth';
import { jsonError, jsonOk } from '@/lib/api-response';

const VerifyEmailSchema = z.object({
  token: z.string().min(10).optional(),
  resend: z.boolean().optional(),
});

export async function POST(req: NextRequest) {
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = VerifyEmailSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid email verification request.', 400, 'VALIDATION_ERROR');
  }

  const db = getDb();

  if (parsed.data.resend) {
    const auth = authenticateRequest(req);
    if (!auth) {
      return jsonError('Authentication required to issue a new verification token.', 401, 'UNAUTHORIZED');
    }
    const verifyId = `ver-${crypto.randomUUID().slice(0, 8)}`;
    const rawToken = `tr_ver_${crypto.randomBytes(18).toString('hex')}`;
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

    db.prepare(
      `INSERT INTO auth_verification_tokens (id, user_id, token_hash, purpose, expires_at, created_at)
       VALUES (?, ?, ?, 'email_verify', ?, ?)`
    ).run(verifyId, auth.userId, sha256(rawToken), expiresAt, now);

    return jsonOk({
      issued: true,
      expiresAt,
      ...(process.env.NODE_ENV !== 'production' ? { verificationTokenPreview: rawToken } : {}),
    });
  }

  if (!parsed.data.token) {
    return jsonError('Verification token is required.', 400, 'TOKEN_REQUIRED');
  }

  const tokenHash = sha256(parsed.data.token.trim());
  const row = db
    .prepare(
      `SELECT vt.id, vt.user_id, vt.expires_at, vt.used_at, u.email
       FROM auth_verification_tokens vt
       JOIN users u ON u.id = vt.user_id
       WHERE vt.token_hash = ? AND vt.purpose = 'email_verify'`
    )
    .get(tokenHash) as
    | { id: string; user_id: string; expires_at: string; used_at: string | null; email: string }
    | undefined;

  if (!row || row.used_at || Date.parse(row.expires_at) < Date.now()) {
    return jsonError('Verification token is invalid or expired.', 400, 'INVALID_OR_EXPIRED_TOKEN');
  }

  const now = new Date().toISOString();
  db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').run(row.user_id);
  db.prepare('UPDATE auth_verification_tokens SET used_at = ? WHERE id = ?').run(now, row.id);

  const mem = db
    .prepare("SELECT org_id FROM memberships WHERE user_id = ? AND status = 'Active' LIMIT 1")
    .get(row.user_id) as { org_id: string } | undefined;

  if (mem) {
    appendAuditLog(db, {
      orgId: mem.org_id,
      actorEmail: row.email,
      action: 'EMAIL_VERIFIED',
      resourceType: 'User',
      resourceId: row.user_id,
      details: 'Completed single-use cryptographic email verification.',
    });
  }

  return jsonOk({ verified: true, emailVerified: true });
}
