import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { verifyTotpCode } from '@/lib/security/crypto';
import { decryptSecretPayload } from '@/lib/security/vault';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';

const VerifyMfaSchema = z.object({
  code: z.string().min(6).max(12),
});

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = VerifyMfaSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('6-digit TOTP code is required.', 400, 'VALIDATION_ERROR');
  }

  const db = getDb();
  const row = db
    .prepare('SELECT mfa_secret_enc FROM users WHERE id = ?')
    .get(authResult.auth.userId) as { mfa_secret_enc: string | null } | undefined;

  if (!row?.mfa_secret_enc) {
    return jsonError('MFA setup has not been initialized yet.', 400, 'MFA_NOT_INITIALIZED');
  }

  let secret = '';
  try {
    const dec = decryptSecretPayload<{ secret?: string }>(row.mfa_secret_enc, {
      aad: authResult.auth.userId,
    });
    secret = dec.data?.secret || '';
  } catch {
    secret = '';
  }

  if (!secret || !verifyTotpCode(secret, parsed.data.code)) {
    return jsonError('Invalid or expired 6-digit TOTP verification code.', 400, 'INVALID_MFA_CODE');
  }

  db.prepare('UPDATE users SET mfa_verified = 1, mfa_enabled = 1 WHERE id = ?').run(authResult.auth.userId);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'MFA_VERIFIED',
    resourceType: 'User',
    resourceId: authResult.auth.userId,
    details: 'TOTP MFA verified and enforced on account logins.',
  });

  return jsonOk({ mfaVerified: true });
}

export async function DELETE(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  db.prepare('UPDATE users SET mfa_secret_enc = NULL, mfa_verified = 0 WHERE id = ?').run(
    authResult.auth.userId
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'MFA_DISABLED',
    resourceType: 'User',
    resourceId: authResult.auth.userId,
    details: 'Disabled TOTP MFA requirement for user account.',
  });

  return jsonOk({ mfaVerified: false });
}
