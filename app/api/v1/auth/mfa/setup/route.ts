import { NextRequest } from 'next/server';
import { getDb, appendAuditLog } from '@/lib/db';
import { buildOtpAuthUri, generateTotpSecret } from '@/lib/security/crypto';
import { encryptSecretPayload } from '@/lib/security/vault';
import { jsonOk, requireAuth } from '@/lib/api-response';

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const { auth } = authResult;
  const db = getDb();
  const secret = generateTotpSecret();
  const encrypted = encryptSecretPayload({ secret }, { aad: auth.userId });
  const otpauthUri = buildOtpAuthUri(auth.email, secret);

  db.prepare('UPDATE users SET mfa_secret_enc = ?, mfa_verified = 0 WHERE id = ?').run(
    encrypted,
    auth.userId
  );

  appendAuditLog(db, {
    orgId: auth.orgId,
    actorEmail: auth.email,
    action: 'MFA_ENROLLMENT_STARTED',
    resourceType: 'User',
    resourceId: auth.userId,
    details: 'Generated AES-256-GCM encrypted TOTP MFA secret pending 6-digit verification.',
  });

  return jsonOk({
    enrolled: true,
    mfaVerified: false,
    secret,
    otpauthUri,
  });
}
