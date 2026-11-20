import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { hashPassword, verifyPassword } from '@/lib/security/crypto';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';

const UpdateProfileSchema = z.object({
  name: z.string().min(2).max(100).optional(),
  currentPassword: z.string().min(1).optional(),
  newPassword: z.string().min(8).max(128).optional(),
});

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const user = db
    .prepare(
      `SELECT id, email, name, mfa_enabled as mfaEnabled, mfa_verified as mfaVerified,
              email_verified as emailVerified, status, created_at as createdAt
       FROM users WHERE id = ?`
    )
    .get(authResult.auth.userId) as Record<string, unknown> | undefined;

  if (!user) return jsonError('User not found.', 404, 'NOT_FOUND');

  return jsonOk({
    profile: {
      ...user,
      mfaEnabled: Boolean(user.mfaEnabled),
      mfaVerified: Boolean(user.mfaVerified),
      emailVerified: Boolean(user.emailVerified),
    },
  });
}

export async function PATCH(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = UpdateProfileSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid profile update payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const userRow = db
    .prepare('SELECT id, name, password_hash FROM users WHERE id = ?')
    .get(authResult.auth.userId) as { id: string; name: string; password_hash: string } | undefined;

  if (!userRow) return jsonError('User not found.', 404, 'NOT_FOUND');

  let nextHash = userRow.password_hash;
  let passwordChanged = false;

  if (parsed.data.newPassword) {
    if (!parsed.data.currentPassword || !verifyPassword(parsed.data.currentPassword, userRow.password_hash)) {
      return jsonError('Current password is required and must match.', 401, 'INVALID_CURRENT_PASSWORD');
    }
    nextHash = hashPassword(parsed.data.newPassword);
    passwordChanged = true;
  }

  const nextName = parsed.data.name?.trim() || userRow.name;
  db.prepare('UPDATE users SET name = ?, password_hash = ? WHERE id = ?').run(
    nextName,
    nextHash,
    userRow.id
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: passwordChanged ? 'USER_PASSWORD_CHANGED' : 'USER_PROFILE_UPDATED',
    resourceType: 'User',
    resourceId: userRow.id,
    details: passwordChanged
      ? 'Updated profile and rotated user account password.'
      : `Updated profile display name to "${nextName}".`,
  });

  return jsonOk({
    updated: true,
    profile: {
      id: userRow.id,
      email: authResult.auth.email,
      name: nextName,
      passwordChanged,
    },
  });
}
