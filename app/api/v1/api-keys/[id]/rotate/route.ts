import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { getDb, withDbTransaction, appendAuditLog } from '@/lib/db';
import { sha256 } from '@/lib/security/crypto';
import { hasMinRole } from '@/lib/security/auth';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const existing = db
    .prepare(
      `SELECT id, name, key_prefix, user_id, role, scopes_json, expires_at, revoked
       FROM api_keys WHERE id = ? AND org_id = ?`
    )
    .get(id, authResult.auth.orgId) as
    | {
        id: string;
        name: string;
        key_prefix: string;
        user_id: string;
        role: 'Owner' | 'Admin' | 'Developer' | 'Viewer';
        scopes_json: string | null;
        expires_at: string | null;
        revoked: number;
      }
    | undefined;

  if (!existing) {
    return jsonError('API key not found.', 404, 'NOT_FOUND');
  }

  const isAdmin = authResult.auth.role === 'Owner' || authResult.auth.role === 'Admin';
  if (!isAdmin && existing.user_id !== authResult.auth.userId) {
    return jsonError('Only Owners/Admins can rotate another user API key.', 403, 'FORBIDDEN');
  }

  if (!hasMinRole(authResult.auth.role, existing.role)) {
    return jsonError('Cannot rotate an API key with higher privileges than your own role.', 403, 'FORBIDDEN');
  }

  const newKeyId = `key-${crypto.randomUUID().slice(0, 8)}`;
  const rawSecret = `tr_live_${crypto.randomBytes(24).toString('hex')}`;
  const keyPrefix = `${rawSecret.slice(0, 14)}...${rawSecret.slice(-4)}`;
  const keyHash = sha256(rawSecret);
  const now = new Date().toISOString();
  const scopesJson = existing.scopes_json || '["read","scan","write"]';

  withDbTransaction(db, () => {
    db.prepare('UPDATE api_keys SET revoked = 1 WHERE id = ? AND org_id = ?').run(
      existing.id,
      authResult.auth.orgId
    );

    db.prepare(
      `INSERT INTO api_keys (id, org_id, user_id, name, key_prefix, key_hash, role, scopes_json, expires_at, rotated_from_id, last_used_at, created_at, revoked)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, 0)`
    ).run(
      newKeyId,
      authResult.auth.orgId,
      authResult.auth.userId,
      existing.name,
      keyPrefix,
      keyHash,
      existing.role,
      scopesJson,
      existing.expires_at,
      existing.id,
      now
    );

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'API_KEY_ROTATED',
      resourceType: 'ApiKey',
      resourceId: newKeyId,
      details: `Rotated API key "${existing.name}" (revoked ${existing.id}, issued ${newKeyId} ${keyPrefix}).`,
    });
  });

  return jsonOk(
    {
      rotatedFromId: existing.id,
      apiKey: {
        id: newKeyId,
        name: existing.name,
        keyPrefix,
        role: existing.role,
        scopes: JSON.parse(scopesJson) as string[],
        expiresAt: existing.expires_at,
        rotatedFromId: existing.id,
        lastUsedAt: null,
        createdAt: now,
        revoked: false,
        createdByEmail: authResult.auth.email,
      },
      secret: rawSecret,
    },
    201
  );
}
