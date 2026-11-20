import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { sha256 } from '@/lib/security/crypto';
import { hasMinRole } from '@/lib/security/auth';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';

const ALLOWED_SCOPES = ['read', 'scan', 'write', 'admin'] as const;

const CreateApiKeySchema = z.object({
  name: z.string().min(2).max(80),
  role: z.enum(['Owner', 'Admin', 'Developer', 'Viewer']).default('Developer'),
  scopes: z.array(z.enum(ALLOWED_SCOPES)).min(1).optional(),
  expiresInDays: z.number().int().min(1).max(365).optional(),
});

function parseKeyScopes(raw?: unknown): string[] {
  if (typeof raw !== 'string') return ['read', 'scan', 'write'];
  try {
    const arr = JSON.parse(raw);
    return Array.isArray(arr) ? arr.filter((s): s is string => typeof s === 'string') : ['read', 'scan', 'write'];
  } catch {
    return ['read', 'scan', 'write'];
  }
}

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const rows = db
    .prepare(
      `SELECT ak.id, ak.name, ak.key_prefix as keyPrefix, ak.role, ak.scopes_json as scopesJson,
              ak.expires_at as expiresAt, ak.rotated_from_id as rotatedFromId,
              ak.last_used_at as lastUsedAt, ak.created_at as createdAt, ak.revoked,
              u.email as createdByEmail
       FROM api_keys ak
       JOIN users u ON u.id = ak.user_id
       WHERE ak.org_id = ?
       ORDER BY ak.created_at DESC`
    )
    .all(authResult.auth.orgId) as Array<Record<string, unknown>>;

  return jsonOk({
    apiKeys: rows.map((r) => {
      const { scopesJson, ...rest } = r;
      return {
        ...rest,
        scopes: parseKeyScopes(scopesJson),
        revoked: Boolean(r.revoked),
      };
    }),
  });
}

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = CreateApiKeySchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid API key request.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  // Prevent privilege escalation: requested key role cannot exceed caller's role
  if (!hasMinRole(authResult.auth.role, parsed.data.role)) {
    return jsonError(
      `Cannot create API key with ${parsed.data.role} role when your role is ${authResult.auth.role}.`,
      403,
      'FORBIDDEN'
    );
  }

  const scopes = parsed.data.scopes ?? (parsed.data.role === 'Viewer' ? ['read'] : ['read', 'scan', 'write']);
  if (scopes.includes('admin') && authResult.auth.role !== 'Owner' && authResult.auth.role !== 'Admin') {
    return jsonError('Only Owners/Admins can issue API keys with admin scope.', 403, 'FORBIDDEN');
  }

  const keyId = `key-${crypto.randomUUID().slice(0, 8)}`;
  const rawSecret = `tr_live_${crypto.randomBytes(24).toString('hex')}`;
  const keyPrefix = `${rawSecret.slice(0, 14)}...${rawSecret.slice(-4)}`;
  const keyHash = sha256(rawSecret);
  const now = new Date();
  const expiresAt = parsed.data.expiresInDays
    ? new Date(now.getTime() + parsed.data.expiresInDays * 24 * 60 * 60 * 1000).toISOString()
    : null;

  const db = getDb();
  db.prepare(
    `INSERT INTO api_keys (id, org_id, user_id, name, key_prefix, key_hash, role, scopes_json, expires_at, last_used_at, created_at, revoked)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, 0)`
  ).run(
    keyId,
    authResult.auth.orgId,
    authResult.auth.userId,
    parsed.data.name.trim(),
    keyPrefix,
    keyHash,
    parsed.data.role,
    JSON.stringify(scopes),
    expiresAt,
    now.toISOString()
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'API_KEY_CREATED',
    resourceType: 'ApiKey',
    resourceId: keyId,
    details: `Issued scoped API key "${parsed.data.name.trim()}" (${keyPrefix}, role=${parsed.data.role}, scopes=${scopes.join(',')}).`,
  });

  return jsonOk(
    {
      apiKey: {
        id: keyId,
        name: parsed.data.name.trim(),
        keyPrefix,
        role: parsed.data.role,
        scopes,
        expiresAt,
        rotatedFromId: null,
        lastUsedAt: null,
        createdAt: now.toISOString(),
        revoked: false,
        createdByEmail: authResult.auth.email,
      },
      secret: rawSecret,
    },
    201
  );
}

