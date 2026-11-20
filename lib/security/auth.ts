import { NextRequest } from 'next/server';
import { getDb } from '@/lib/db';
import { sha256, verifyToken } from '@/lib/security/crypto';
import { checkRateLimit } from '@/lib/security/rate-limit';

export type Role = 'Owner' | 'Admin' | 'Developer' | 'Viewer';

export interface AuthContext {
  userId: string;
  email: string;
  name: string;
  orgId: string;
  role: Role;
  authMethod?: 'session' | 'api_key';
  apiKeyId?: string;
  scopes: string[];
  jti?: string;
  exp?: number;
  emailVerified?: boolean;
  mfaVerified?: boolean;
}

export const SESSION_COOKIE_NAME = 'trustrail_session';

const ROLE_WEIGHT: Record<Role, number> = {
  Viewer: 1,
  Developer: 2,
  Admin: 3,
  Owner: 4,
};

export function hasMinRole(actual: Role, required: Role): boolean {
  return ROLE_WEIGHT[actual] >= ROLE_WEIGHT[required];
}

export function extractAuthToken(req: NextRequest): string | null {
  const authHeader = req.headers.get('authorization');
  if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    return authHeader.slice(7).trim();
  }
  const apiKeyHeader = req.headers.get('x-api-key');
  if (apiKeyHeader?.trim()) {
    return apiKeyHeader.trim();
  }
  const cookie = req.cookies.get(SESSION_COOKIE_NAME);
  if (cookie?.value) {
    return cookie.value;
  }
  return null;
}

function parseScopes(scopesJson?: string | null): string[] {
  if (!scopesJson) return ['read', 'scan', 'write'];
  try {
    const parsed = JSON.parse(scopesJson);
    if (Array.isArray(parsed)) {
      return parsed.filter((s): s is string => typeof s === 'string' && s.length > 0);
    }
  } catch {
    // fallback below
  }
  return ['read', 'scan', 'write'];
}

export function authenticateRequest(req: NextRequest): AuthContext | null {
  const token = extractAuthToken(req);
  if (!token) return null;

  const db = getDb();

  // 1. Scoped API Key authentication (`tr_live_...`)
  if (token.startsWith('tr_live_')) {
    const ip = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || req.headers.get('x-real-ip') || '127.0.0.1';
    const rlFailCheck = checkRateLimit(`apikey-fail:${ip}`, 30, 60_000);
    if (!rlFailCheck.allowed) {
      return null;
    }

    const keyHash = sha256(token);
    const keyRow = db
      .prepare(
        `SELECT ak.id as key_id, ak.org_id, ak.user_id, ak.role as key_role, ak.revoked,
                ak.scopes_json, ak.expires_at,
                u.email, u.name, u.status as user_status, u.email_verified, u.mfa_verified,
                m.status as membership_status, m.role as member_role
         FROM api_keys ak
         JOIN users u ON u.id = ak.user_id
         JOIN memberships m ON m.user_id = ak.user_id AND m.org_id = ak.org_id
         WHERE ak.key_hash = ? AND ak.revoked = 0 AND m.status = 'Active' AND u.status = 'Active'`
      )
      .get(keyHash) as
      | {
          key_id: string;
          org_id: string;
          user_id: string;
          key_role: Role;
          revoked: number;
          scopes_json: string | null;
          expires_at: string | null;
          email: string;
          name: string;
          user_status: string;
          email_verified: number;
          mfa_verified: number;
          membership_status: string;
          member_role: Role;
        }
      | undefined;

    if (!keyRow) return null;

    if (keyRow.expires_at && new Date(keyRow.expires_at).getTime() <= Date.now()) {
      return null;
    }

    // Effective role is the lower privilege between membership role and key role
    const effectiveRole: Role =
      ROLE_WEIGHT[keyRow.key_role] <= ROLE_WEIGHT[keyRow.member_role]
        ? keyRow.key_role
        : keyRow.member_role;

    db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(
      new Date().toISOString(),
      keyRow.key_id
    );

    return {
      userId: keyRow.user_id,
      email: keyRow.email,
      name: keyRow.name,
      orgId: keyRow.org_id,
      role: effectiveRole,
      authMethod: 'api_key',
      apiKeyId: keyRow.key_id,
      scopes: parseScopes(keyRow.scopes_json),
      emailVerified: Boolean(keyRow.email_verified),
      mfaVerified: Boolean(keyRow.mfa_verified),
    };
  }

  // 2. Signed HMAC Session Token authentication
  const claims = verifyToken(token);
  if (!claims || typeof claims.userId !== 'string' || typeof claims.orgId !== 'string') {
    return null;
  }

  const jti = typeof claims.jti === 'string' ? claims.jti : undefined;
  const exp = typeof claims.exp === 'number' ? claims.exp : undefined;

  if (jti) {
    const revoked = db.prepare('SELECT jti FROM revoked_tokens WHERE jti = ?').get(jti);
    if (revoked) return null;
  }

  const row = db
    .prepare(
      `SELECT u.id as user_id, u.email, u.name, u.status as user_status, u.email_verified, u.mfa_verified,
              m.org_id, m.role, m.status
       FROM users u
       JOIN memberships m ON m.user_id = u.id
       WHERE u.id = ? AND m.org_id = ? AND m.status = 'Active' AND u.status = 'Active'`
    )
    .get(claims.userId, claims.orgId) as
    | {
        user_id: string;
        email: string;
        name: string;
        user_status: string;
        email_verified: number;
        mfa_verified: number;
        org_id: string;
        role: Role;
        status: string;
      }
    | undefined;

  if (!row) return null;

  return {
    userId: row.user_id,
    email: row.email,
    name: row.name,
    orgId: row.org_id,
    role: row.role,
    authMethod: 'session',
    scopes: ['read', 'scan', 'write', 'admin'],
    jti,
    exp,
    emailVerified: Boolean(row.email_verified),
    mfaVerified: Boolean(row.mfa_verified),
  };
}

