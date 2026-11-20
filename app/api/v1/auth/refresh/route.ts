import { NextRequest, NextResponse } from 'next/server';
import { getDb, appendAuditLog } from '@/lib/db';
import { signToken } from '@/lib/security/crypto';
import { SESSION_COOKIE_NAME } from '@/lib/security/auth';
import { jsonError, requireAuth } from '@/lib/api-response';

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const { auth } = authResult;
  if (auth.authMethod !== 'session') {
    return jsonError('Token refresh applies only to session tokens.', 400, 'INVALID_TOKEN_TYPE');
  }

  const db = getDb();
  const nowSec = Math.floor(Date.now() / 1000);
  if (auth.jti) {
    db.prepare(
      `INSERT OR IGNORE INTO revoked_tokens (jti, user_id, expires_at, revoked_at)
       VALUES (?, ?, ?, ?)`
    ).run(auth.jti, auth.userId, auth.exp ?? nowSec + 86400, new Date().toISOString());
  }

  const nextToken = signToken({
    userId: auth.userId,
    orgId: auth.orgId,
    role: auth.role,
    email: auth.email,
  });

  appendAuditLog(db, {
    orgId: auth.orgId,
    actorEmail: auth.email,
    action: 'SESSION_REFRESHED',
    resourceType: 'Session',
    resourceId: auth.userId,
    details: 'Rotated session JWT and revoked previous session identifier.',
  });

  const response = NextResponse.json({
    refreshed: true,
    token: nextToken,
    user: {
      id: auth.userId,
      email: auth.email,
      name: auth.name,
      role: auth.role,
      orgId: auth.orgId,
      emailVerified: Boolean(auth.emailVerified),
      mfaVerified: Boolean(auth.mfaVerified),
    },
  });

  response.cookies.set(SESSION_COOKIE_NAME, nextToken, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 86400,
    secure: process.env.NODE_ENV === 'production',
  });

  return response;
}
