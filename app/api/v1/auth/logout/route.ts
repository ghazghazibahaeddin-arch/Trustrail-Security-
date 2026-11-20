import { NextRequest, NextResponse } from 'next/server';
import { getDb } from '@/lib/db';
import { verifyToken } from '@/lib/security/crypto';
import { extractAuthToken, SESSION_COOKIE_NAME } from '@/lib/security/auth';

export async function POST(req: NextRequest) {
  const token = extractAuthToken(req);
  if (token && !token.startsWith('tr_live_')) {
    const claims = verifyToken(token);
    if (claims && typeof claims.jti === 'string' && typeof claims.userId === 'string') {
      const db = getDb();
      const nowSec = Math.floor(Date.now() / 1000);
      db.prepare('DELETE FROM revoked_tokens WHERE expires_at < ?').run(nowSec);
      db.prepare(
        `INSERT OR IGNORE INTO revoked_tokens (jti, user_id, expires_at, revoked_at)
         VALUES (?, ?, ?, ?)`
      ).run(
        claims.jti,
        claims.userId,
        typeof claims.exp === 'number' ? claims.exp : nowSec + 86400,
        new Date().toISOString()
      );
    }
  }

  const response = NextResponse.json({ authenticated: false, loggedOut: true });
  response.cookies.set(SESSION_COOKIE_NAME, '', {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 0,
  });
  return response;
}

