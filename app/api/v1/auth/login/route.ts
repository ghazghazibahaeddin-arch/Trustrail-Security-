import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { verifyPassword, signToken, verifyTotpCode } from '@/lib/security/crypto';
import { decryptSecretPayload } from '@/lib/security/vault';
import { SESSION_COOKIE_NAME } from '@/lib/security/auth';
import { checkRateLimit } from '@/lib/security/rate-limit';
import { getClientIp, jsonError } from '@/lib/api-response';
import { computeOrganizationSnapshot } from '@/lib/domain-mappers';

const LoginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  orgId: z.string().optional(),
  mfaCode: z.string().max(12).optional(),
});

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MS = 15 * 60 * 1000;

function recordFailedAttempt(emailKey: string): { locked: boolean; lockedUntil: string | null } {
  const db = getDb();
  const now = new Date();
  const row = db
    .prepare('SELECT attempts, locked_until FROM login_attempts WHERE email_key = ?')
    .get(emailKey) as { attempts: number; locked_until: string | null } | undefined;

  const previousAttempts =
    row && (!row.locked_until || Date.parse(row.locked_until) > now.getTime()) ? row.attempts : 0;
  const nextAttempts = previousAttempts + 1;
  const lockedUntil =
    nextAttempts >= MAX_FAILED_ATTEMPTS ? new Date(now.getTime() + LOCKOUT_MS).toISOString() : null;

  db.prepare(
    `INSERT INTO login_attempts (email_key, attempts, locked_until, last_attempt_at)
     VALUES (?, ?, ?, ?)
     ON CONFLICT(email_key) DO UPDATE SET
       attempts = excluded.attempts,
       locked_until = excluded.locked_until,
       last_attempt_at = excluded.last_attempt_at`
  ).run(emailKey, nextAttempts, lockedUntil, now.toISOString());

  return { locked: Boolean(lockedUntil), lockedUntil };
}

export async function POST(req: NextRequest) {
  const ip = getClientIp(req);
  const rl = checkRateLimit(`login:${ip}`, 30, 60_000);
  if (!rl.allowed) {
    return jsonError('Too many login attempts. Please wait a minute.', 429, 'RATE_LIMITED');
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = LoginSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid credentials format.', 400, 'VALIDATION_ERROR');
  }

  const db = getDb();
  const emailKey = parsed.data.email.trim().toLowerCase();

  const attemptRow = db
    .prepare('SELECT attempts, locked_until FROM login_attempts WHERE email_key = ?')
    .get(emailKey) as { attempts: number; locked_until: string | null } | undefined;

  if (attemptRow?.locked_until && Date.parse(attemptRow.locked_until) > Date.now()) {
    return jsonError(
      'Account temporarily locked due to repeated failed login attempts. Try again later or reset your password.',
      429,
      'ACCOUNT_LOCKED',
      { lockedUntil: attemptRow.locked_until }
    );
  }

  const user = db
    .prepare(
      `SELECT id, email, name, password_hash, status, mfa_secret_enc, mfa_verified, email_verified
       FROM users WHERE lower(email) = lower(?)`
    )
    .get(emailKey) as
    | {
        id: string;
        email: string;
        name: string;
        password_hash: string;
        status: string;
        mfa_secret_enc: string | null;
        mfa_verified: number;
        email_verified: number;
      }
    | undefined;

  if (user && user.status === 'Disabled') {
    return jsonError('This user account has been disabled by an administrator.', 403, 'ACCOUNT_DISABLED');
  }

  if (!user || !verifyPassword(parsed.data.password, user.password_hash)) {
    const lockState = recordFailedAttempt(emailKey);
    if (lockState.locked) {
      return jsonError(
        'Too many failed login attempts. Account locked for 15 minutes.',
        429,
        'ACCOUNT_LOCKED',
        { lockedUntil: lockState.lockedUntil }
      );
    }
    return jsonError('Invalid email or password.', 401, 'INVALID_CREDENTIALS');
  }

  // Enforce TOTP MFA if user completed MFA enrollment
  if (user.mfa_verified === 1 && user.mfa_secret_enc) {
    if (!parsed.data.mfaCode || !parsed.data.mfaCode.trim()) {
      return jsonError('Two-factor authentication TOTP code is required.', 401, 'MFA_REQUIRED', {
        mfaRequired: true,
      });
    }
    let totpSecret = '';
    try {
      const dec = decryptSecretPayload<{ secret?: string }>(user.mfa_secret_enc, { aad: user.id });
      totpSecret = dec.data?.secret || '';
    } catch {
      totpSecret = '';
    }
    if (!totpSecret || !verifyTotpCode(totpSecret, parsed.data.mfaCode)) {
      recordFailedAttempt(emailKey);
      return jsonError('Invalid TOTP verification code.', 401, 'INVALID_MFA_CODE', {
        mfaRequired: true,
      });
    }
  }

  // Reset lockout counter on successful authentication
  db.prepare('DELETE FROM login_attempts WHERE email_key = ?').run(emailKey);

  const memberships = db
    .prepare(
      `SELECT m.org_id as orgId, o.name as orgName, o.slug, o.edition, m.role, m.title
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.status = 'Active'`
    )
    .all(user.id) as Array<{
    orgId: string;
    orgName: string;
    slug: string;
    edition: string;
    role: 'Owner' | 'Admin' | 'Developer' | 'Viewer';
    title: string;
  }>;

  if (memberships.length === 0) {
    return jsonError('User has no active organization memberships.', 403, 'NO_MEMBERSHIP');
  }

  const selected = parsed.data.orgId
    ? memberships.find((m) => m.orgId === parsed.data.orgId)
    : memberships[0];

  if (!selected) {
    return jsonError('Requested organization membership not found.', 403, 'FORBIDDEN_ORG');
  }

  const token = signToken({
    userId: user.id,
    orgId: selected.orgId,
    role: selected.role,
    email: user.email,
  });

  appendAuditLog(db, {
    orgId: selected.orgId,
    actorEmail: user.email,
    action: 'USER_LOGIN',
    resourceType: 'Session',
    resourceId: user.id,
    details: `Authenticated session established with role ${selected.role}${user.mfa_verified ? ' (TOTP MFA verified)' : ''}.`,
  });

  const organization = computeOrganizationSnapshot(db, selected.orgId);

  const response = NextResponse.json({
    authenticated: true,
    token,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      role: selected.role,
      orgId: selected.orgId,
      emailVerified: Boolean(user.email_verified),
      mfaVerified: Boolean(user.mfa_verified),
    },
    organization,
    memberships,
  });

  response.cookies.set(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 86400,
    secure: process.env.NODE_ENV === 'production',
  });

  return response;
}

