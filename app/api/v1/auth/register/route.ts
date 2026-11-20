import crypto from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getDb, withDbTransaction } from '@/lib/db';
import { hashPassword, sha256, signToken } from '@/lib/security/crypto';
import { SESSION_COOKIE_NAME } from '@/lib/security/auth';
import { checkRateLimit } from '@/lib/security/rate-limit';
import { getClientIp, jsonError } from '@/lib/api-response';
import { provisionNewOrgDefaults } from '@/lib/org-provisioning';
import { computeOrganizationSnapshot } from '@/lib/domain-mappers';

const RegisterSchema = z.object({
  email: z.string().email(),
  name: z.string().min(2).max(100),
  password: z.string().min(8).max(128),
  organizationName: z.string().min(2).max(120),
  edition: z.enum(['developer', 'smb', 'enterprise']).default('developer'),
});

export async function POST(req: NextRequest) {
  const ip = getClientIp(req);
  const rl = checkRateLimit(`register:${ip}`, 20, 60_000);
  if (!rl.allowed) {
    return jsonError('Too many registration attempts.', 429, 'RATE_LIMITED');
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = RegisterSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid registration payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const normalizedEmail = parsed.data.email.trim().toLowerCase();
  const existing = db
    .prepare('SELECT id FROM users WHERE lower(email) = lower(?)')
    .get(normalizedEmail);

  if (existing) {
    return jsonError('An account with this email already exists.', 409, 'EMAIL_EXISTS');
  }

  const userId = `usr-${crypto.randomUUID().slice(0, 8)}`;
  const orgId = `org-${crypto.randomUUID().slice(0, 8)}`;
  const memId = `mem-${crypto.randomUUID().slice(0, 8)}`;
  const verifyId = `ver-${crypto.randomUUID().slice(0, 8)}`;
  const rawVerifyToken = `tr_ver_${crypto.randomBytes(18).toString('hex')}`;
  const now = new Date().toISOString();
  const verifyExpires = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  const slugBase =
    parsed.data.organizationName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '') || 'workspace';
  const slug = `${slugBase}-${orgId.slice(-4)}`;

  const tierName =
    parsed.data.edition === 'enterprise'
      ? 'Enterprise Security Grid'
      : parsed.data.edition === 'smb'
      ? 'Teams & SMB Edition'
      : 'Developer Free Edition';

  withDbTransaction(db, () => {
    db.prepare(
      `INSERT INTO organizations (id, name, slug, edition, tier_name, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run(orgId, parsed.data.organizationName.trim(), slug, parsed.data.edition, tierName, now);

    db.prepare(
      `INSERT INTO users (id, email, name, password_hash, mfa_enabled, mfa_verified, email_verified, status, created_at)
       VALUES (?, ?, ?, ?, 1, 0, 0, 'Active', ?)`
    ).run(userId, normalizedEmail, parsed.data.name.trim(), hashPassword(parsed.data.password), now);

    db.prepare(
      `INSERT INTO memberships (id, user_id, org_id, role, title, status, created_at)
       VALUES (?, ?, ?, 'Owner', 'Workspace Owner', 'Active', ?)`
    ).run(memId, userId, orgId, now);

    db.prepare(
      `INSERT INTO auth_verification_tokens (id, user_id, token_hash, purpose, expires_at, created_at)
       VALUES (?, ?, ?, 'email_verify', ?, ?)`
    ).run(verifyId, userId, sha256(rawVerifyToken), verifyExpires, now);

    provisionNewOrgDefaults(db, orgId, normalizedEmail);
  });

  const token = signToken({
    userId,
    orgId,
    role: 'Owner',
    email: normalizedEmail,
  });

  const organization = computeOrganizationSnapshot(db, orgId);

  const response = NextResponse.json(
    {
      authenticated: true,
      token,
      emailVerificationRequired: true,
      ...(process.env.NODE_ENV !== 'production' ? { verificationTokenPreview: rawVerifyToken } : {}),
      user: {
        id: userId,
        email: normalizedEmail,
        name: parsed.data.name.trim(),
        role: 'Owner',
        orgId,
        emailVerified: false,
        mfaVerified: false,
      },
      organization,
      memberships: [
        {
          orgId,
          orgName: parsed.data.organizationName.trim(),
          slug,
          edition: parsed.data.edition,
          role: 'Owner',
          title: 'Workspace Owner',
        },
      ],
    },
    { status: 201 }
  );

  response.cookies.set(SESSION_COOKIE_NAME, token, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 86400,
    secure: process.env.NODE_ENV === 'production',
  });

  return response;
}

