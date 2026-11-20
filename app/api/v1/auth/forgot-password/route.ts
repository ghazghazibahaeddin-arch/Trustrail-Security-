import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { sha256 } from '@/lib/security/crypto';
import { checkRateLimit } from '@/lib/security/rate-limit';
import { getClientIp, jsonError, jsonOk } from '@/lib/api-response';

const ForgotPasswordSchema = z.object({
  email: z.string().email(),
});

export async function POST(req: NextRequest) {
  const ip = getClientIp(req);
  const rl = checkRateLimit(`forgot-pwd:${ip}`, 10, 60_000);
  if (!rl.allowed) {
    return jsonError('Too many password reset requests.', 429, 'RATE_LIMITED');
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = ForgotPasswordSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Valid email address required.', 400, 'VALIDATION_ERROR');
  }

  const db = getDb();
  const normalizedEmail = parsed.data.email.trim().toLowerCase();
  const user = db
    .prepare("SELECT id, email FROM users WHERE lower(email) = lower(?) AND status = 'Active'")
    .get(normalizedEmail) as { id: string; email: string } | undefined;

  let resetTokenPreview: string | undefined;

  if (user) {
    const tokenId = `rst-${crypto.randomUUID().slice(0, 8)}`;
    const rawToken = `tr_rst_${crypto.randomBytes(20).toString('hex')}`;
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000).toISOString();

    db.prepare(
      `INSERT INTO auth_verification_tokens (id, user_id, token_hash, purpose, expires_at, created_at)
       VALUES (?, ?, ?, 'password_reset', ?, ?)`
    ).run(tokenId, user.id, sha256(rawToken), expiresAt, now);

    const mem = db
      .prepare("SELECT org_id FROM memberships WHERE user_id = ? AND status = 'Active' LIMIT 1")
      .get(user.id) as { org_id: string } | undefined;

    if (mem) {
      appendAuditLog(db, {
        orgId: mem.org_id,
        actorEmail: user.email,
        action: 'PASSWORD_RESET_REQUESTED',
        resourceType: 'User',
        resourceId: user.id,
        details: 'Issued 15-minute single-use password reset token.',
      });
    }

    if (process.env.NODE_ENV !== 'production') {
      resetTokenPreview = rawToken;
    }
  }

  return jsonOk({
    accepted: true,
    message: 'If an active account exists for this email, a single-use password reset token has been generated (expires in 15 minutes).',
    ...(resetTokenPreview ? { resetTokenPreview } : {}),
  });
}
