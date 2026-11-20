import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { hashPassword } from '@/lib/security/crypto';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';

const InviteMemberSchema = z.object({
  email: z.string().email(),
  name: z.string().min(2).max(100),
  role: z.enum(['Owner', 'Admin', 'Developer', 'Viewer']),
  title: z.string().min(2).max(100).default('Security Engineer'),
});

const UpdateMemberSchema = z.object({
  membershipId: z.string().min(1),
  role: z.enum(['Owner', 'Admin', 'Developer', 'Viewer']).optional(),
  status: z.enum(['Active', 'Suspended']).optional(),
  userStatus: z.enum(['Active', 'Disabled']).optional(),
});

function fetchTeamMembers(orgId: string) {
  const db = getDb();
  return db
    .prepare(
      `SELECT m.id as membershipId, u.id as userId, u.name, u.email, m.role, m.title, m.status,
              u.status as userStatus, u.mfa_enabled as mfaEnabled, u.mfa_verified as mfaVerified
       FROM memberships m
       JOIN users u ON u.id = m.user_id
       WHERE m.org_id = ?
       ORDER BY m.created_at ASC`
    )
    .all(orgId)
    .map((r: Record<string, unknown>) => ({
      ...r,
      mfaEnabled: Boolean(r.mfaEnabled || r.mfaVerified),
      mfaVerified: Boolean(r.mfaVerified),
    }));
}

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  return jsonOk({ members: fetchTeamMembers(authResult.auth.orgId) });
}

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Admin');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = InviteMemberSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid member invitation payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  if (parsed.data.role === 'Owner' && authResult.auth.role !== 'Owner') {
    return jsonError('Only an Owner can assign the Owner role.', 403, 'FORBIDDEN_ROLE_ESCALATION');
  }

  const db = getDb();
  const normalizedEmail = parsed.data.email.trim().toLowerCase();
  const now = new Date().toISOString();

  let userRow = db
    .prepare('SELECT id FROM users WHERE lower(email) = lower(?)')
    .get(normalizedEmail) as { id: string } | undefined;

  if (!userRow) {
    const newUserId = `usr-${crypto.randomUUID().slice(0, 8)}`;
    const tempPass = crypto.randomBytes(16).toString('hex');
    db.prepare(
      `INSERT INTO users (id, email, name, password_hash, mfa_enabled, mfa_verified, email_verified, status, created_at)
       VALUES (?, ?, ?, ?, 1, 0, 1, 'Active', ?)`
    ).run(newUserId, normalizedEmail, parsed.data.name.trim(), hashPassword(tempPass), now);
    userRow = { id: newUserId };
  }

  const existingMembership = db
    .prepare('SELECT id FROM memberships WHERE user_id = ? AND org_id = ?')
    .get(userRow.id, authResult.auth.orgId);

  if (existingMembership) {
    return jsonError('User is already a member of this organization.', 409, 'MEMBER_EXISTS');
  }

  const memId = `mem-${crypto.randomUUID().slice(0, 8)}`;
  db.prepare(
    `INSERT INTO memberships (id, user_id, org_id, role, title, status, created_at)
     VALUES (?, ?, ?, ?, ?, 'Active', ?)`
  ).run(memId, userRow.id, authResult.auth.orgId, parsed.data.role, parsed.data.title.trim(), now);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'TEAM_MEMBER_INVITED',
    resourceType: 'Membership',
    resourceId: memId,
    details: `Invited ${normalizedEmail} with role ${parsed.data.role}.`,
  });

  return jsonOk({ members: fetchTeamMembers(authResult.auth.orgId) }, 201);
}

export async function PATCH(req: NextRequest) {
  const authResult = requireAuth(req, 'Admin');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = UpdateMemberSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid member update payload.', 400, 'VALIDATION_ERROR');
  }

  const db = getDb();
  const existing = db
    .prepare('SELECT id, user_id, role, status FROM memberships WHERE id = ? AND org_id = ?')
    .get(parsed.data.membershipId, authResult.auth.orgId) as
    | { id: string; user_id: string; role: string; status: string }
    | undefined;

  if (!existing) return jsonError('Membership not found.', 404, 'NOT_FOUND');

  if (parsed.data.role === 'Owner' && authResult.auth.role !== 'Owner') {
    return jsonError('Only an Owner can grant Owner role.', 403, 'FORBIDDEN_ROLE_ESCALATION');
  }

  if ((parsed.data.userStatus === 'Disabled' || parsed.data.status === 'Suspended') && existing.user_id === authResult.auth.userId) {
    return jsonError('You cannot suspend or disable your own active account.', 400, 'SELF_LOCKOUT_PREVENTED');
  }

  if (existing.role === 'Owner' && authResult.auth.role !== 'Owner') {
    return jsonError('Only an Owner can modify an Owner membership.', 403, 'FORBIDDEN');
  }

  db.prepare('UPDATE memberships SET role = ?, status = ? WHERE id = ? AND org_id = ?').run(
    parsed.data.role ?? existing.role,
    parsed.data.status ?? existing.status,
    parsed.data.membershipId,
    authResult.auth.orgId
  );

  if (parsed.data.userStatus) {
    db.prepare('UPDATE users SET status = ? WHERE id = ?').run(parsed.data.userStatus, existing.user_id);
  }

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'TEAM_MEMBER_UPDATED',
    resourceType: 'Membership',
    resourceId: parsed.data.membershipId,
    details: `Updated membership (role=${parsed.data.role ?? existing.role}, status=${parsed.data.status ?? existing.status}${parsed.data.userStatus ? `, userStatus=${parsed.data.userStatus}` : ''}).`,
  });

  return jsonOk({ members: fetchTeamMembers(authResult.auth.orgId) });
}

