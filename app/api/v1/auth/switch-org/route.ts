import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { signToken } from '@/lib/security/crypto';
import { SESSION_COOKIE_NAME } from '@/lib/security/auth';
import { jsonError, requireAuth } from '@/lib/api-response';
import { computeOrganizationSnapshot } from '@/lib/domain-mappers';

const SwitchSchema = z.object({
  orgId: z.string().min(1),
});

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = SwitchSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('orgId is required.', 400, 'VALIDATION_ERROR');
  }

  const db = getDb();
  const membership = db
    .prepare(
      `SELECT m.org_id as orgId, m.role, o.name as orgName
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.org_id = ? AND m.status = 'Active'`
    )
    .get(authResult.auth.userId, parsed.data.orgId) as
    | { orgId: string; role: 'Owner' | 'Admin' | 'Developer' | 'Viewer'; orgName: string }
    | undefined;

  if (!membership) {
    return jsonError('You do not belong to the requested organization.', 403, 'FORBIDDEN_ORG');
  }

  const token = signToken({
    userId: authResult.auth.userId,
    orgId: membership.orgId,
    role: membership.role,
    email: authResult.auth.email,
  });

  appendAuditLog(db, {
    orgId: membership.orgId,
    actorEmail: authResult.auth.email,
    action: 'SWITCH_ORGANIZATION',
    resourceType: 'Organization',
    resourceId: membership.orgId,
    details: `Switched active tenant context to ${membership.orgName}.`,
  });

  const organization = computeOrganizationSnapshot(db, membership.orgId);

  const response = NextResponse.json({
    authenticated: true,
    token,
    user: {
      id: authResult.auth.userId,
      email: authResult.auth.email,
      name: authResult.auth.name,
      role: membership.role,
      orgId: membership.orgId,
    },
    organization,
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
