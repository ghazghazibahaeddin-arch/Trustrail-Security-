import { NextRequest } from 'next/server';
import { getDb } from '@/lib/db';
import { authenticateRequest } from '@/lib/security/auth';
import { computeOrganizationSnapshot } from '@/lib/domain-mappers';
import { jsonOk } from '@/lib/api-response';

export async function GET(req: NextRequest) {
  const auth = authenticateRequest(req);
  if (!auth) {
    return jsonOk({ authenticated: false, user: null, organization: null, memberships: [] });
  }

  const db = getDb();
  const org = computeOrganizationSnapshot(db, auth.orgId);

  const memberships = db
    .prepare(
      `SELECT m.org_id as orgId, o.name as orgName, o.slug, o.edition, m.role, m.title
       FROM memberships m
       JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.status = 'Active'
       ORDER BY o.name ASC`
    )
    .all(auth.userId);

  return jsonOk({
    authenticated: true,
    user: {
      id: auth.userId,
      email: auth.email,
      name: auth.name,
      role: auth.role,
      orgId: auth.orgId,
      emailVerified: Boolean(auth.emailVerified),
      mfaVerified: Boolean(auth.mfaVerified),
    },
    organization: org,
    memberships,
  });
}
