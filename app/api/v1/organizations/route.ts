import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, withDbTransaction, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { computeOrganizationSnapshot } from '@/lib/domain-mappers';
import { provisionNewOrgDefaults } from '@/lib/org-provisioning';

const UpdateOrgSchema = z.object({
  name: z.string().min(2).max(120).optional(),
  edition: z.enum(['developer', 'smb', 'enterprise']).optional(),
  dataRetentionDays: z.number().int().min(30).max(3650).optional(),
  threatSharingOptIn: z.boolean().optional(),
  enforcementMode: z.enum(['Observe', 'Recommend', 'Enforce']).optional(),
});

const CreateOrgSchema = z.object({
  name: z.string().min(2).max(120),
  edition: z.enum(['developer', 'smb', 'enterprise']).default('smb'),
});

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const org = computeOrganizationSnapshot(db, authResult.auth.orgId);
  if (!org) return jsonError('Organization not found.', 404, 'NOT_FOUND');

  return jsonOk({ organization: org });
}

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = CreateOrgSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid organization payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const orgId = `org-${crypto.randomUUID().slice(0, 8)}`;
  const memId = `mem-${crypto.randomUUID().slice(0, 8)}`;
  const now = new Date().toISOString();
  const slugBase =
    parsed.data.name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-|-$/g, '') || 'org';
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
    ).run(orgId, parsed.data.name.trim(), slug, parsed.data.edition, tierName, now);

    db.prepare(
      `INSERT INTO memberships (id, user_id, org_id, role, title, status, created_at)
       VALUES (?, ?, ?, 'Owner', 'Workspace Owner', 'Active', ?)`
    ).run(memId, authResult.auth.userId, orgId, now);

    provisionNewOrgDefaults(db, orgId, authResult.auth.email);
  });

  const organization = computeOrganizationSnapshot(db, orgId);
  return jsonOk({ organization }, 201);
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

  const parsed = UpdateOrgSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid organization update payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const current = db
    .prepare(
      'SELECT name, edition, tier_name, data_retention_days, threat_sharing_opt_in, enforcement_mode FROM organizations WHERE id = ?'
    )
    .get(authResult.auth.orgId) as
    | {
        name: string;
        edition: string;
        tier_name: string;
        data_retention_days: number;
        threat_sharing_opt_in: number;
        enforcement_mode?: string;
      }
    | undefined;

  if (!current) return jsonError('Organization not found.', 404, 'NOT_FOUND');

  const nextEdition = parsed.data.edition || current.edition;
  const nextTier =
    nextEdition === 'enterprise'
      ? 'Enterprise Security Grid'
      : nextEdition === 'smb'
      ? 'Teams & SMB Edition'
      : 'Developer Free Edition';
  const nextEnforcement = parsed.data.enforcementMode || current.enforcement_mode || 'Enforce';

  db.prepare(
    `UPDATE organizations
     SET name = ?, edition = ?, tier_name = ?, data_retention_days = ?, threat_sharing_opt_in = ?, enforcement_mode = ?
     WHERE id = ?`
  ).run(
    parsed.data.name?.trim() || current.name,
    nextEdition,
    nextTier,
    parsed.data.dataRetentionDays ?? current.data_retention_days,
    parsed.data.threatSharingOptIn !== undefined
      ? parsed.data.threatSharingOptIn
        ? 1
        : 0
      : current.threat_sharing_opt_in,
    nextEnforcement,
    authResult.auth.orgId
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'ORGANIZATION_UPDATED',
    resourceType: 'Organization',
    resourceId: authResult.auth.orgId,
    details: `Updated org settings (edition=${nextEdition}, mode=${nextEnforcement}, retention=${parsed.data.dataRetentionDays ?? current.data_retention_days}d).`,
  });

  const organization = computeOrganizationSnapshot(db, authResult.auth.orgId);
  return jsonOk({ organization });
}

