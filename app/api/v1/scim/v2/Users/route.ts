import crypto from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { sha256, hashPassword } from '@/lib/security/crypto';
import { publishEvent } from '@/lib/fabric/event-bus';

const ScimCreateUserSchema = z.object({
  schemas: z.array(z.string()).optional(),
  userName: z.string().email(),
  displayName: z.string().min(1).max(160).optional(),
  name: z
    .object({
      givenName: z.string().optional(),
      familyName: z.string().optional(),
    })
    .optional(),
  active: z.boolean().default(true),
  groups: z.array(z.string()).optional(),
});

function authenticateScim(req: NextRequest): { tokenId: string; orgId: string; name: string } | null {
  const authHeader = req.headers.get('authorization');
  if (!authHeader?.startsWith('Bearer tr_scim_')) return null;
  const raw = authHeader.slice(7).trim();
  if (!raw) return null;

  const db = getDb();
  const row = db
    .prepare(
      `SELECT id as tokenId, org_id as orgId, name FROM scim_tokens WHERE token_hash = ? AND revoked = 0`
    )
    .get(sha256(raw)) as { tokenId: string; orgId: string; name: string } | undefined;

  if (row) {
    db.prepare(`UPDATE scim_tokens SET last_used_at = ? WHERE id = ?`).run(new Date().toISOString(), row.tokenId);
  }
  return row || null;
}

function scimError(detail: string, status: number) {
  return NextResponse.json(
    {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:Error'],
      detail,
      status: String(status),
    },
    { status, headers: { 'Content-Type': 'application/scim+json' } }
  );
}

export async function GET(req: NextRequest) {
  const scim = authenticateScim(req);
  if (!scim) {
    return scimError('Invalid or missing SCIM 2.0 Bearer token.', 401);
  }

  const db = getDb();
  const rows = db
    .prepare(
      `SELECT u.id, u.email, u.name, u.status, m.role, u.created_at as createdAt
       FROM memberships m
       JOIN users u ON u.id = m.user_id
       WHERE m.org_id = ?
       ORDER BY u.created_at DESC`
    )
    .all(scim.orgId) as Array<{
    id: string;
    email: string;
    name: string;
    status: string;
    role: string;
    createdAt: string;
  }>;

  return NextResponse.json(
    {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:ListResponse'],
      totalResults: rows.length,
      startIndex: 1,
      itemsPerPage: rows.length,
      Resources: rows.map((u) => ({
        schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
        id: u.id,
        userName: u.email,
        displayName: u.name,
        active: u.status === 'Active',
        roles: [{ value: u.role }],
        meta: { resourceType: 'User', created: u.createdAt },
      })),
    },
    { headers: { 'Content-Type': 'application/scim+json' } }
  );
}

export async function POST(req: NextRequest) {
  const scim = authenticateScim(req);
  if (!scim) {
    return scimError('Invalid or missing SCIM 2.0 Bearer token.', 401);
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return scimError('Invalid JSON payload.', 400);
  }

  const parsed = ScimCreateUserSchema.safeParse(body);
  if (!parsed.success) {
    return scimError('Invalid SCIM 2.0 User resource payload.', 400);
  }

  const db = getDb();
  const email = parsed.data.userName.toLowerCase().trim();
  const displayName =
    parsed.data.displayName?.trim() ||
    [parsed.data.name?.givenName, parsed.data.name?.familyName].filter(Boolean).join(' ').trim() ||
    email.split('@')[0];

  const ssoCfg = db
    .prepare(`SELECT role_mapping_json FROM sso_configs WHERE org_id = ?`)
    .get(scim.orgId) as { role_mapping_json?: string } | undefined;
  let roleMap: Record<string, string> = {};
  try {
    roleMap = JSON.parse(ssoCfg?.role_mapping_json || '{}') as Record<string, string>;
  } catch {
    roleMap = {};
  }

  let mappedRole: 'Owner' | 'Admin' | 'Developer' | 'Viewer' = 'Developer';
  for (const grp of parsed.data.groups || []) {
    const candidate = roleMap[grp] || roleMap[grp.toLowerCase()];
    if (candidate === 'Owner' || candidate === 'Admin' || candidate === 'Developer' || candidate === 'Viewer') {
      mappedRole = candidate;
      break;
    }
  }

  const now = new Date().toISOString();
  const nextStatus = parsed.data.active ? 'Active' : 'Disabled';

  let userRow = db
    .prepare(`SELECT id, email, name FROM users WHERE email = ?`)
    .get(email) as { id: string; email: string; name: string } | undefined;

  if (!userRow) {
    const userId = `user-${crypto.randomUUID().slice(0, 8)}`;
    const tempPassHash = hashPassword(crypto.randomBytes(24).toString('hex'));
    db.prepare(
      `INSERT INTO users (id, email, name, password_hash, mfa_verified, email_verified, status, created_at)
       VALUES (?, ?, ?, ?, 0, 1, ?, ?)`
    ).run(userId, email, displayName, tempPassHash, nextStatus, now);
    userRow = { id: userId, email, name: displayName };
  } else {
    db.prepare(`UPDATE users SET name = ?, status = ? WHERE id = ?`).run(displayName, nextStatus, userRow.id);
  }

  const existingMember = db
    .prepare(`SELECT id, role FROM memberships WHERE user_id = ? AND org_id = ?`)
    .get(userRow.id, scim.orgId) as { id: string; role: string } | undefined;

  if (!existingMember) {
    db.prepare(`INSERT INTO memberships (id, user_id, org_id, role, created_at) VALUES (?, ?, ?, ?, ?)`).run(
      `mem-${crypto.randomUUID().slice(0, 8)}`,
      userRow.id,
      scim.orgId,
      mappedRole,
      now
    );
  } else {
    db.prepare(`UPDATE memberships SET role = ? WHERE id = ?`).run(mappedRole, existingMember.id);
  }

  publishEvent(db, {
    orgId: scim.orgId,
    eventType: 'iam.permission_change_detected',
    actorId: `scim:${scim.tokenId}`,
    sourceConnector: 'sso_oidc',
    sourceResourceId: userRow.id,
    payload: {
      email,
      role: mappedRole,
      active: parsed.data.active,
      groups: parsed.data.groups || [],
      provisionedBy: scim.name,
    },
  });

  appendAuditLog(db, {
    orgId: scim.orgId,
    actorEmail: `scim:${scim.name}`,
    action: 'SCIM_USER_PROVISIONED',
    resourceType: 'User',
    resourceId: userRow.id,
    details: `SCIM 2.0 provisioned ${email} with role=${mappedRole}, active=${parsed.data.active}.`,
  });

  return NextResponse.json(
    {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      id: userRow.id,
      userName: email,
      displayName,
      active: parsed.data.active,
      roles: [{ value: mappedRole }],
      meta: { resourceType: 'User', created: now },
    },
    { status: 201, headers: { 'Content-Type': 'application/scim+json' } }
  );
}
