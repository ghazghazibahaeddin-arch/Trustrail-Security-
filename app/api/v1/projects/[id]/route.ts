import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { listProjectsWithStats } from '@/lib/domain-mappers';

const UpdateProjectSchema = z.object({
  branch: z.string().min(1).max(60).optional(),
  owner: z.string().min(1).max(100).optional(),
  slsaLevel: z.enum(['SLSA 1', 'SLSA 2', 'SLSA 3', 'None']).optional(),
  connectedAwsAccount: z.string().max(120).nullable().optional(),
});

export async function GET(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const projects = listProjectsWithStats(db, authResult.auth.orgId);
  const project = projects.find((p) => p.id === id);

  if (!project) {
    return jsonError('Project not found.', 404, 'NOT_FOUND');
  }
  return jsonOk({ project });
}

export async function PATCH(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const existing = db
    .prepare('SELECT id, branch, owner, slsa_level, connected_aws_account FROM projects WHERE id = ? AND org_id = ?')
    .get(id, authResult.auth.orgId) as
    | { id: string; branch: string; owner: string; slsa_level: string; connected_aws_account: string | null }
    | undefined;

  if (!existing) {
    return jsonError('Project not found.', 404, 'NOT_FOUND');
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = UpdateProjectSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid project update payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  db.prepare(
    `UPDATE projects SET branch = ?, owner = ?, slsa_level = ?, connected_aws_account = ? WHERE id = ? AND org_id = ?`
  ).run(
    parsed.data.branch ?? existing.branch,
    parsed.data.owner ?? existing.owner,
    parsed.data.slsaLevel ?? existing.slsa_level,
    parsed.data.connectedAwsAccount !== undefined ? parsed.data.connectedAwsAccount : existing.connected_aws_account,
    id,
    authResult.auth.orgId
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'PROJECT_UPDATED',
    resourceType: 'Project',
    resourceId: id,
    details: 'Updated project security metadata.',
  });

  const projects = listProjectsWithStats(db, authResult.auth.orgId);
  return jsonOk({ project: projects.find((p) => p.id === id) });
}

export async function DELETE(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Admin');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const existing = db
    .prepare('SELECT id, name FROM projects WHERE id = ? AND org_id = ?')
    .get(id, authResult.auth.orgId) as { id: string; name: string } | undefined;

  if (!existing) {
    return jsonError('Project not found.', 404, 'NOT_FOUND');
  }

  db.prepare('DELETE FROM projects WHERE id = ? AND org_id = ?').run(id, authResult.auth.orgId);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'PROJECT_DELETED',
    resourceType: 'Project',
    resourceId: id,
    details: `Deleted project ${existing.name}.`,
  });

  return jsonOk({ deleted: true, id });
}
