import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { computeOrganizationSnapshot, listEnrichedFindings, listProjectsWithStats } from '@/lib/domain-mappers';

const UpdateFindingSchema = z.object({
  status: z.enum(['Open', 'In_Remediation', 'Under_Review', 'Resolved', 'False_Positive']),
  resolutionEvidence: z.string().max(1000).optional(),
  assignedOwner: z.string().max(100).optional(),
});

export async function GET(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const finding = listEnrichedFindings(db, authResult.auth.orgId).find((f) => f.id === id);

  if (!finding) {
    return jsonError('Finding not found.', 404, 'NOT_FOUND');
  }
  return jsonOk({ finding });
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
    .prepare('SELECT id, title, status, assigned_owner FROM findings WHERE id = ? AND org_id = ?')
    .get(id, authResult.auth.orgId) as
    | { id: string; title: string; status: string; assigned_owner: string }
    | undefined;

  if (!existing) {
    return jsonError('Finding not found.', 404, 'NOT_FOUND');
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = UpdateFindingSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid finding update payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const isClosing = parsed.data.status === 'Resolved' || parsed.data.status === 'False_Positive';
  const evidenceText =
    parsed.data.resolutionEvidence?.trim() ||
    (isClosing ? `Verified closed by ${authResult.auth.email}` : null);

  const verifiedAt = isClosing ? new Date().toISOString() : null;

  db.prepare(
    `UPDATE findings SET status = ?, resolution_evidence = COALESCE(?, resolution_evidence), assigned_owner = ?, verified_at = ?
     WHERE id = ? AND org_id = ?`
  ).run(
    parsed.data.status,
    evidenceText,
    parsed.data.assignedOwner?.trim() || existing.assigned_owner,
    verifiedAt,
    id,
    authResult.auth.orgId
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: `FINDING_${parsed.data.status.toUpperCase()}`,
    resourceType: 'Finding',
    resourceId: id,
    details: `${existing.title} -> ${parsed.data.status}${evidenceText ? ` (${evidenceText})` : ''}`,
  });

  const findings = listEnrichedFindings(db, authResult.auth.orgId);
  return jsonOk({
    finding: findings.find((f) => f.id === id),
    findings,
    projects: listProjectsWithStats(db, authResult.auth.orgId),
    organization: computeOrganizationSnapshot(db, authResult.auth.orgId),
  });
}
