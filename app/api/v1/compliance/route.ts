import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { computeOrganizationSnapshot } from '@/lib/domain-mappers';

const UpdateControlSchema = z.object({
  id: z.string().min(1),
  status: z.enum(['Verified', 'Needs_Evidence', 'Non_Compliant']),
  evidenceCount: z.number().int().min(0).optional(),
});

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const controls = db
    .prepare(
      `SELECT id, framework, code, title, status, evidence_count as evidenceCount, last_verified as lastVerified, owner
       FROM compliance_controls WHERE org_id = ?`
    )
    .all(authResult.auth.orgId);

  return jsonOk({ controls });
}

export async function PATCH(req: NextRequest) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = UpdateControlSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid compliance control update.', 400, 'VALIDATION_ERROR');
  }

  const db = getDb();
  const existing = db
    .prepare('SELECT id, code, evidence_count FROM compliance_controls WHERE id = ? AND org_id = ?')
    .get(parsed.data.id, authResult.auth.orgId) as { id: string; code: string; evidence_count: number } | undefined;

  if (!existing) return jsonError('Compliance control not found.', 404, 'NOT_FOUND');

  const nextCount = parsed.data.evidenceCount ?? (parsed.data.status === 'Verified' ? existing.evidence_count + 1 : existing.evidence_count);
  const today = new Date().toISOString().slice(0, 10);

  db.prepare(
    `UPDATE compliance_controls SET status = ?, evidence_count = ?, last_verified = ? WHERE id = ? AND org_id = ?`
  ).run(parsed.data.status, nextCount, today, parsed.data.id, authResult.auth.orgId);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'COMPLIANCE_CONTROL_UPDATED',
    resourceType: 'ComplianceControl',
    resourceId: parsed.data.id,
    details: `Control ${existing.code} updated to ${parsed.data.status} (evidenceCount=${nextCount}).`,
  });

  const controls = db
    .prepare(
      `SELECT id, framework, code, title, status, evidence_count as evidenceCount, last_verified as lastVerified, owner
       FROM compliance_controls WHERE org_id = ?`
    )
    .all(authResult.auth.orgId);

  return jsonOk({
    controls,
    organization: computeOrganizationSnapshot(db, authResult.auth.orgId),
  });
}
