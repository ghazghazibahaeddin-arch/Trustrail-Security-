import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { computeChangeStateHash } from '@/lib/engines/intent-lock';
import { listChangeContractsFormatted } from '@/lib/domain-mappers';

const ApproveSchema = z.object({
  action: z.enum(['approve', 'reject', 'revoke']).default('approve'),
  reason: z.string().max(400).optional(),
});

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Admin');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const row = db
    .prepare(
      `SELECT id, title, target_asset, previous_state_hash, new_state_payload, purpose
       FROM change_contracts WHERE id = ? AND org_id = ?`
    )
    .get(id, authResult.auth.orgId) as
    | {
        id: string;
        title: string;
        target_asset: string;
        previous_state_hash: string;
        new_state_payload: string;
        purpose: string;
      }
    | undefined;

  if (!row) return jsonError('Change contract not found.', 404, 'NOT_FOUND');

  let body: unknown = {};
  try {
    body = await req.json();
  } catch {
    body = {};
  }

  const parsed = ApproveSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid approval payload.', 400, 'VALIDATION_ERROR');
  }

  let parsedPayload: unknown = {};
  try {
    parsedPayload = JSON.parse(row.new_state_payload);
  } catch {
    parsedPayload = row.new_state_payload;
  }

  const currentHash = computeChangeStateHash({
    targetAsset: row.target_asset,
    previousStateHash: row.previous_state_hash,
    newStatePayload: parsedPayload,
    purpose: row.purpose,
  });

  if (parsed.data.action === 'approve') {
    db.prepare(
      `UPDATE change_contracts
       SET approved_hash = ?, new_state_hash = ?, intent_lock_status = 'Approved', approved_by = ?
       WHERE id = ? AND org_id = ?`
    ).run(currentHash, currentHash, `${authResult.auth.name} (${authResult.auth.email})`, id, authResult.auth.orgId);

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'INTENT_LOCK_APPROVED',
      resourceType: 'ChangeContract',
      resourceId: id,
      details: `Bound approval for "${row.title}" to hash ${currentHash}.`,
    });
  } else if (parsed.data.action === 'revoke') {
    db.prepare(
      `UPDATE change_contracts
       SET intent_lock_status = 'Modified_Revalidation_Required', approved_by = NULL, approved_hash = NULL
       WHERE id = ? AND org_id = ?`
    ).run(id, authResult.auth.orgId);

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'INTENT_LOCK_REVOKED',
      resourceType: 'ChangeContract',
      resourceId: id,
      details: `Revoked approval for "${row.title}". ${parsed.data.reason || ''}`.trim(),
    });
  } else {
    db.prepare(
      `UPDATE change_contracts
       SET intent_lock_status = 'Rejected', approved_by = NULL, approved_hash = NULL
       WHERE id = ? AND org_id = ?`
    ).run(id, authResult.auth.orgId);

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'INTENT_LOCK_REJECTED',
      resourceType: 'ChangeContract',
      resourceId: id,
      details: `Rejected "${row.title}". ${parsed.data.reason || ''}`.trim(),
    });
  }

  const changes = listChangeContractsFormatted(db, authResult.auth.orgId);
  return jsonOk({ change: changes.find((c) => c.id === id), changes });
}
