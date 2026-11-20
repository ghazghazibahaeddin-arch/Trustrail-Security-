import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { computeChangeStateHash, verifyIntentLock } from '@/lib/engines/intent-lock';
import { listChangeContractsFormatted } from '@/lib/domain-mappers';

const PatchChangeSchema = z.object({
  newStatePayload: z.record(z.string(), z.unknown()).optional(),
  purpose: z.string().min(5).max(500).optional(),
  evidenceSummary: z.string().max(500).optional(),
});

export async function GET(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const change = listChangeContractsFormatted(db, authResult.auth.orgId).find((c) => c.id === id);
  if (!change) return jsonError('Change contract not found.', 404, 'NOT_FOUND');

  return jsonOk({ change });
}

export async function PATCH(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const row = db
    .prepare(
      `SELECT id, title, target_asset, previous_state_hash, new_state_payload, approved_hash, purpose, intent_lock_status, evidence_summary
       FROM change_contracts WHERE id = ? AND org_id = ?`
    )
    .get(id, authResult.auth.orgId) as
    | {
        id: string;
        title: string;
        target_asset: string;
        previous_state_hash: string;
        new_state_payload: string;
        approved_hash: string | null;
        purpose: string;
        intent_lock_status: string;
        evidence_summary: string;
      }
    | undefined;

  if (!row) return jsonError('Change contract not found.', 404, 'NOT_FOUND');

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = PatchChangeSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid change update payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  let currentPayload: unknown = {};
  try {
    currentPayload = JSON.parse(row.new_state_payload);
  } catch {
    currentPayload = row.new_state_payload;
  }

  const nextPayload = parsed.data.newStatePayload ?? currentPayload;
  const nextPurpose = parsed.data.purpose?.trim() ?? row.purpose;

  const nextHash = computeChangeStateHash({
    targetAsset: row.target_asset,
    previousStateHash: row.previous_state_hash,
    newStatePayload: nextPayload,
    purpose: nextPurpose,
  });

  const verification = verifyIntentLock(
    row.approved_hash,
    {
      targetAsset: row.target_asset,
      previousStateHash: row.previous_state_hash,
      newStatePayload: nextPayload,
      purpose: nextPurpose,
    },
    row.intent_lock_status
  );

  // If payload mutated after approval, IntentLock automatically revokes approval!
  const nextStatus = verification.status;
  const nextApprovedBy = nextStatus === 'Modified_Revalidation_Required' ? null : undefined;

  if (nextStatus === 'Modified_Revalidation_Required') {
    db.prepare(
      `UPDATE change_contracts
       SET new_state_payload = ?, new_state_hash = ?, purpose = ?, intent_lock_status = ?, approved_by = NULL, evidence_summary = ?
       WHERE id = ? AND org_id = ?`
    ).run(
      JSON.stringify(nextPayload),
      nextHash,
      nextPurpose,
      nextStatus,
      parsed.data.evidenceSummary?.trim() || verification.reason,
      id,
      authResult.auth.orgId
    );
  } else {
    db.prepare(
      `UPDATE change_contracts
       SET new_state_payload = ?, new_state_hash = ?, purpose = ?, intent_lock_status = ?, evidence_summary = ?
       WHERE id = ? AND org_id = ?`
    ).run(
      JSON.stringify(nextPayload),
      nextHash,
      nextPurpose,
      nextStatus,
      parsed.data.evidenceSummary?.trim() || row.evidence_summary,
      id,
      authResult.auth.orgId
    );
  }

  void nextApprovedBy;

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: nextStatus === 'Modified_Revalidation_Required' ? 'INTENT_LOCK_TAMPER_REVOKED' : 'CHANGE_CONTRACT_UPDATED',
    resourceType: 'ChangeContract',
    resourceId: id,
    details: `${row.title}: ${verification.reason} (newHash=${nextHash})`,
  });

  const changes = listChangeContractsFormatted(db, authResult.auth.orgId);
  return jsonOk({
    change: changes.find((c) => c.id === id),
    changes,
    verification,
  });
}
