import { NextRequest } from 'next/server';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { verifyIntentLock } from '@/lib/engines/intent-lock';
import { evaluatePolicies, type PolicyRule } from '@/lib/engines/policy-engine';
import { listChangeContractsFormatted } from '@/lib/domain-mappers';

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const row = db
    .prepare(
      `SELECT id, title, target_asset, previous_state_hash, new_state_payload, approved_hash, purpose, intent_lock_status
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
      }
    | undefined;

  if (!row) return jsonError('Change contract not found.', 404, 'NOT_FOUND');

  let parsedPayload: unknown = {};
  try {
    parsedPayload = JSON.parse(row.new_state_payload);
  } catch {
    parsedPayload = row.new_state_payload;
  }

  const verification = verifyIntentLock(
    row.approved_hash,
    {
      targetAsset: row.target_asset,
      previousStateHash: row.previous_state_hash,
      newStatePayload: parsedPayload,
      purpose: row.purpose,
    },
    row.intent_lock_status
  );

  if (!verification.isValid || verification.status !== 'Approved') {
    if (verification.status === 'Modified_Revalidation_Required') {
      db.prepare(
        `UPDATE change_contracts SET intent_lock_status = 'Modified_Revalidation_Required', approved_by = NULL WHERE id = ? AND org_id = ?`
      ).run(id, authResult.auth.orgId);
    }
    return jsonError(
      `Execution blocked by IntentLock: ${verification.reason}`,
      409,
      'INTENT_LOCK_BLOCKED',
      { verification }
    );
  }

  const policyRows = db
    .prepare('SELECT id, name, engine, severity, status, rule_code as ruleCode FROM policies WHERE org_id = ?')
    .all(authResult.auth.orgId) as unknown as PolicyRule[];

  const orgRow = db
    .prepare('SELECT enforcement_mode FROM organizations WHERE id = ?')
    .get(authResult.auth.orgId) as { enforcement_mode?: 'Observe' | 'Recommend' | 'Enforce' } | undefined;
  const enforcementMode = orgRow?.enforcement_mode || 'Enforce';

  const payloadText = JSON.stringify(parsedPayload);
  const policyDecision = evaluatePolicies(
    policyRows,
    {
      type: 'change_contract',
      intentLockValid: verification.isValid,
      hasPublicS3: /public-read(?:-write)?/i.test(payloadText),
      hasOpenAdminPort: payloadText.includes('0.0.0.0/0') && (payloadText.includes('"22"') || payloadText.includes(':22') || payloadText.includes('port":22')),
      hasHumanApproval: true,
      requiresHumanApproval: true,
    },
    enforcementMode
  );

  if (!policyDecision.allowed) {
    return jsonError(
      policyDecision.decision === 'REQUIRE_APPROVAL'
        ? 'Change flagged by Trustrail Policy Engine (Recommend mode — additional review required).'
        : 'Execution denied by Trustrail Policy Engine.',
      403,
      'POLICY_DENIED',
      { policyDecision }
    );
  }

  db.prepare(
    `UPDATE change_contracts SET intent_lock_status = 'Executed' WHERE id = ? AND org_id = ?`
  ).run(id, authResult.auth.orgId);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'CHANGE_CONTRACT_EXECUTED',
    resourceType: 'ChangeContract',
    resourceId: id,
    details: `Executed verified change "${row.title}" under IntentLock hash ${verification.currentHash}.`,
  });

  const changes = listChangeContractsFormatted(db, authResult.auth.orgId);
  return jsonOk({
    executed: true,
    verification,
    policyDecision,
    change: changes.find((c) => c.id === id),
    changes,
  });
}
