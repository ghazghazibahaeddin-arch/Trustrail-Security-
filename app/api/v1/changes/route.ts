import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { computeChangeStateHash } from '@/lib/engines/intent-lock';
import { sha256 } from '@/lib/security/crypto';
import { listChangeContractsFormatted } from '@/lib/domain-mappers';

const CreateChangeSchema = z.object({
  title: z.string().min(3).max(160),
  project: z.string().min(1).max(120),
  targetAsset: z.string().min(1).max(160),
  previousStateHash: z.string().optional(),
  newStatePayload: z.record(z.string(), z.unknown()),
  purpose: z.string().min(5).max(500),
  riskLevel: z.enum(['High', 'Medium', 'Low']).default('Medium'),
  evidenceSummary: z.string().max(500).optional(),
});

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const contracts = listChangeContractsFormatted(db, authResult.auth.orgId);
  return jsonOk({ changes: contracts });
}

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = CreateChangeSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid change contract payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const id = `change-${crypto.randomUUID().slice(0, 8)}`;
  const now = new Date().toISOString();
  const prevHash = parsed.data.previousStateHash || `sha256:${sha256(parsed.data.targetAsset + now)}`;
  const newHash = computeChangeStateHash({
    targetAsset: parsed.data.targetAsset,
    previousStateHash: prevHash,
    newStatePayload: parsed.data.newStatePayload,
    purpose: parsed.data.purpose,
  });

  db.prepare(
    `INSERT INTO change_contracts (id, org_id, title, actor, project, target_asset, previous_state_hash, new_state_payload, new_state_hash, approved_hash, purpose, risk_level, intent_lock_status, approved_by, evidence_summary, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?, 'Locked', NULL, ?, ?)`
  ).run(
    id,
    authResult.auth.orgId,
    parsed.data.title.trim(),
    authResult.auth.name,
    parsed.data.project.trim(),
    parsed.data.targetAsset.trim(),
    prevHash,
    JSON.stringify(parsed.data.newStatePayload),
    newHash,
    parsed.data.purpose.trim(),
    parsed.data.riskLevel,
    parsed.data.evidenceSummary?.trim() || 'IntentLock contract bound to canonical SHA-256 payload digest.',
    now
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'CHANGE_CONTRACT_CREATED',
    resourceType: 'ChangeContract',
    resourceId: id,
    details: `Created IntentLock contract "${parsed.data.title}" (${newHash}).`,
  });

  const changes = listChangeContractsFormatted(db, authResult.auth.orgId);
  return jsonOk({ change: changes.find((c) => c.id === id), changes }, 201);
}
