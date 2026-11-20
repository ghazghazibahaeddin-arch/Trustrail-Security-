import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';

const CreatePolicySchema = z.object({
  name: z.string().min(3).max(160),
  engine: z.enum(['OPA Rego', 'Cloud Guard', 'IntentLock', 'SCA Guard', 'Agent Guard']),
  severity: z.enum(['Critical', 'High', 'Medium']),
  status: z.enum(['Enforced', 'Audit_Only', 'Disabled']).default('Enforced'),
  ruleCode: z.enum([
    'REQUIRE_COSIGN_SIGNATURE',
    'BLOCK_PUBLIC_S3_ACL',
    'BLOCK_OPEN_ADMIN_PORTS',
    'INTENT_LOCK_APPROVAL',
    'BLOCK_HIGH_CVSS',
    'AGENT_LEAST_PRIVILEGE',
  ]),
});

const TogglePolicySchema = z.object({
  id: z.string().min(1),
  status: z.enum(['Enforced', 'Audit_Only', 'Disabled']),
});

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const policies = db
    .prepare(
      `SELECT id, name, engine, severity, status, rule_code as ruleCode, created_at as createdAt
       FROM policies WHERE org_id = ? ORDER BY created_at DESC`
    )
    .all(authResult.auth.orgId);

  return jsonOk({ policies });
}

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Admin');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = CreatePolicySchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid policy payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const id = `pol-${crypto.randomUUID().slice(0, 8)}`;
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO policies (id, org_id, name, engine, severity, status, rule_code, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    authResult.auth.orgId,
    parsed.data.name.trim(),
    parsed.data.engine,
    parsed.data.severity,
    parsed.data.status,
    parsed.data.ruleCode,
    now
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'POLICY_CREATED',
    resourceType: 'Policy',
    resourceId: id,
    details: `Created policy "${parsed.data.name}" (${parsed.data.ruleCode}, status=${parsed.data.status}).`,
  });

  const policies = db
    .prepare(
      `SELECT id, name, engine, severity, status, rule_code as ruleCode, created_at as createdAt
       FROM policies WHERE org_id = ? ORDER BY created_at DESC`
    )
    .all(authResult.auth.orgId) as Array<{ id: string } & Record<string, unknown>>;

  return jsonOk({ policy: policies.find((p) => p.id === id), policies }, 201);
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

  const parsed = TogglePolicySchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid policy update payload.', 400, 'VALIDATION_ERROR');
  }

  const db = getDb();
  const existing = db
    .prepare('SELECT id, name FROM policies WHERE id = ? AND org_id = ?')
    .get(parsed.data.id, authResult.auth.orgId) as { id: string; name: string } | undefined;

  if (!existing) return jsonError('Policy not found.', 404, 'NOT_FOUND');

  db.prepare('UPDATE policies SET status = ? WHERE id = ? AND org_id = ?').run(
    parsed.data.status,
    parsed.data.id,
    authResult.auth.orgId
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'POLICY_UPDATED',
    resourceType: 'Policy',
    resourceId: parsed.data.id,
    details: `Policy "${existing.name}" status changed to ${parsed.data.status}.`,
  });

  const policies = db
    .prepare(
      `SELECT id, name, engine, severity, status, rule_code as ruleCode, created_at as createdAt
       FROM policies WHERE org_id = ? ORDER BY created_at DESC`
    )
    .all(authResult.auth.orgId);

  return jsonOk({ policies });
}
