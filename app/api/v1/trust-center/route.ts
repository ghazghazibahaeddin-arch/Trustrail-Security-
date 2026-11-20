import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { sha256 } from '@/lib/security/crypto';

const CreateReceiptSchema = z.object({
  title: z.string().min(3).max(160),
  scope: z.array(z.string().min(2)).min(1),
  expiresDays: z.number().int().min(1).max(365).default(180),
});

function formatReceipt(r: {
  id: string;
  title: string;
  issued_at: string;
  expires_at: string;
  scope_json: string;
  signature: string;
  revoked: number;
  access_count: number;
}) {
  return {
    id: r.id,
    title: r.title,
    issuedAt: r.issued_at,
    expiresAt: r.expires_at,
    scope: JSON.parse(r.scope_json || '[]') as string[],
    signature: r.signature,
    revoked: Boolean(r.revoked),
    accessCount: r.access_count,
  };
}

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const rows = db
    .prepare(
      `SELECT id, title, issued_at, expires_at, scope_json, signature, revoked, access_count
       FROM trust_receipts WHERE org_id = ? ORDER BY issued_at DESC`
    )
    .all(authResult.auth.orgId) as Array<{
    id: string;
    title: string;
    issued_at: string;
    expires_at: string;
    scope_json: string;
    signature: string;
    revoked: number;
    access_count: number;
  }>;

  return jsonOk({ trustReceipts: rows.map(formatReceipt) });
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

  const parsed = CreateReceiptSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid Trust Passport payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const id = `tr-${crypto.randomUUID().slice(0, 8)}`;
  const issuedAt = new Date().toISOString().slice(0, 10);
  const expiresAt = new Date(Date.now() + parsed.data.expiresDays * 86_400_000).toISOString().slice(0, 10);
  const signature = `sig_sha256_${sha256(`${id}|${authResult.auth.orgId}|${issuedAt}|${parsed.data.scope.join(',')}`).slice(0, 24)}`;

  db.prepare(
    `INSERT INTO trust_receipts (id, org_id, title, issued_at, expires_at, scope_json, signature, revoked, access_count)
     VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)`
  ).run(id, authResult.auth.orgId, parsed.data.title.trim(), issuedAt, expiresAt, JSON.stringify(parsed.data.scope), signature);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'TRUST_PASSPORT_ISSUED',
    resourceType: 'TrustReceipt',
    resourceId: id,
    details: `Issued signed Trust Passport "${parsed.data.title}" expiring ${expiresAt}.`,
  });

  const rows = db
    .prepare(
      `SELECT id, title, issued_at, expires_at, scope_json, signature, revoked, access_count
       FROM trust_receipts WHERE org_id = ? ORDER BY issued_at DESC`
    )
    .all(authResult.auth.orgId) as Array<{
    id: string;
    title: string;
    issued_at: string;
    expires_at: string;
    scope_json: string;
    signature: string;
    revoked: number;
    access_count: number;
  }>;

  const trustReceipts = rows.map(formatReceipt);
  return jsonOk({ trustReceipt: trustReceipts.find((t) => t.id === id), trustReceipts }, 201);
}
