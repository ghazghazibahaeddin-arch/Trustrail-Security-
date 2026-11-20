import { NextRequest } from 'next/server';
import { getDb } from '@/lib/db';
import { sha256 } from '@/lib/security/crypto';
import { jsonOk, requireAuth } from '@/lib/api-response';

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const limitParam = Number(req.nextUrl.searchParams.get('limit') || '100');
  const limit = Number.isFinite(limitParam) ? Math.min(500, Math.max(1, limitParam)) : 100;

  const db = getDb();
  const chronological = db
    .prepare(
      `SELECT id, org_id, actor_email, action, resource_type, resource_id, details, prev_hash, entry_hash, created_at
       FROM audit_logs WHERE org_id = ? ORDER BY id ASC`
    )
    .all(authResult.auth.orgId) as Array<{
    id: number;
    org_id: string;
    actor_email: string;
    action: string;
    resource_type: string;
    resource_id: string;
    details: string;
    prev_hash: string;
    entry_hash: string;
    created_at: string;
  }>;

  // Verify cryptographic hash chain integrity across the tenant's ledger
  let chainValid = true;
  let expectedPrev = 'GENESIS';
  for (const row of chronological) {
    if (row.prev_hash !== expectedPrev) {
      chainValid = false;
      break;
    }
    const recomputed = sha256(
      `${row.prev_hash}|${row.org_id}|${row.actor_email}|${row.action}|${row.resource_type}|${row.resource_id}|${row.details}|${row.created_at}`
    );
    if (recomputed !== row.entry_hash) {
      chainValid = false;
      break;
    }
    expectedPrev = row.entry_hash;
  }

  const logs = chronological
    .slice(-limit)
    .reverse()
    .map((r) => ({
      id: r.id,
      orgId: r.org_id,
      actorEmail: r.actor_email,
      action: r.action,
      resourceType: r.resource_type,
      resourceId: r.resource_id,
      details: r.details,
      prevHash: r.prev_hash,
      entryHash: r.entry_hash,
      createdAt: r.created_at,
    }));

  return jsonOk({
    chainVerified: chainValid,
    totalEntries: chronological.length,
    logs,
  });
}
