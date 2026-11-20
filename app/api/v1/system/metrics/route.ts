import { NextRequest } from 'next/server';
import { getDb, verifyAuditChain } from '@/lib/db';
import { getActiveVaultKeyVersion } from '@/lib/security/vault';
import { jsonOk, requireAuth } from '@/lib/api-response';

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer', 'read');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const orgId = authResult.auth.orgId;

  const findingsSummary = db
    .prepare(
      `SELECT severity, status, COUNT(*) as count
       FROM findings WHERE org_id = ? GROUP BY severity, status`
    )
    .all(orgId) as Array<{ severity: string; status: string; count: number }>;

  const remediationSummary = db
    .prepare(
      `SELECT status, COUNT(*) as count
       FROM remediation_runs WHERE org_id = ? GROUP BY status`
    )
    .all(orgId) as Array<{ status: string; count: number }>;

  const jobsSummary = db
    .prepare(
      `SELECT status, COUNT(*) as count
       FROM background_jobs WHERE org_id = ? GROUP BY status`
    )
    .all(orgId) as Array<{ status: string; count: number }>;

  const recentNotifications = db
    .prepare(
      `SELECT id, org_id as orgId, channel, event_type as eventType, status, http_status as httpStatus, summary, created_at as createdAt
       FROM notification_deliveries WHERE org_id = ? ORDER BY created_at DESC LIMIT 20`
    )
    .all(orgId);

  const orgRow = db
    .prepare('SELECT enforcement_mode FROM organizations WHERE id = ?')
    .get(orgId) as { enforcement_mode?: string } | undefined;

  const auditChain = verifyAuditChain(db, orgId);

  return jsonOk({
    generatedAt: new Date().toISOString(),
    vaultKeyVersion: getActiveVaultKeyVersion(),
    enforcementMode: orgRow?.enforcement_mode || 'Enforce',
    auditChain,
    findingsSummary,
    remediationSummary,
    jobsSummary,
    recentNotifications,
  });
}
