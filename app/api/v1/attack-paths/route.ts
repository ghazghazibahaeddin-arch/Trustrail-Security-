import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { synthesizeAttackPaths } from '@/lib/engines/attack-path-engine';
import { computeOrganizationSnapshot, listEnrichedFindings } from '@/lib/domain-mappers';

function computeTenantAttackPaths(orgId: string) {
  const db = getDb();
  const assets = db
    .prepare(
      `SELECT id, org_id as orgId, name, asset_type as assetType, owner, internet_exposed as internetExposed, criticality
       FROM assets WHERE org_id = ?`
    )
    .all(orgId) as Array<{
    id: string;
    orgId: string;
    name: string;
    assetType: string;
    owner: string;
    internetExposed: number;
    criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  }>;

  const edges = db
    .prepare(
      `SELECT id, org_id as orgId, source_asset_id as sourceAssetId, target_asset_id as targetAssetId, relation, evidence
       FROM graph_edges WHERE org_id = ?`
    )
    .all(orgId) as Array<{
    id: string;
    orgId: string;
    sourceAssetId: string;
    targetAssetId: string;
    relation: string;
    evidence: string;
  }>;

  const findings = db
    .prepare(
      `SELECT id, title, severity, category, asset_id as assetId, asset_name as assetName, status, cvss
       FROM findings WHERE org_id = ?`
    )
    .all(orgId) as Array<{
    id: string;
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    category: string;
    assetId: string | null;
    assetName: string;
    status: string;
    cvss: number;
  }>;

  return synthesizeAttackPaths(
    assets.map((a) => ({ ...a, internetExposed: Boolean(a.internetExposed) })),
    edges,
    findings
      .filter((f) => f.assetId)
      .map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        category: f.category,
        assetId: f.assetId!,
        assetName: f.assetName,
        status: f.status,
        cvss: f.cvss,
      }))
  );
}

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const attackPaths = computeTenantAttackPaths(authResult.auth.orgId);
  return jsonOk({ attackPaths });
}

const MitigatePathSchema = z.object({
  pathId: z.string().min(1),
  resolutionEvidence: z.string().min(3).max(500).optional(),
});

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = MitigatePathSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('pathId is required.', 400, 'VALIDATION_ERROR');
  }

  const currentPaths = computeTenantAttackPaths(authResult.auth.orgId);
  const target = currentPaths.find((p) => p.id === parsed.data.pathId);
  if (!target) {
    return jsonError('Attack path not found or already mitigated.', 404, 'NOT_FOUND');
  }

  const db = getDb();
  const now = new Date().toISOString();
  const evidence = parsed.data.resolutionEvidence || `Mitigated via Attack Path break by ${authResult.auth.email}`;

  for (const fid of target.contributingFindingIds) {
    db.prepare(
      `UPDATE findings SET status = 'Resolved', resolution_evidence = ?, verified_at = ?
       WHERE id = ? AND org_id = ?`
    ).run(evidence, now, fid, authResult.auth.orgId);
  }

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'ATTACK_PATH_MITIGATED',
    resourceType: 'AttackPath',
    resourceId: target.id,
    details: `Severed attack path "${target.title}" by resolving ${target.contributingFindingIds.join(', ')}.`,
  });

  const remainingPaths = computeTenantAttackPaths(authResult.auth.orgId);
  return jsonOk({
    mitigatedPathId: target.id,
    attackPaths: remainingPaths,
    findings: listEnrichedFindings(db, authResult.auth.orgId),
    organization: computeOrganizationSnapshot(db, authResult.auth.orgId),
  });
}
