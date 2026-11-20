import { NextRequest } from 'next/server';
import { getDb } from '@/lib/db';
import { jsonOk, requireAuth } from '@/lib/api-response';
import { synthesizeAttackPaths } from '@/lib/engines/attack-path-engine';

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const assets = db
    .prepare(
      `SELECT id, org_id as orgId, project_id as projectId, name, asset_type as assetType, owner, internet_exposed as internetExposed, criticality, created_at as createdAt
       FROM assets WHERE org_id = ?`
    )
    .all(authResult.auth.orgId) as Array<{
    id: string;
    orgId: string;
    projectId: string | null;
    name: string;
    assetType: string;
    owner: string;
    internetExposed: number;
    criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    createdAt: string;
  }>;

  const edges = db
    .prepare(
      `SELECT id, org_id as orgId, source_asset_id as sourceAssetId, target_asset_id as targetAssetId,
              relation, evidence, COALESCE(confidence, 0.95) as confidence,
              collected_at as collectedAt, verified_at as verifiedAt
       FROM graph_edges WHERE org_id = ?`
    )
    .all(authResult.auth.orgId) as Array<{
    id: string;
    orgId: string;
    sourceAssetId: string;
    targetAssetId: string;
    relation: string;
    evidence: string;
    confidence: number;
    collectedAt: string | null;
    verifiedAt: string | null;
  }>;

  const findings = db
    .prepare(
      `SELECT id, title, severity, category, asset_id as assetId, asset_name as assetName, status, cvss
       FROM findings WHERE org_id = ?`
    )
    .all(authResult.auth.orgId) as Array<{
    id: string;
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    category: string;
    assetId: string | null;
    assetName: string;
    status: string;
    cvss: number;
  }>;

  const normalizedAssets = assets.map((a) => ({
    ...a,
    internetExposed: Boolean(a.internetExposed),
    openFindingsCount: findings.filter(
      (f) => f.assetId === a.id && f.status !== 'Resolved' && f.status !== 'False_Positive'
    ).length,
  }));

  const attackPaths = synthesizeAttackPaths(
    normalizedAssets,
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

  return jsonOk({
    nodes: normalizedAssets,
    edges,
    attackPaths,
  });
}
