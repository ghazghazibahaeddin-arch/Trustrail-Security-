import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { analyzeKubernetesManifestOrSnapshot } from '@/lib/integrations/kubernetes-analyzer';
import { computeOrganizationSnapshot, listEnrichedFindings } from '@/lib/domain-mappers';
import { publishEvent } from '@/lib/fabric/event-bus';

const KubernetesAnalyzeSchema = z.object({
  clusterName: z.string().min(2).max(100).default('prod-eks-us-east-1'),
  manifestContent: z.string().max(250_000).optional(),
  manifestYaml: z.string().max(250_000).optional(),
  resources: z
    .array(
      z.object({
        kind: z.string().min(2).max(60),
        name: z.string().min(1).max(120),
        namespace: z.string().max(80).optional(),
        privileged: z.boolean().optional(),
        hostNetwork: z.boolean().optional(),
        hostPID: z.boolean().optional(),
        runAsNonRoot: z.boolean().optional(),
        readOnlyRootFilesystem: z.boolean().optional(),
        allowPrivilegeEscalation: z.boolean().optional(),
        wildcardRbac: z.boolean().optional(),
        clusterAdminBinding: z.boolean().optional(),
        hasNetworkPolicy: z.boolean().optional(),
      })
    )
    .optional(),
});

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Developer', 'scan');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = KubernetesAnalyzeSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid Kubernetes analysis payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const rawManifest = parsed.data.manifestContent?.trim() || parsed.data.manifestYaml?.trim();
  if (!rawManifest && (!parsed.data.resources || parsed.data.resources.length === 0)) {
    return jsonError('Provide either manifestContent YAML or resources snapshot.', 400, 'EMPTY_INPUT');
  }

  const analysis = analyzeKubernetesManifestOrSnapshot({
    clusterName: parsed.data.clusterName,
    manifestContent: rawManifest,
    resources: parsed.data.resources,
  });
  const db = getDb();
  const now = new Date().toISOString();

  // Upsert Kubernetes assets into Security Graph
  const affectedAssetIds: string[] = [];
  for (const a of analysis.discoveredAssets) {
    let existingAsset = db
      .prepare('SELECT id FROM assets WHERE org_id = ? AND name = ?')
      .get(authResult.auth.orgId, a.name) as { id: string } | undefined;

    if (!existingAsset) {
      const assetId = `asset-${crypto.randomUUID().slice(0, 8)}`;
      db.prepare(
        `INSERT INTO assets (id, org_id, project_id, name, asset_type, owner, internet_exposed, criticality, created_at)
         VALUES (?, ?, NULL, ?, ?, ?, 0, ?, ?)`
      ).run(assetId, authResult.auth.orgId, a.name, a.assetType, authResult.auth.name, a.criticality, now);
      existingAsset = { id: assetId };
    }
    affectedAssetIds.push(existingAsset.id);
  }

  let newFindingsInserted = 0;
  const primaryAssetId = affectedAssetIds[0] || null;
  for (const f of analysis.findings) {
    const existing = db
      .prepare('SELECT id FROM findings WHERE org_id = ? AND fingerprint = ?')
      .get(authResult.auth.orgId, f.fingerprint);
    if (!existing) {
      newFindingsInserted += 1;
      db.prepare(
        `INSERT INTO findings (id, org_id, project_id, asset_id, fingerprint, title, severity, category, scanner, asset_name, file_path, line, cve, cvss, exploitability, status, evidence, suggested_fix, assigned_owner, discovered_at)
         VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, 'Open', ?, ?, ?, ?)`
      ).run(
        `finding-${crypto.randomUUID().slice(0, 8)}`,
        authResult.auth.orgId,
        primaryAssetId,
        f.fingerprint,
        f.title,
        f.severity,
        f.category,
        f.scanner,
        parsed.data.clusterName,
        f.filePath || 'k8s-manifest.yaml',
        f.cvss,
        f.exploitability,
        f.evidence,
        f.suggestedFix,
        authResult.auth.name,
        now
      );
    }
  }

  db.prepare(
    `UPDATE connectors
     SET assets_discovered = assets_discovered + ?, events_imported = events_imported + 1, last_sync = ?, lifecycle_state = 'HEALTHY', status = 'Connected'
     WHERE org_id = ? AND provider_key = 'kubernetes'`
  ).run(analysis.discoveredAssets.length, now, authResult.auth.orgId);

  publishEvent(db, {
    orgId: authResult.auth.orgId,
    eventType: analysis.findings.length > 0 ? 'state.drift_detected' : 'asset.discovered',
    actorId: authResult.auth.email,
    sourceConnector: 'kubernetes',
    sourceResourceId: parsed.data.clusterName,
    affectedAssetIds,
    payload: {
      resourcesAnalyzed: analysis.resourcesAnalyzed,
      findingsDetected: analysis.findings.length,
      newFindingsInserted,
    },
  });

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'KUBERNETES_POSTURE_ANALYZED',
    resourceType: 'KubernetesCluster',
    resourceId: parsed.data.clusterName,
    details: `Analyzed ${analysis.resourcesAnalyzed} Kubernetes resources: ${analysis.findings.length} findings (${newFindingsInserted} new).`,
  });

  return jsonOk(
    {
      clusterName: parsed.data.clusterName,
      resourcesAnalyzed: analysis.resourcesAnalyzed,
      findingsDetected: analysis.findings.length,
      findingsCount: analysis.findings.length,
      newFindingsInserted,
      findings: listEnrichedFindings(db, authResult.auth.orgId),
      organization: computeOrganizationSnapshot(db, authResult.auth.orgId),
    },
    201
  );
}
