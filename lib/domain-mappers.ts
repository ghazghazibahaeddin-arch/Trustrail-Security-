import type { DatabaseSync } from 'node:sqlite';
import { calculateRiskPriority } from '@/lib/engines/risk-engine';
import { synthesizeAttackPaths, type FindingLink, type GraphAssetNode, type GraphEdge } from '@/lib/engines/attack-path-engine';
import { verifyIntentLock } from '@/lib/engines/intent-lock';

export function computeOrganizationSnapshot(db: DatabaseSync, orgId: string) {
  const orgRow = db
    .prepare('SELECT id, name, slug, edition, tier_name, data_retention_days, threat_sharing_opt_in, enforcement_mode, created_at FROM organizations WHERE id = ?')
    .get(orgId) as
    | {
        id: string;
        name: string;
        slug: string;
        edition: 'developer' | 'smb' | 'enterprise';
        tier_name: string;
        data_retention_days: number;
        threat_sharing_opt_in: number;
        enforcement_mode?: 'Observe' | 'Recommend' | 'Enforce';
        created_at: string;
      }
    | undefined;

  if (!orgRow) return null;

  const assetsRows = db
    .prepare('SELECT id, org_id, project_id, name, asset_type, owner, internet_exposed, criticality FROM assets WHERE org_id = ?')
    .all(orgId) as Array<{
    id: string;
    org_id: string;
    project_id: string | null;
    name: string;
    asset_type: string;
    owner: string;
    internet_exposed: number;
    criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  }>;

  const edgesRows = db
    .prepare('SELECT id, org_id, source_asset_id, target_asset_id, relation, evidence FROM graph_edges WHERE org_id = ?')
    .all(orgId) as Array<{
    id: string;
    org_id: string;
    source_asset_id: string;
    target_asset_id: string;
    relation: string;
    evidence: string;
  }>;

  const findingsRows = db
    .prepare(
      `SELECT id, title, severity, category, asset_id, asset_name, status, cvss
       FROM findings WHERE org_id = ?`
    )
    .all(orgId) as Array<{
    id: string;
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    category: string;
    asset_id: string | null;
    asset_name: string;
    status: string;
    cvss: number;
  }>;

  const openFindings = findingsRows.filter((f) => f.status !== 'Resolved' && f.status !== 'False_Positive');
  const criticalCount = openFindings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = openFindings.filter((f) => f.severity === 'HIGH').length;
  const mediumCount = openFindings.filter((f) => f.severity === 'MEDIUM').length;

  const graphAssets: GraphAssetNode[] = assetsRows.map((a) => ({
    id: a.id,
    orgId: a.org_id,
    name: a.name,
    assetType: a.asset_type,
    owner: a.owner,
    internetExposed: Boolean(a.internet_exposed),
    criticality: a.criticality,
  }));

  const graphEdges: GraphEdge[] = edgesRows.map((e) => ({
    id: e.id,
    orgId: e.org_id,
    sourceAssetId: e.source_asset_id,
    targetAssetId: e.target_asset_id,
    relation: e.relation,
    evidence: e.evidence,
  }));

  const findingLinks: FindingLink[] = findingsRows
    .filter((f) => f.asset_id)
    .map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      category: f.category,
      assetId: f.asset_id!,
      assetName: f.asset_name,
      status: f.status,
      cvss: f.cvss,
    }));

  const attackPaths = synthesizeAttackPaths(graphAssets, graphEdges, findingLinks);

  const activeIncidentsRow = db
    .prepare("SELECT COUNT(*) as cnt FROM incidents WHERE org_id = ? AND status IN ('Open', 'Contained')")
    .get(orgId) as { cnt: number };

  const controlsRows = db
    .prepare('SELECT status FROM compliance_controls WHERE org_id = ?')
    .all(orgId) as Array<{ status: string }>;

  const verifiedControls = controlsRows.filter((c) => c.status === 'Verified').length;
  const compliancePercentage =
    controlsRows.length > 0 ? Math.round((verifiedControls / controlsRows.length) * 100) : 100;

  const rawRisk = Math.min(
    99,
    Math.max(
      5,
      criticalCount * 14 +
        highCount * 6 +
        mediumCount * 2 +
        attackPaths.length * 8 +
        (activeIncidentsRow?.cnt || 0) * 10
    )
  );

  const securityRating: 'A+' | 'A' | 'B+' | 'B' | 'C' | 'D' | 'F' =
    rawRisk <= 12
      ? 'A+'
      : rawRisk <= 25
      ? 'A'
      : rawRisk <= 40
      ? 'B+'
      : rawRisk <= 55
      ? 'B'
      : rawRisk <= 70
      ? 'C'
      : rawRisk <= 85
      ? 'D'
      : 'F';

  return {
    id: orgRow.id,
    name: orgRow.name,
    slug: orgRow.slug,
    edition: orgRow.edition,
    tierName: orgRow.tier_name,
    dataRetentionDays: orgRow.data_retention_days,
    threatSharingOptIn: Boolean(orgRow.threat_sharing_opt_in),
    enforcementMode: orgRow.enforcement_mode || 'Enforce',
    riskScore: rawRisk,
    securityRating,
    assetsCount: assetsRows.length,
    openFindingsCount: openFindings.length,
    criticalPathsCount: attackPaths.filter((p) => p.status === 'Active').length,
    activeIncidentsCount: activeIncidentsRow?.cnt || 0,
    compliancePercentage,
  };
}

export function listProjectsWithStats(db: DatabaseSync, orgId: string) {
  const rows = db
    .prepare(
      `SELECT id, name, repo_url, branch, language, framework, owner, status, last_scanned, connected_aws_account, sbom_json, slsa_level, created_at
       FROM projects WHERE org_id = ? ORDER BY created_at DESC`
    )
    .all(orgId) as Array<{
    id: string;
    name: string;
    repo_url: string;
    branch: string;
    language: string;
    framework: string;
    owner: string;
    status: 'protected' | 'warning' | 'critical' | 'scanning';
    last_scanned: string;
    connected_aws_account: string | null;
    sbom_json: string | null;
    slsa_level: 'SLSA 1' | 'SLSA 2' | 'SLSA 3' | 'None';
    created_at: string;
  }>;

  const openFindings = db
    .prepare(
      `SELECT project_id, severity FROM findings
       WHERE org_id = ? AND status NOT IN ('Resolved', 'False_Positive')`
    )
    .all(orgId) as Array<{ project_id: string | null; severity: string }>;

  return rows.map((p) => {
    const pFindings = openFindings.filter((f) => f.project_id === p.id);
    const counts = {
      critical: pFindings.filter((f) => f.severity === 'CRITICAL').length,
      high: pFindings.filter((f) => f.severity === 'HIGH').length,
      medium: pFindings.filter((f) => f.severity === 'MEDIUM').length,
      low: pFindings.filter((f) => f.severity === 'LOW').length,
    };

    const computedStatus: 'protected' | 'warning' | 'critical' | 'scanning' =
      p.status === 'scanning'
        ? 'scanning'
        : counts.critical > 0
        ? 'critical'
        : counts.high > 0
        ? 'warning'
        : 'protected';

    let sbom: unknown = null;
    if (p.sbom_json) {
      try {
        sbom = JSON.parse(p.sbom_json);
      } catch {
        sbom = null;
      }
    }

    return {
      id: p.id,
      name: p.name,
      repoUrl: p.repo_url,
      branch: p.branch,
      language: p.language,
      framework: p.framework,
      owner: p.owner,
      status: computedStatus,
      lastScanned: p.last_scanned,
      findingsCount: counts,
      connectedAwsAccount: p.connected_aws_account || undefined,
      sbomGenerated: Boolean(sbom),
      sbom,
      slsaLevel: p.slsa_level,
      createdAt: p.created_at,
    };
  });
}

export function listEnrichedFindings(db: DatabaseSync, orgId: string) {
  const orgSnapshot = computeOrganizationSnapshot(db, orgId);
  const assetsRows = db
    .prepare('SELECT id, internet_exposed, criticality FROM assets WHERE org_id = ?')
    .all(orgId) as Array<{ id: string; internet_exposed: number; criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' }>;
  const assetMap = new Map(assetsRows.map((a) => [a.id, a]));

  const edgesRows = db
    .prepare('SELECT id, org_id, source_asset_id, target_asset_id, relation, evidence FROM graph_edges WHERE org_id = ?')
    .all(orgId) as Array<{
    id: string;
    org_id: string;
    source_asset_id: string;
    target_asset_id: string;
    relation: string;
    evidence: string;
  }>;
  const fullAssets = db
    .prepare('SELECT id, org_id, name, asset_type, owner, internet_exposed, criticality FROM assets WHERE org_id = ?')
    .all(orgId) as Array<{
    id: string;
    org_id: string;
    name: string;
    asset_type: string;
    owner: string;
    internet_exposed: number;
    criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  }>;

  const rows = db
    .prepare(
      `SELECT id, project_id, asset_id, fingerprint, title, severity, category, scanner, asset_name, file_path, line, cve, cvss, exploitability, status, evidence, suggested_fix, resolution_evidence, assigned_owner, discovered_at, verified_at
       FROM findings WHERE org_id = ? ORDER BY cvss DESC, discovered_at DESC`
    )
    .all(orgId) as Array<{
    id: string;
    project_id: string | null;
    asset_id: string | null;
    fingerprint: string;
    title: string;
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    category: 'SAST' | 'SCA' | 'SECRET' | 'IAC' | 'CLOUD' | 'CONTAINER' | 'API' | 'SUPPLY_CHAIN';
    scanner: string;
    asset_name: string;
    file_path: string | null;
    line: number | null;
    cve: string | null;
    cvss: number;
    exploitability: 'High' | 'Medium' | 'Low' | 'Proof-of-Concept';
    status: 'Open' | 'In_Remediation' | 'Under_Review' | 'Resolved' | 'False_Positive';
    evidence: string;
    suggested_fix: string;
    resolution_evidence: string | null;
    assigned_owner: string;
    discovered_at: string;
    verified_at: string | null;
  }>;

  const computedPaths = synthesizeAttackPaths(
    fullAssets.map((a) => ({
      id: a.id,
      orgId: a.org_id,
      name: a.name,
      assetType: a.asset_type,
      owner: a.owner,
      internetExposed: Boolean(a.internet_exposed),
      criticality: a.criticality,
    })),
    edgesRows.map((e) => ({
      id: e.id,
      orgId: e.org_id,
      sourceAssetId: e.source_asset_id,
      targetAssetId: e.target_asset_id,
      relation: e.relation,
      evidence: e.evidence,
    })),
    rows
      .filter((r) => r.asset_id)
      .map((r) => ({
        id: r.id,
        title: r.title,
        severity: r.severity,
        category: r.category,
        assetId: r.asset_id!,
        assetName: r.asset_name,
        status: r.status,
        cvss: r.cvss,
      }))
  );

  const findingIdsInPaths = new Set<string>();
  for (const p of computedPaths) {
    for (const fid of p.contributingFindingIds) {
      findingIdsInPaths.add(fid);
    }
  }

  const intelRows = db
    .prepare(
      `SELECT cve_id, MAX(kev_listed) as kev_listed, MAX(epss_score) as epss_score
       FROM vulnerability_intel GROUP BY cve_id`
    )
    .all() as Array<{ cve_id: string; kev_listed: number; epss_score: number | null }>;
  const intelMap = new Map(intelRows.map((i) => [i.cve_id.toUpperCase(), i]));

  return rows.map((r) => {
    const asset = r.asset_id ? assetMap.get(r.asset_id) : undefined;
    const intel = r.cve ? intelMap.get(r.cve.toUpperCase()) : undefined;
    const risk = calculateRiskPriority({
      cvss: r.cvss,
      exploitability: r.exploitability,
      internetExposed: Boolean(asset?.internet_exposed),
      assetCriticality: asset?.criticality || (r.severity === 'CRITICAL' ? 'CRITICAL' : 'HIGH'),
      inActiveAttackPath: findingIdsInPaths.has(r.id),
      fixAvailable: Boolean(r.suggested_fix),
      kevListed: Boolean(intel?.kev_listed),
      epssScore: intel?.epss_score ?? null,
    });

    return {
      id: r.id,
      projectId: r.project_id || '',
      assetId: r.asset_id || undefined,
      fingerprint: r.fingerprint,
      title: r.title,
      severity: r.severity,
      category: r.category,
      scanner: r.scanner,
      assetName: r.asset_name,
      filePath: r.file_path || undefined,
      line: r.line || undefined,
      cve: r.cve || undefined,
      kevListed: Boolean(intel?.kev_listed),
      epssScore: intel?.epss_score ?? undefined,
      cvss: r.cvss,
      exploitability: r.exploitability,
      status: r.status,
      discoveredAt: r.discovered_at,
      verifiedAt: r.verified_at || undefined,
      evidence: r.evidence,
      suggestedFix: r.suggested_fix,
      resolutionEvidence: r.resolution_evidence || undefined,
      aiPatchReady: Boolean(orgSnapshot),
      assignedOwner: r.assigned_owner,
      riskScore: risk.score,
      priorityTier: risk.priorityTier,
      riskReasons: risk.reasons,
    };
  });
}

export function listChangeContractsFormatted(db: DatabaseSync, orgId: string) {
  const rows = db
    .prepare(
      `SELECT id, title, actor, project, target_asset, previous_state_hash, new_state_payload, new_state_hash, approved_hash, purpose, risk_level, intent_lock_status, approved_by, evidence_summary, created_at
       FROM change_contracts WHERE org_id = ? ORDER BY created_at DESC`
    )
    .all(orgId) as Array<{
    id: string;
    title: string;
    actor: string;
    project: string;
    target_asset: string;
    previous_state_hash: string;
    new_state_payload: string;
    new_state_hash: string;
    approved_hash: string | null;
    purpose: string;
    risk_level: 'High' | 'Medium' | 'Low';
    intent_lock_status: string;
    approved_by: string | null;
    evidence_summary: string;
    created_at: string;
  }>;

  return rows.map((c) => {
    let parsedPayload: unknown = {};
    try {
      parsedPayload = JSON.parse(c.new_state_payload);
    } catch {
      parsedPayload = c.new_state_payload;
    }

    const lockCheck = verifyIntentLock(
      c.approved_hash,
      {
        targetAsset: c.target_asset,
        previousStateHash: c.previous_state_hash,
        newStatePayload: parsedPayload,
        purpose: c.purpose,
      },
      c.intent_lock_status
    );

    return {
      id: c.id,
      title: c.title,
      actor: c.actor,
      project: c.project,
      targetAsset: c.target_asset,
      previousStateHash: c.previous_state_hash,
      newStatePayload: parsedPayload,
      newStateHash: lockCheck.currentHash,
      approvedHash: c.approved_hash || undefined,
      purpose: c.purpose,
      riskLevel: c.risk_level,
      intentLockStatus: lockCheck.status,
      intentLockReason: lockCheck.reason,
      approvedBy: lockCheck.status === 'Modified_Revalidation_Required' ? undefined : c.approved_by || undefined,
      createdAt: c.created_at,
      evidenceSummary: c.evidence_summary,
    };
  });
}
