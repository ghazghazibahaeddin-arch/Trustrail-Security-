import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { executeUnifiedScan } from '@/lib/engines/scanner-engine';
import {
  computeOrganizationSnapshot,
  listEnrichedFindings,
  listProjectsWithStats,
} from '@/lib/domain-mappers';
import { publishEvent } from '@/lib/fabric/event-bus';

const ScanRequestSchema = z.object({
  projectId: z.string().optional(),
  projectName: z.string().optional(),
  codeContent: z.string().max(250_000).optional(),
  filePath: z.string().max(255).optional(),
  packageJsonContent: z.string().max(250_000).optional(),
  packageLockContent: z.string().max(500_000).optional(),
  requirementsTxtContent: z.string().max(100_000).optional(),
  goModContent: z.string().max(100_000).optional(),
  pomXmlContent: z.string().max(250_000).optional(),
  githubWorkflowContent: z.string().max(100_000).optional(),
  terraformContent: z.string().max(250_000).optional(),
  dockerfileContent: z.string().max(100_000).optional(),
});

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer', 'read');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const scans = db
    .prepare(
      `SELECT id, project_id as projectId, triggered_by as triggeredBy, status, scanners_run as scannersRun, files_scanned as filesScanned, findings_detected as findingsDetected, error_message as errorMessage, started_at as startedAt, completed_at as completedAt
       FROM scans WHERE org_id = ? ORDER BY started_at DESC LIMIT 50`
    )
    .all(authResult.auth.orgId) as Array<Record<string, unknown>>;

  return jsonOk({
    scans: scans.map((s) => ({
      ...s,
      scannersRun: (() => {
        try {
          return JSON.parse(String(s.scannersRun || '[]'));
        } catch {
          return [];
        }
      })(),
    })),
  });
}

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Developer', 'scan');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = ScanRequestSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid scan payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  let projectRow:
    | { id: string; name: string; repo_url: string; owner: string; sbom_json?: string | null }
    | undefined;

  if (parsed.data.projectId) {
    projectRow = db
      .prepare('SELECT id, name, repo_url, owner, sbom_json FROM projects WHERE id = ? AND org_id = ?')
      .get(parsed.data.projectId, authResult.auth.orgId) as
      | { id: string; name: string; repo_url: string; owner: string; sbom_json?: string | null }
      | undefined;
    if (!projectRow) {
      return jsonError('Target project not found in your organization.', 404, 'PROJECT_NOT_FOUND');
    }
  } else if (parsed.data.projectName) {
    projectRow = db
      .prepare('SELECT id, name, repo_url, owner, sbom_json FROM projects WHERE name = ? AND org_id = ?')
      .get(parsed.data.projectName, authResult.auth.orgId) as
      | { id: string; name: string; repo_url: string; owner: string; sbom_json?: string | null }
      | undefined;
  } else {
    projectRow = db
      .prepare('SELECT id, name, repo_url, owner, sbom_json FROM projects WHERE org_id = ? ORDER BY created_at DESC LIMIT 1')
      .get(authResult.auth.orgId) as
      | { id: string; name: string; repo_url: string; owner: string; sbom_json?: string | null }
      | undefined;
  }

  const projectName = projectRow?.name || parsed.data.projectName || 'workspace-target';
  const scanId = `scan-${crypto.randomUUID().slice(0, 8)}`;
  const startedAt = new Date().toISOString();

  const hasArtifacts = Boolean(
    parsed.data.codeContent?.trim() ||
      parsed.data.packageJsonContent?.trim() ||
      parsed.data.packageLockContent?.trim() ||
      parsed.data.requirementsTxtContent?.trim() ||
      parsed.data.goModContent?.trim() ||
      parsed.data.pomXmlContent?.trim() ||
      parsed.data.githubWorkflowContent?.trim() ||
      parsed.data.terraformContent?.trim() ||
      parsed.data.dockerfileContent?.trim()
  );

  let derivedPkgJson: string | undefined;
  if (!hasArtifacts && projectRow?.sbom_json) {
    try {
      const sbomObj = JSON.parse(projectRow.sbom_json) as {
        components?: Array<{ name: string; version: string }>;
      };
      if (sbomObj.components && sbomObj.components.length > 0) {
        const deps: Record<string, string> = {};
        for (const c of sbomObj.components) {
          deps[c.name] = c.version;
        }
        derivedPkgJson = JSON.stringify({ name: projectName, dependencies: deps });
      }
    } catch {
      derivedPkgJson = undefined;
    }
  }

  const execResult =
    hasArtifacts || derivedPkgJson
      ? executeUnifiedScan({
          projectName,
          codeContent: parsed.data.codeContent,
          filePath: parsed.data.filePath,
          packageJsonContent: parsed.data.packageJsonContent || derivedPkgJson,
          packageLockContent: parsed.data.packageLockContent,
          requirementsTxtContent: parsed.data.requirementsTxtContent,
          goModContent: parsed.data.goModContent,
          pomXmlContent: parsed.data.pomXmlContent,
          githubWorkflowContent: parsed.data.githubWorkflowContent,
          terraformContent: parsed.data.terraformContent,
          dockerfileContent: parsed.data.dockerfileContent,
        })
      : {
          findings: [],
          sbom: null,
          scannersRun: ['trustrail-unified-posture-sweep'],
          filesScanned: 0,
          errors: [],
        };

  // Ensure an asset exists for the project
  let assetId: string | null = null;
  if (projectRow) {
    const assetRow = db
      .prepare('SELECT id FROM assets WHERE project_id = ? AND org_id = ? LIMIT 1')
      .get(projectRow.id, authResult.auth.orgId) as { id: string } | undefined;
    if (assetRow) {
      assetId = assetRow.id;
    } else {
      assetId = `asset-${crypto.randomUUID().slice(0, 8)}`;
      db.prepare(
        `INSERT INTO assets (id, org_id, project_id, name, asset_type, owner, internet_exposed, criticality, created_at)
         VALUES (?, ?, ?, ?, 'Repository', ?, 0, 'HIGH', ?)`
      ).run(assetId, authResult.auth.orgId, projectRow.id, projectRow.repo_url, projectRow.owner, startedAt);
    }
  }

  let newFindingsInserted = 0;
  let existingFindingsUpdated = 0;

  for (const f of execResult.findings) {
    const existingFinding = db
      .prepare('SELECT id, status FROM findings WHERE org_id = ? AND fingerprint = ?')
      .get(authResult.auth.orgId, f.fingerprint) as { id: string; status: string } | undefined;

    if (existingFinding) {
      existingFindingsUpdated += 1;
      const nextStatus = existingFinding.status === 'Resolved' ? 'Open' : existingFinding.status;
      db.prepare(
        `UPDATE findings SET evidence = ?, status = ?, discovered_at = ? WHERE id = ? AND org_id = ?`
      ).run(f.evidence, nextStatus, startedAt, existingFinding.id, authResult.auth.orgId);
    } else {
      newFindingsInserted += 1;
      db.prepare(
        `INSERT INTO findings (id, org_id, project_id, asset_id, fingerprint, title, severity, category, scanner, asset_name, file_path, line, cve, cvss, exploitability, status, evidence, suggested_fix, assigned_owner, discovered_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?)`
      ).run(
        `finding-${crypto.randomUUID().slice(0, 8)}`,
        authResult.auth.orgId,
        projectRow?.id || null,
        assetId,
        f.fingerprint,
        f.title,
        f.severity,
        f.category,
        f.scanner,
        projectRow?.repo_url || projectName,
        f.filePath || null,
        f.line || null,
        f.cve || null,
        f.cvss,
        f.exploitability,
        f.evidence,
        f.suggestedFix,
        projectRow?.owner || authResult.auth.name,
        startedAt
      );
    }
  }

  if (projectRow) {
    if (execResult.sbom) {
      db.prepare(
        `UPDATE projects SET last_scanned = ?, sbom_json = ?, slsa_level = CASE WHEN slsa_level = 'None' THEN 'SLSA 1' ELSE slsa_level END WHERE id = ? AND org_id = ?`
      ).run(startedAt, JSON.stringify(execResult.sbom), projectRow.id, authResult.auth.orgId);
    } else {
      db.prepare(`UPDATE projects SET last_scanned = ? WHERE id = ? AND org_id = ?`).run(
        startedAt,
        projectRow.id,
        authResult.auth.orgId
      );
    }
  }

  const completedAt = new Date().toISOString();
  const scanStatus = execResult.errors.length > 0 && execResult.findings.length === 0 && !execResult.sbom ? 'Failed' : 'Completed';

  db.prepare(
    `INSERT INTO scans (id, org_id, project_id, triggered_by, status, scanners_run, files_scanned, findings_detected, error_message, started_at, completed_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    scanId,
    authResult.auth.orgId,
    projectRow?.id || null,
    authResult.auth.email,
    scanStatus,
    JSON.stringify(execResult.scannersRun),
    execResult.filesScanned,
    execResult.findings.length,
    execResult.errors.length > 0 ? execResult.errors.join('; ') : null,
    startedAt,
    completedAt
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'SCAN_EXECUTED',
    resourceType: 'Scan',
    resourceId: scanId,
    details: `Executed ${execResult.scannersRun.join(', ')} on ${projectName}: ${execResult.findings.length} findings (${newFindingsInserted} new, ${existingFindingsUpdated} deduplicated).`,
  });

  const correlationId = `corr-${scanId}`;
  publishEvent(db, {
    orgId: authResult.auth.orgId,
    eventType: scanStatus === 'Failed' ? 'scan.failed' : 'scan.completed',
    actorId: authResult.auth.email,
    sourceConnector: 'trustrail_scanner',
    sourceResourceId: projectRow?.id || projectName,
    affectedAssetIds: assetId ? [assetId] : [],
    correlationId,
    payload: {
      scanId,
      projectName,
      findingsDetected: execResult.findings.length,
      newFindingsInserted,
      scannersRun: execResult.scannersRun,
    },
  });

  const secretFindings = execResult.findings.filter((f) => f.category === 'SECRET');
  if (secretFindings.length > 0) {
    publishEvent(db, {
      orgId: authResult.auth.orgId,
      eventType: 'secret.detected',
      actorId: authResult.auth.email,
      sourceConnector: 'trustrail_scanner',
      sourceResourceId: projectRow?.repo_url || projectName,
      affectedAssetIds: assetId ? [assetId] : [],
      correlationId,
      payload: {
        count: secretFindings.length,
        titles: secretFindings.slice(0, 5).map((s) => s.title),
      },
    });
  } else if (newFindingsInserted > 0) {
    publishEvent(db, {
      orgId: authResult.auth.orgId,
      eventType: 'vulnerability.discovered',
      actorId: authResult.auth.email,
      sourceConnector: 'trustrail_scanner',
      sourceResourceId: projectRow?.id || projectName,
      affectedAssetIds: assetId ? [assetId] : [],
      correlationId,
      payload: { newFindingsInserted, totalFindings: execResult.findings.length },
    });
  }

  if (execResult.sbom) {
    publishEvent(db, {
      orgId: authResult.auth.orgId,
      eventType: 'sbom.generated',
      actorId: authResult.auth.email,
      sourceConnector: 'trustrail_scanner',
      sourceResourceId: projectRow?.id || projectName,
      affectedAssetIds: assetId ? [assetId] : [],
      correlationId,
      payload: { components: execResult.sbom.components.length },
    });
  }

  return jsonOk(
    {
      scan: {
        id: scanId,
        projectId: projectRow?.id || null,
        projectName,
        status: scanStatus,
        scannersRun: execResult.scannersRun,
        filesScanned: execResult.filesScanned,
        findingsDetected: execResult.findings.length,
        newFindingsInserted,
        existingFindingsUpdated,
        sbomGenerated: Boolean(execResult.sbom),
        sbom: execResult.sbom,
        errors: execResult.errors,
        startedAt,
        completedAt,
      },
      organization: computeOrganizationSnapshot(db, authResult.auth.orgId),
      projects: listProjectsWithStats(db, authResult.auth.orgId),
      findings: listEnrichedFindings(db, authResult.auth.orgId),
    },
    201
  );
}
