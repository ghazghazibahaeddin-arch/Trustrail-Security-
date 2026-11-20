import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { parseConnectorConfig } from '@/lib/security/connector-config';
import { executeUnifiedScan, NormalizedFindingInput } from '@/lib/engines/scanner-engine';
import { queryOsvPackages } from '@/lib/integrations/osv-client';
import { computeOrganizationSnapshot, listEnrichedFindings, listProjectsWithStats } from '@/lib/domain-mappers';

const ScanGithubRepoSchema = z.object({
  repo: z.string().min(3).max(200),
  branch: z.string().min(1).max(100).optional(),
  includeOsvCheck: z.boolean().default(true),
});

function parseRepoSlug(raw: string): { owner: string; repo: string } | null {
  let cleaned = raw.trim();
  if (cleaned.startsWith('https://') || cleaned.startsWith('http://')) {
    try {
      const u = new URL(cleaned);
      if (u.hostname.toLowerCase() !== 'github.com') return null;
      cleaned = u.pathname.replace(/^\/+|\/+$/g, '');
    } catch {
      return null;
    }
  } else if (cleaned.startsWith('github.com/')) {
    cleaned = cleaned.slice('github.com/'.length);
  }
  cleaned = cleaned.replace(/\.git$/i, '').replace(/^\/+|\/+$/g, '');
  const parts = cleaned.split('/');
  if (parts.length !== 2) return null;
  const [owner, repo] = parts;
  if (!/^[A-Za-z0-9_.-]+$/.test(owner) || !/^[A-Za-z0-9_.-]+$/.test(repo)) {
    return null;
  }
  return { owner, repo };
}

async function fetchGithubRawContent(
  owner: string,
  repo: string,
  filePath: string,
  ref: string,
  headers: Record<string, string>
): Promise<string | null> {
  const encodedPath = filePath
    .split('/')
    .map((seg) => encodeURIComponent(seg))
    .join('/');
  const res = await fetch(
    `https://api.github.com/repos/${owner}/${repo}/contents/${encodedPath}?ref=${encodeURIComponent(ref)}`,
    { headers, signal: AbortSignal.timeout(8000) }
  );
  if (!res.ok) return null;
  const json = (await res.json()) as { content?: string; encoding?: string };
  if (!json.content || json.encoding !== 'base64') return null;
  return Buffer.from(json.content.replace(/\n/g, ''), 'base64').toString('utf8');
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

  const parsed = ScanGithubRepoSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid GitHub repository scan request.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const slug = parseRepoSlug(parsed.data.repo);
  if (!slug) {
    return jsonError(
      'Invalid GitHub repository format. Use "owner/repo" or "https://github.com/owner/repo".',
      400,
      'INVALID_REPO_SLUG'
    );
  }

  const db = getDb();
  const connRow = db
    .prepare(`SELECT id, config_json FROM connectors WHERE org_id = ? AND provider_key = 'github'`)
    .get(authResult.auth.orgId) as { id: string; config_json: string | null } | undefined;
  const cfg = parseConnectorConfig(
    connRow?.config_json,
    connRow ? { orgId: authResult.auth.orgId, connectorId: connRow.id } : undefined
  );
  const githubToken = cfg.githubToken || process.env.GITHUB_TOKEN;

  const ghHeaders: Record<string, string> = {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'Trustrail-Security-Cloud',
  };
  if (githubToken) {
    ghHeaders.Authorization = `Bearer ${githubToken}`;
  }

  try {
    const repoRes = await fetch(`https://api.github.com/repos/${slug.owner}/${slug.repo}`, {
      headers: ghHeaders,
      signal: AbortSignal.timeout(8000),
    });
    if (repoRes.status === 404) {
      return jsonError(
        `GitHub repository "${slug.owner}/${slug.repo}" was not found or is private (save a GitHub PAT in Integrations to access private repos).`,
        404,
        'REPO_NOT_FOUND'
      );
    }
    if (!repoRes.ok) {
      return jsonError(`GitHub API error (HTTP ${repoRes.status}).`, 502, 'GITHUB_API_ERROR');
    }

    const repoMeta = (await repoRes.json()) as {
      name: string;
      full_name: string;
      default_branch?: string;
      language?: string;
      private?: boolean;
    };

    const branch = parsed.data.branch || repoMeta.default_branch || 'main';
    const treeRes = await fetch(
      `https://api.github.com/repos/${slug.owner}/${slug.repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`,
      { headers: ghHeaders, signal: AbortSignal.timeout(10_000) }
    );

    const treeItems: Array<{ path: string; type: string; size?: number }> = [];
    if (treeRes.ok) {
      const treeJson = (await treeRes.json()) as {
        tree?: Array<{ path: string; type: string; size?: number }>;
      };
      for (const item of treeJson.tree || []) {
        if (item.type === 'blob' && (item.size ?? 0) < 120_000) {
          treeItems.push(item);
        }
      }
    }

    const packagePath = treeItems.find((i) => i.path === 'package.json')?.path
      || treeItems.find((i) => i.path.endsWith('/package.json'))?.path;
    const dockerfilePath = treeItems.find((i) => i.path === 'Dockerfile')?.path
      || treeItems.find((i) => i.path.endsWith('/Dockerfile'))?.path;
    const tfPaths = treeItems.filter((i) => i.path.endsWith('.tf')).slice(0, 3).map((i) => i.path);
    const codePaths = treeItems
      .filter((i) => /\.(ts|tsx|js|jsx|py)$/i.test(i.path) && !i.path.includes('node_modules/'))
      .sort((a, b) => {
        const score = (p: string) =>
          /auth|login|api|route|server|config|db|controller/i.test(p) ? 0 : 1;
        return score(a.path) - score(b.path);
      })
      .slice(0, 4)
      .map((i) => i.path);

    const [pkgRaw, dockerRaw, tfContents, codeContents] = await Promise.all([
      packagePath ? fetchGithubRawContent(slug.owner, slug.repo, packagePath, branch, ghHeaders) : Promise.resolve(null),
      dockerfilePath ? fetchGithubRawContent(slug.owner, slug.repo, dockerfilePath, branch, ghHeaders) : Promise.resolve(null),
      Promise.all(tfPaths.map((p) => fetchGithubRawContent(slug.owner, slug.repo, p, branch, ghHeaders))),
      Promise.all(codePaths.map(async (p) => ({ path: p, content: await fetchGithubRawContent(slug.owner, slug.repo, p, branch, ghHeaders) }))),
    ]);

    const repoUrl = `github.com/${repoMeta.full_name}`;
    const now = new Date().toISOString();

    // Upsert project & asset
    let projectRow = db
      .prepare('SELECT id, name, owner FROM projects WHERE org_id = ? AND repo_url = ?')
      .get(authResult.auth.orgId, repoUrl) as { id: string; name: string; owner: string } | undefined;

    if (!projectRow) {
      const projId = `proj-${crypto.randomUUID().slice(0, 8)}`;
      db.prepare(
        `INSERT INTO projects (id, org_id, name, repo_url, branch, language, framework, owner, status, last_scanned, connected_aws_account, sbom_json, slsa_level, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'GitHub Repository', ?, 'protected', ?, NULL, NULL, 'SLSA 1', ?)`
      ).run(projId, authResult.auth.orgId, repoMeta.name, repoUrl, branch, repoMeta.language || 'TypeScript', authResult.auth.name, now, now);
      projectRow = { id: projId, name: repoMeta.name, owner: authResult.auth.name };
    }

    let assetRow = db
      .prepare('SELECT id FROM assets WHERE org_id = ? AND project_id = ? LIMIT 1')
      .get(authResult.auth.orgId, projectRow.id) as { id: string } | undefined;

    if (!assetRow) {
      const assetId = `asset-${crypto.randomUUID().slice(0, 8)}`;
      db.prepare(
        `INSERT INTO assets (id, org_id, project_id, name, asset_type, owner, internet_exposed, criticality, created_at)
         VALUES (?, ?, ?, ?, 'Repository', ?, ?, 'HIGH', ?)`
      ).run(assetId, authResult.auth.orgId, projectRow.id, repoUrl, projectRow.owner, repoMeta.private ? 0 : 1, now);
      assetRow = { id: assetId };
    }

    // Execute real scanners on fetched repository files
    const combinedFindings: NormalizedFindingInput[] = [];
    const scannersRun = new Set<string>(['github-live-tree-fetcher']);
    let filesScanned = 0;
    let sbomJson: string | null = null;

    if (pkgRaw) {
      const res = executeUnifiedScan({ projectName: projectRow.name, packageJsonContent: pkgRaw });
      combinedFindings.push(...res.findings);
      res.scannersRun.forEach((s) => scannersRun.add(s));
      filesScanned += res.filesScanned;
      if (res.sbom) {
        sbomJson = JSON.stringify(res.sbom);
        if (parsed.data.includeOsvCheck && res.sbom.components.length > 0) {
          try {
            const osv = await queryOsvPackages(
              res.sbom.components.slice(0, 25).map((c) => ({
                ecosystem: 'npm' as const,
                name: c.name,
                version: c.version,
              }))
            );
            scannersRun.add('osv-dev-live-feed');
            for (const adv of osv.advisories) {
              const cve = adv.aliases.find((a) => a.startsWith('CVE-')) || adv.id;
              combinedFindings.push({
                fingerprint: crypto
                  .createHash('sha256')
                  .update(`${projectRow.name}|OSV|${adv.packageName}|${adv.id}`)
                  .digest('hex')
                  .slice(0, 16),
                title: `${adv.packageName}@${adv.packageVersion}: ${adv.summary.slice(0, 100)}`,
                severity: adv.severityLabel,
                category: 'SCA',
                scanner: 'osv-dev-live-feed',
                filePath: packagePath || 'package.json',
                cve,
                cvss: adv.severityScore,
                exploitability: adv.severityLabel === 'CRITICAL' ? 'High' : 'Medium',
                evidence: `OSV.dev live advisory ${adv.id} matched npm dependency ${adv.packageName}@${adv.packageVersion}.`,
                suggestedFix: adv.fixedVersion
                  ? `Upgrade ${adv.packageName} to >= ${adv.fixedVersion}.`
                  : `Review ${adv.id} at https://osv.dev/vulnerability/${adv.id}`,
                confidence: 0.96,
              });
            }
          } catch {
            // Continue gracefully if OSV rate-limited
          }
        }
      }
    }

    if (dockerRaw) {
      const res = executeUnifiedScan({ projectName: projectRow.name, dockerfileContent: dockerRaw });
      combinedFindings.push(...res.findings);
      res.scannersRun.forEach((s) => scannersRun.add(s));
      filesScanned += res.filesScanned;
    }

    tfContents.forEach((tf) => {
      if (!tf) return;
      const res = executeUnifiedScan({ projectName: projectRow.name, terraformContent: tf });
      combinedFindings.push(...res.findings);
      res.scannersRun.forEach((s) => scannersRun.add(s));
      filesScanned += res.filesScanned;
    });

    codeContents.forEach((entry) => {
      if (!entry.content) return;
      const res = executeUnifiedScan({
        projectName: projectRow.name,
        codeContent: entry.content,
        filePath: entry.path,
      });
      combinedFindings.push(...res.findings);
      res.scannersRun.forEach((s) => scannersRun.add(s));
      filesScanned += res.filesScanned;
    });

    let newFindingsInserted = 0;
    for (const f of combinedFindings) {
      const existing = db
        .prepare('SELECT id FROM findings WHERE org_id = ? AND fingerprint = ?')
        .get(authResult.auth.orgId, f.fingerprint);
      if (!existing) {
        newFindingsInserted += 1;
        db.prepare(
          `INSERT INTO findings (id, org_id, project_id, asset_id, fingerprint, title, severity, category, scanner, asset_name, file_path, line, cve, cvss, exploitability, status, evidence, suggested_fix, assigned_owner, discovered_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?)`
        ).run(
          `finding-${crypto.randomUUID().slice(0, 8)}`,
          authResult.auth.orgId,
          projectRow.id,
          assetRow.id,
          f.fingerprint,
          f.title,
          f.severity,
          f.category,
          f.scanner,
          repoUrl,
          f.filePath || null,
          f.line || null,
          f.cve || null,
          f.cvss,
          f.exploitability,
          f.evidence,
          f.suggestedFix,
          projectRow.owner,
          now
        );
      }
    }

    const hasCrit = combinedFindings.some((f) => f.severity === 'CRITICAL');
    const hasHigh = combinedFindings.some((f) => f.severity === 'HIGH');
    const nextProjStatus = hasCrit ? 'critical' : hasHigh ? 'warning' : 'protected';

    db.prepare(
      `UPDATE projects SET last_scanned = ?, status = ?, sbom_json = COALESCE(?, sbom_json) WHERE id = ? AND org_id = ?`
    ).run(now, nextProjStatus, sbomJson, projectRow.id, authResult.auth.orgId);

    const scanId = `scan-${crypto.randomUUID().slice(0, 8)}`;
    db.prepare(
      `INSERT INTO scans (id, org_id, project_id, triggered_by, status, scanners_run, files_scanned, findings_detected, error_message, started_at, completed_at)
       VALUES (?, ?, ?, ?, 'Completed', ?, ?, ?, NULL, ?, ?)`
    ).run(
      scanId,
      authResult.auth.orgId,
      projectRow.id,
      authResult.auth.email,
      JSON.stringify(Array.from(scannersRun)),
      filesScanned,
      combinedFindings.length,
      now,
      new Date().toISOString()
    );

    if (githubToken) {
      db.prepare(
        `UPDATE connectors SET status = 'Connected', health_check = 'Healthy', last_sync = ? WHERE org_id = ? AND provider_key = 'github'`
      ).run(now, authResult.auth.orgId);
    }

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'GITHUB_REPO_SCANNED',
      resourceType: 'Project',
      resourceId: projectRow.id,
      details: `Live scanned GitHub repository ${repoMeta.full_name}@${branch}: ${filesScanned} manifests/files inspected, ${combinedFindings.length} findings (${newFindingsInserted} new).`,
    });

    return jsonOk(
      {
        repository: repoMeta.full_name,
        branch,
        filesInspected: [
          ...(packagePath ? [packagePath] : []),
          ...(dockerfilePath ? [dockerfilePath] : []),
          ...tfPaths,
          ...codePaths,
        ],
        findingsDetected: combinedFindings.length,
        newFindingsInserted,
        scannersRun: Array.from(scannersRun),
        sbomGenerated: Boolean(sbomJson),
        organization: computeOrganizationSnapshot(db, authResult.auth.orgId),
        projects: listProjectsWithStats(db, authResult.auth.orgId),
        findings: listEnrichedFindings(db, authResult.auth.orgId),
      },
      201
    );
  } catch (err) {
    return jsonError(`GitHub live scan failed: ${(err as Error).message}`, 502, 'GITHUB_SCAN_FAILED');
  }
}
