import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { queryOsvPackages, OsvPackageQuery } from '@/lib/integrations/osv-client';
import { computeOrganizationSnapshot, listEnrichedFindings } from '@/lib/domain-mappers';

const OsvQuerySchema = z.object({
  projectId: z.string().optional(),
  persistFindings: z.boolean().default(true),
  packages: z
    .array(
      z.object({
        ecosystem: z.enum(['npm', 'PyPI', 'Go', 'Maven']).default('npm'),
        name: z.string().min(1).max(150),
        version: z.string().min(1).max(60),
      })
    )
    .max(40)
    .optional(),
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

  const parsed = OsvQuerySchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid OSV query payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  let projectRow: { id: string; name: string; repo_url: string; owner: string; sbom_json: string | null } | undefined;

  if (parsed.data.projectId) {
    projectRow = db
      .prepare('SELECT id, name, repo_url, owner, sbom_json FROM projects WHERE id = ? AND org_id = ?')
      .get(parsed.data.projectId, authResult.auth.orgId) as
      | { id: string; name: string; repo_url: string; owner: string; sbom_json: string | null }
      | undefined;
    if (!projectRow) {
      return jsonError('Project not found in your organization.', 404, 'PROJECT_NOT_FOUND');
    }
  }

  let queries: OsvPackageQuery[] = parsed.data.packages || [];
  if (queries.length === 0 && projectRow?.sbom_json) {
    try {
      const sbom = JSON.parse(projectRow.sbom_json) as {
        components?: Array<{ name: string; version: string; purl?: string }>;
      };
      queries = (sbom.components || []).map((c) => ({
        ecosystem: c.purl?.startsWith('pkg:pypi/') ? 'PyPI' : c.purl?.startsWith('pkg:golang/') ? 'Go' : 'npm',
        name: c.name,
        version: c.version,
      }));
    } catch {
      queries = [];
    }
  }

  if (queries.length === 0) {
    return jsonError(
      'Provide at least one package (name + version) or select a project with a generated CycloneDX SBOM.',
      400,
      'NO_PACKAGES'
    );
  }

  try {
    const { advisories, queriedCount } = await queryOsvPackages(queries);
    const now = new Date().toISOString();

    let newFindingsInserted = 0;
    if (parsed.data.persistFindings && advisories.length > 0) {
      let assetId: string | null = null;
      if (projectRow) {
        const assetRow = db
          .prepare('SELECT id FROM assets WHERE project_id = ? AND org_id = ? LIMIT 1')
          .get(projectRow.id, authResult.auth.orgId) as { id: string } | undefined;
        assetId = assetRow?.id || null;
      }

      for (const adv of advisories) {
        const cve = adv.aliases.find((a) => a.startsWith('CVE-')) || adv.id;
        const fp = crypto
          .createHash('sha256')
          .update(`osv|${projectRow?.id || 'ad-hoc'}|${adv.ecosystem}|${adv.packageName}|${adv.packageVersion}|${adv.id}`)
          .digest('hex')
          .slice(0, 16);

        const existing = db
          .prepare('SELECT id FROM findings WHERE org_id = ? AND fingerprint = ?')
          .get(authResult.auth.orgId, fp) as { id: string } | undefined;

        if (!existing) {
          newFindingsInserted += 1;
          db.prepare(
            `INSERT INTO findings (id, org_id, project_id, asset_id, fingerprint, title, severity, category, scanner, asset_name, file_path, line, cve, cvss, exploitability, status, evidence, suggested_fix, assigned_owner, discovered_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'SCA', 'osv-dev-live-feed', ?, 'package.json', NULL, ?, ?, ?, 'Open', ?, ?, ?, ?)`
          ).run(
            `finding-${crypto.randomUUID().slice(0, 8)}`,
            authResult.auth.orgId,
            projectRow?.id || null,
            assetId,
            fp,
            `${adv.packageName}@${adv.packageVersion}: ${adv.summary.slice(0, 110)}`,
            adv.severityLabel,
            projectRow?.repo_url || `${adv.ecosystem}:${adv.packageName}`,
            cve,
            adv.severityScore,
            adv.severityLabel === 'CRITICAL' ? 'High' : 'Medium',
            `OSV.dev advisory ${adv.id} (${adv.aliases.join(', ') || 'no aliases'}) affects ${adv.ecosystem} package ${adv.packageName}@${adv.packageVersion}.`,
            adv.fixedVersion
              ? `Upgrade ${adv.packageName} to >= ${adv.fixedVersion} to remediate ${cve}.`
              : `Review ${adv.id} on https://osv.dev/vulnerability/${adv.id} and apply vendor patch.`,
            projectRow?.owner || authResult.auth.name,
            now
          );
        }
      }
    }

    db.prepare(
      `UPDATE connectors SET status = 'Connected', health_check = 'Healthy', last_sync = ? WHERE org_id = ? AND provider_key = 'osv'`
    ).run(now, authResult.auth.orgId);

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'OSV_CVE_SYNC',
      resourceType: 'Integration',
      resourceId: 'osv',
      details: `Queried OSV.dev live API for ${queriedCount} package(s): ${advisories.length} advisories returned, ${newFindingsInserted} new findings stored.`,
    });

    return jsonOk({
      source: 'https://api.osv.dev/v1/querybatch',
      queriedCount,
      advisoriesCount: advisories.length,
      newFindingsInserted,
      advisories,
      organization: computeOrganizationSnapshot(db, authResult.auth.orgId),
      findings: listEnrichedFindings(db, authResult.auth.orgId),
    });
  } catch (err) {
    return jsonError(`OSV.dev query failed: ${(err as Error).message}`, 502, 'EXTERNAL_API_ERROR');
  }
}
