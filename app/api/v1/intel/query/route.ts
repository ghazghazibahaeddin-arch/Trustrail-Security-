import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { queryMultiSourceVulnerabilityIntel } from '@/lib/integrations/intel-aggregator';
import { listEnrichedFindings } from '@/lib/domain-mappers';

const IntelQuerySchema = z.object({
  cveIds: z.array(z.string().min(4).max(32)).max(10).optional(),
  packages: z
    .array(
      z.object({
        ecosystem: z.enum(['npm', 'PyPI', 'Go', 'Maven']),
        name: z.string().min(1).max(160),
        version: z.string().min(1).max(60),
      })
    )
    .max(25)
    .optional(),
  forceRefresh: z.boolean().default(false),
});

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer', 'read');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const rows = db
    .prepare(
      `SELECT id, cve_id as cveId, source, source_url as sourceUrl, kev_listed as kevListed,
              kev_due_date as kevDueDate, epss_score as epssScore, epss_percentile as epssPercentile,
              cvss_score as cvssScore, retrieved_at as retrievedAt, expires_at as expiresAt
       FROM vulnerability_intel ORDER BY retrieved_at DESC LIMIT 100`
    )
    .all() as Array<Record<string, unknown>>;

  return jsonOk({
    records: rows.map((r) => ({ ...r, kevListed: Boolean(r.kevListed) })),
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

  const parsed = IntelQuerySchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid vulnerability intelligence query.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const result = await queryMultiSourceVulnerabilityIntel(db, {
    cveIds: parsed.data.cveIds,
    packages: parsed.data.packages,
    forceRefresh: parsed.data.forceRefresh,
  });

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'VULNERABILITY_INTEL_ENRICHED',
    resourceType: 'ThreatIntel',
    resourceId: (parsed.data.cveIds || ['packages']).join(',').slice(0, 60),
    details: `Aggregated OSV/NVD/KEV/EPSS intel for ${result.cveResults.length} CVE(s) and ${result.osvQueried} package(s).`,
  });

  return jsonOk({
    ...result,
    findings: listEnrichedFindings(db, authResult.auth.orgId),
  });
}
