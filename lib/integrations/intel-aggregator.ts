import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { queryOsvPackages, type OsvPackageQuery } from '@/lib/integrations/osv-client';

export interface UnifiedVulnerabilityIntel {
  cveId: string;
  kevListed: boolean;
  kevDueDate?: string | null;
  kevVendorProject?: string | null;
  kevShortDescription?: string | null;
  epssScore: number | null;
  epssPercentile: number | null;
  cvssScore: number | null;
  cwes: string[];
  fixedVersions: string[];
  sources: Array<{ source: 'OSV' | 'NVD' | 'KEV' | 'EPSS' | 'GHSA'; url: string; retrievedAt: string }>;
  cached: boolean;
}

let kevMemoryCache: { fetchedAt: number; entries: Map<string, { dueDate?: string; vendorProject?: string; shortDescription?: string }> } | null = null;

async function fetchCisaKevCatalog(): Promise<Map<string, { dueDate?: string; vendorProject?: string; shortDescription?: string }>> {
  const nowMs = Date.now();
  if (kevMemoryCache && nowMs - kevMemoryCache.fetchedAt < 6 * 3600_000) {
    return kevMemoryCache.entries;
  }

  const map = new Map<string, { dueDate?: string; vendorProject?: string; shortDescription?: string }>();
  try {
    const res = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { signal: AbortSignal.timeout(7000) }
    );
    if (res.ok) {
      const json = (await res.json()) as {
        vulnerabilities?: Array<{
          cveID?: string;
          dueDate?: string;
          vendorProject?: string;
          shortDescription?: string;
        }>;
      };
      for (const v of json.vulnerabilities || []) {
        if (v.cveID) {
          map.set(v.cveID.toUpperCase(), {
            dueDate: v.dueDate,
            vendorProject: v.vendorProject,
            shortDescription: v.shortDescription,
          });
        }
      }
      kevMemoryCache = { fetchedAt: nowMs, entries: map };
    }
  } catch {
    // Graceful fallback to empty or cached DB records if network unavailable
  }
  return map;
}

async function fetchFirstEpss(cveId: string): Promise<{ epss: number | null; percentile: number | null }> {
  try {
    const res = await fetch(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cveId)}`, {
      signal: AbortSignal.timeout(6000),
    });
    if (!res.ok) return { epss: null, percentile: null };
    const json = (await res.json()) as {
      data?: Array<{ cve?: string; epss?: string; percentile?: string }>;
    };
    const item = json.data?.[0];
    if (!item) return { epss: null, percentile: null };
    return {
      epss: item.epss !== undefined ? Number(item.epss) : null,
      percentile: item.percentile !== undefined ? Number(item.percentile) : null,
    };
  } catch {
    return { epss: null, percentile: null };
  }
}

async function fetchNvdCve(cveId: string): Promise<{ cvssScore: number | null; cwes: string[]; summary?: string }> {
  try {
    const headers: Record<string, string> = { 'User-Agent': 'Trustrail-Security-Cloud' };
    if (process.env.NVD_API_KEY) {
      headers.apiKey = process.env.NVD_API_KEY;
    }
    const res = await fetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`, {
      headers,
      signal: AbortSignal.timeout(7000),
    });
    if (!res.ok) return { cvssScore: null, cwes: [] };
    const json = (await res.json()) as {
      vulnerabilities?: Array<{
        cve?: {
          descriptions?: Array<{ lang?: string; value?: string }>;
          weaknesses?: Array<{ description?: Array<{ value?: string }> }>;
          metrics?: {
            cvssMetricV31?: Array<{ cvssData?: { baseScore?: number } }>;
            cvssMetricV30?: Array<{ cvssData?: { baseScore?: number } }>;
          };
        };
      }>;
    };
    const cve = json.vulnerabilities?.[0]?.cve;
    if (!cve) return { cvssScore: null, cwes: [] };
    const cvssScore =
      cve.metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore ??
      cve.metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore ??
      null;
    const cwes = (cve.weaknesses || [])
      .flatMap((w) => (w.description || []).map((d) => d.value || ''))
      .filter((x) => x.startsWith('CWE-'));
    const summary = cve.descriptions?.find((d) => d.lang === 'en')?.value;
    return { cvssScore, cwes: Array.from(new Set(cwes)), summary };
  } catch {
    return { cvssScore: null, cwes: [] };
  }
}

export function upsertVulnerabilityIntelRecord(
  db: DatabaseSync,
  record: {
    cveId: string;
    source: 'OSV' | 'NVD' | 'KEV' | 'EPSS' | 'GHSA';
    sourceUrl?: string;
    kevListed?: boolean;
    kevDueDate?: string | null;
    epssScore?: number | null;
    epssPercentile?: number | null;
    cvssScore?: number | null;
    cwes?: string[];
    fixedVersions?: string[];
    raw?: unknown;
    ttlHours?: number;
  }
): void {
  const now = new Date();
  const expires = new Date(now.getTime() + (record.ttlHours ?? 12) * 3600_000);
  const normalizedCve = record.cveId.toUpperCase();
  const existing = db
    .prepare('SELECT id FROM vulnerability_intel WHERE cve_id = ? AND source = ?')
    .get(normalizedCve, record.source) as { id: string } | undefined;

  if (existing) {
    db.prepare(
      `UPDATE vulnerability_intel
       SET source_url = ?, kev_listed = ?, kev_due_date = ?, epss_score = ?, epss_percentile = ?,
           cvss_score = ?, cwes_json = ?, fixed_versions_json = ?, raw_json = ?, retrieved_at = ?, expires_at = ?
       WHERE id = ?`
    ).run(
      record.sourceUrl || null,
      record.kevListed ? 1 : 0,
      record.kevDueDate || null,
      record.epssScore ?? null,
      record.epssPercentile ?? null,
      record.cvssScore ?? null,
      JSON.stringify(record.cwes || []),
      JSON.stringify(record.fixedVersions || []),
      record.raw ? JSON.stringify(record.raw).slice(0, 12_000) : null,
      now.toISOString(),
      expires.toISOString(),
      existing.id
    );
  } else {
    db.prepare(
      `INSERT INTO vulnerability_intel
       (id, cve_id, source, source_url, kev_listed, kev_due_date, epss_score, epss_percentile, cvss_score, cwes_json, fixed_versions_json, raw_json, retrieved_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      `intel-${crypto.randomUUID().slice(0, 8)}`,
      normalizedCve,
      record.source,
      record.sourceUrl || null,
      record.kevListed ? 1 : 0,
      record.kevDueDate || null,
      record.epssScore ?? null,
      record.epssPercentile ?? null,
      record.cvssScore ?? null,
      JSON.stringify(record.cwes || []),
      JSON.stringify(record.fixedVersions || []),
      record.raw ? JSON.stringify(record.raw).slice(0, 12_000) : null,
      now.toISOString(),
      expires.toISOString()
    );
  }
}

export function getCachedCveIntel(db: DatabaseSync, cveId: string): UnifiedVulnerabilityIntel | null {
  const rows = db
    .prepare(
      `SELECT cve_id, source, source_url, kev_listed, kev_due_date, epss_score, epss_percentile, cvss_score, cwes_json, fixed_versions_json, retrieved_at
       FROM vulnerability_intel WHERE cve_id = ?`
    )
    .all(cveId.toUpperCase()) as Array<{
    cve_id: string;
    source: 'OSV' | 'NVD' | 'KEV' | 'EPSS' | 'GHSA';
    source_url: string | null;
    kev_listed: number;
    kev_due_date: string | null;
    epss_score: number | null;
    epss_percentile: number | null;
    cvss_score: number | null;
    cwes_json: string;
    fixed_versions_json: string;
    retrieved_at: string;
  }>;

  if (rows.length === 0) return null;

  let kevListed = false;
  let kevDueDate: string | null = null;
  let epssScore: number | null = null;
  let epssPercentile: number | null = null;
  let cvssScore: number | null = null;
  const cwes = new Set<string>();
  const fixedVersions = new Set<string>();
  const sources: UnifiedVulnerabilityIntel['sources'] = [];

  for (const r of rows) {
    if (r.kev_listed) {
      kevListed = true;
      kevDueDate = r.kev_due_date;
    }
    if (r.epss_score !== null) epssScore = r.epss_score;
    if (r.epss_percentile !== null) epssPercentile = r.epss_percentile;
    if (r.cvss_score !== null) cvssScore = Math.max(cvssScore ?? 0, r.cvss_score);
    for (const c of JSON.parse(r.cwes_json || '[]') as string[]) cwes.add(c);
    for (const f of JSON.parse(r.fixed_versions_json || '[]') as string[]) fixedVersions.add(f);
    sources.push({
      source: r.source,
      url: r.source_url || `https://nvd.nist.gov/vuln/detail/${r.cve_id}`,
      retrievedAt: r.retrieved_at,
    });
  }

  return {
    cveId: cveId.toUpperCase(),
    kevListed,
    kevDueDate,
    epssScore,
    epssPercentile,
    cvssScore,
    cwes: Array.from(cwes),
    fixedVersions: Array.from(fixedVersions),
    sources,
    cached: true,
  };
}

export async function enrichCveIntelligence(
  db: DatabaseSync,
  cveId: string,
  forceRefresh = false
): Promise<UnifiedVulnerabilityIntel> {
  const normalized = cveId.trim().toUpperCase();
  if (!forceRefresh) {
    const existing = db
      .prepare('SELECT expires_at FROM vulnerability_intel WHERE cve_id = ? LIMIT 1')
      .get(normalized) as { expires_at: string } | undefined;
    if (existing && new Date(existing.expires_at).getTime() > Date.now()) {
      const cached = getCachedCveIntel(db, normalized);
      if (cached) return cached;
    }
  }

  const [kevMap, epssData, nvdData] = await Promise.all([
    fetchCisaKevCatalog(),
    fetchFirstEpss(normalized),
    fetchNvdCve(normalized),
  ]);

  const kevEntry = kevMap.get(normalized);
  if (kevEntry || kevMap.size > 0) {
    upsertVulnerabilityIntelRecord(db, {
      cveId: normalized,
      source: 'KEV',
      sourceUrl: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
      kevListed: Boolean(kevEntry),
      kevDueDate: kevEntry?.dueDate || null,
      raw: kevEntry || { listed: false },
    });
  }

  if (epssData.epss !== null) {
    upsertVulnerabilityIntelRecord(db, {
      cveId: normalized,
      source: 'EPSS',
      sourceUrl: `https://api.first.org/data/v1/epss?cve=${normalized}`,
      epssScore: epssData.epss,
      epssPercentile: epssData.percentile,
      raw: epssData,
    });
  }

  if (nvdData.cvssScore !== null || nvdData.cwes.length > 0) {
    upsertVulnerabilityIntelRecord(db, {
      cveId: normalized,
      source: 'NVD',
      sourceUrl: `https://nvd.nist.gov/vuln/detail/${normalized}`,
      cvssScore: nvdData.cvssScore,
      cwes: nvdData.cwes,
      raw: nvdData,
    });
  }

  const aggregated = getCachedCveIntel(db, normalized);
  return (
    aggregated || {
      cveId: normalized,
      kevListed: Boolean(kevEntry),
      kevDueDate: kevEntry?.dueDate || null,
      kevVendorProject: kevEntry?.vendorProject || null,
      kevShortDescription: kevEntry?.shortDescription || null,
      epssScore: epssData.epss,
      epssPercentile: epssData.percentile,
      cvssScore: nvdData.cvssScore,
      cwes: nvdData.cwes,
      fixedVersions: [],
      sources: [],
      cached: false,
    }
  );
}

export async function queryMultiSourceVulnerabilityIntel(
  db: DatabaseSync,
  input: { cveIds?: string[]; packages?: OsvPackageQuery[]; forceRefresh?: boolean }
) {
  const cveResults: UnifiedVulnerabilityIntel[] = [];
  const cveList = Array.from(new Set((input.cveIds || []).map((c) => c.trim().toUpperCase()).filter(Boolean))).slice(0, 10);

  for (const cve of cveList) {
    cveResults.push(await enrichCveIntelligence(db, cve, Boolean(input.forceRefresh)));
  }

  let osvAdvisories: Awaited<ReturnType<typeof queryOsvPackages>>['advisories'] = [];
  let osvQueried = 0;
  if (input.packages && input.packages.length > 0) {
    try {
      const osv = await queryOsvPackages(input.packages);
      osvAdvisories = osv.advisories;
      osvQueried = osv.queriedCount;
      for (const adv of osv.advisories) {
        const cve = adv.aliases.find((a) => a.startsWith('CVE-')) || adv.id;
        upsertVulnerabilityIntelRecord(db, {
          cveId: cve,
          source: adv.id.startsWith('GHSA-') ? 'GHSA' : 'OSV',
          sourceUrl: `https://osv.dev/vulnerability/${adv.id}`,
          cvssScore: adv.severityScore,
          fixedVersions: adv.fixedVersion ? [adv.fixedVersion] : [],
          raw: adv,
        });
      }
    } catch {
      // Non-fatal if OSV unreachable
    }
  }

  return {
    cveResults,
    osvQueried,
    osvAdvisories,
  };
}
