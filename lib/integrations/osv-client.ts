export interface OsvPackageQuery {
  ecosystem: 'npm' | 'PyPI' | 'Go' | 'Maven';
  name: string;
  version: string;
}

export interface OsvMatchedVulnerability {
  id: string;
  aliases: string[];
  summary: string;
  severityScore: number;
  severityLabel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  packageName: string;
  packageVersion: string;
  ecosystem: string;
  fixedVersion?: string;
}

function normalizeVersion(raw: string): string {
  return raw.replace(/^[~^>=<\s]+/, '').trim();
}

export async function queryOsvPackages(
  packages: OsvPackageQuery[]
): Promise<{
  advisories: OsvMatchedVulnerability[];
  queriedCount: number;
}> {
  const cleanPackages = packages
    .map((p) => ({
      ecosystem: p.ecosystem,
      name: p.name.trim(),
      version: normalizeVersion(p.version),
    }))
    .filter((p) => p.name && p.version && p.version !== '*' && p.version !== 'latest')
    .slice(0, 40);

  if (cleanPackages.length === 0) {
    return { advisories: [], queriedCount: 0 };
  }

  const batchRes = await fetch('https://api.osv.dev/v1/querybatch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      queries: cleanPackages.map((p) => ({
        package: { name: p.name, ecosystem: p.ecosystem },
        version: p.version,
      })),
    }),
    signal: AbortSignal.timeout(10_000),
  });

  if (!batchRes.ok) {
    throw new Error(`OSV.dev querybatch returned HTTP ${batchRes.status}`);
  }

  const batchData = (await batchRes.json()) as {
    results?: Array<{ vulns?: Array<{ id: string; modified?: string }> }>;
  };

  const results = batchData.results || [];
  const vulnLookupList: Array<{ id: string; pkg: OsvPackageQuery }> = [];

  results.forEach((res, idx) => {
    const pkg = cleanPackages[idx];
    if (!pkg || !res.vulns) return;
    for (const v of res.vulns.slice(0, 5)) {
      vulnLookupList.push({ id: v.id, pkg });
    }
  });

  // Fetch full details for up to 15 unique advisory IDs to populate real CVEs, summaries, and fix versions
  const uniqueIds = Array.from(new Set(vulnLookupList.map((v) => v.id))).slice(0, 15);
  const detailsMap = new Map<
    string,
    {
      summary?: string;
      aliases?: string[];
      fixed?: string;
      severityScore: number;
      severityLabel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
    }
  >();

  await Promise.all(
    uniqueIds.map(async (vulnId) => {
      try {
        const dRes = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(vulnId)}`, {
          signal: AbortSignal.timeout(6000),
        });
        if (!dRes.ok) return;
        const d = (await dRes.json()) as {
          summary?: string;
          details?: string;
          aliases?: string[];
          database_specific?: { severity?: string };
          affected?: Array<{
            ranges?: Array<{ events?: Array<{ fixed?: string }> }>;
          }>;
        };

        let fixed: string | undefined;
        for (const aff of d.affected || []) {
          for (const rng of aff.ranges || []) {
            for (const ev of rng.events || []) {
              if (ev.fixed) {
                fixed = ev.fixed;
                break;
              }
            }
            if (fixed) break;
          }
          if (fixed) break;
        }

        const rawSev = (d.database_specific?.severity || '').toUpperCase();
        const severityLabel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' =
          rawSev === 'CRITICAL'
            ? 'CRITICAL'
            : rawSev === 'HIGH'
            ? 'HIGH'
            : rawSev === 'LOW'
            ? 'LOW'
            : 'MEDIUM';
        const severityScore =
          severityLabel === 'CRITICAL' ? 9.3 : severityLabel === 'HIGH' ? 7.8 : severityLabel === 'MEDIUM' ? 5.9 : 3.5;

        detailsMap.set(vulnId, {
          summary: d.summary || d.details?.slice(0, 180) || `Open-source advisory ${vulnId}`,
          aliases: d.aliases || [],
          fixed,
          severityScore,
          severityLabel,
        });
      } catch {
        // Fallback if individual advisory fetch fails
      }
    })
  );

  const advisories: OsvMatchedVulnerability[] = vulnLookupList.map(({ id, pkg }) => {
    const info = detailsMap.get(id);
    return {
      id,
      aliases: info?.aliases || [],
      summary: info?.summary || `Vulnerability ${id} affecting ${pkg.name}@${pkg.version}`,
      severityScore: info?.severityScore ?? 7.5,
      severityLabel: info?.severityLabel ?? 'HIGH',
      packageName: pkg.name,
      packageVersion: pkg.version,
      ecosystem: pkg.ecosystem,
      fixedVersion: info?.fixed,
    };
  });

  return { advisories, queriedCount: cleanPackages.length };
}
