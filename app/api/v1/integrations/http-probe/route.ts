import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { assertSafeExternalUrl, fetchWithSafeRedirects } from '@/lib/security/ssrf';
import { inspectTlsCertificate, type TlsInspectionResult } from '@/lib/integrations/tls-inspector';
import { computeOrganizationSnapshot, listEnrichedFindings } from '@/lib/domain-mappers';

const HttpProbeSchema = z.object({
  targetUrl: z.string().min(8).max(400),
  projectId: z.string().optional(),
  persistFindings: z.boolean().default(true),
});

interface HeaderFindingSpec {
  key: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cvss: number;
  evidence: string;
  suggestedFix: string;
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

  const parsed = HttpProbeSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid HTTP probe request.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  let initialSafeUrl: URL;
  try {
    initialSafeUrl = await assertSafeExternalUrl(parsed.data.targetUrl);
  } catch (err) {
    return jsonError((err as Error).message, 400, 'SSRF_BLOCKED');
  }

  const db = getDb();
  let projectId: string | null = null;
  let owner = authResult.auth.name;
  if (parsed.data.projectId) {
    const p = db
      .prepare('SELECT id, owner FROM projects WHERE id = ? AND org_id = ?')
      .get(parsed.data.projectId, authResult.auth.orgId) as { id: string; owner: string } | undefined;
    if (!p) return jsonError('Project not found in your organization.', 404, 'PROJECT_NOT_FOUND');
    projectId = p.id;
    owner = p.owner;
  }

  try {
    const started = Date.now();
    const { response: probeRes, finalUrl: safeUrl, redirectCount } = await fetchWithSafeRedirects(
      initialSafeUrl.toString(),
      {
        method: 'GET',
        headers: {
          'User-Agent': 'Trustrail-Security-Scanner/1.0',
          Accept: 'text/html,application/json;q=0.9,*/*;q=0.8',
        },
        signal: AbortSignal.timeout(8000),
      },
      { maxRedirects: 3 }
    );
    const latencyMs = Date.now() - started;

    const tlsInspection: TlsInspectionResult | null =
      safeUrl.protocol === 'https:'
        ? await inspectTlsCertificate(
            safeUrl.hostname,
            safeUrl.port ? Number.parseInt(safeUrl.port, 10) : 443
          )
        : null;

    const headersObj: Record<string, string> = {};
    probeRes.headers.forEach((value, key) => {
      headersObj[key.toLowerCase()] = value;
    });

    const detectedIssues: HeaderFindingSpec[] = [];

    if (safeUrl.protocol === 'http:') {
      detectedIssues.push({
        key: 'CLEARTEXT_HTTP',
        title: `Unencrypted HTTP Endpoint Exposed (${safeUrl.hostname})`,
        severity: 'HIGH',
        cvss: 7.4,
        evidence: `Endpoint ${safeUrl.origin} responded over plaintext HTTP without enforcing HTTPS.`,
        suggestedFix: 'Terminate TLS 1.3 at the edge and issue a 301 redirect from HTTP to HTTPS.',
      });
    } else {
      if (tlsInspection?.inspected && !tlsInspection.valid) {
        detectedIssues.push({
          key: 'INVALID_TLS_CERT',
          title: `Untrusted or Invalid TLS Certificate on ${safeUrl.hostname}`,
          severity: 'HIGH',
          cvss: 7.5,
          evidence: `TLS handshake reported authorization error: ${tlsInspection.authorizationError || 'untrusted chain'} (issuer=${tlsInspection.issuer || 'unknown'}).`,
          suggestedFix: 'Provision a valid CA-signed TLS certificate matching the exact hostname SAN.',
        });
      }
      if (tlsInspection?.inspected && tlsInspection.daysRemaining !== null && tlsInspection.daysRemaining < 14) {
        detectedIssues.push({
          key: 'EXPIRING_TLS_CERT',
          title: `TLS Certificate Expiring Soon (${tlsInspection.daysRemaining}d remaining) on ${safeUrl.hostname}`,
          severity: 'MEDIUM',
          cvss: 5.3,
          evidence: `Certificate validTo="${tlsInspection.validTo}" expires in ${tlsInspection.daysRemaining} days.`,
          suggestedFix: 'Renew TLS certificate immediately and automate ACME/Certbot renewal.',
        });
      }
      if (tlsInspection?.protocol && /^(TLSv1|TLSv1\.1|SSLv3)$/i.test(tlsInspection.protocol)) {
        detectedIssues.push({
          key: 'WEAK_TLS_PROTOCOL',
          title: `Deprecated TLS Protocol Negotiated (${tlsInspection.protocol}) on ${safeUrl.hostname}`,
          severity: 'HIGH',
          cvss: 7.4,
          evidence: `Server negotiated legacy protocol ${tlsInspection.protocol}.`,
          suggestedFix: 'Disable TLS 1.0/1.1 and enforce TLS 1.2+ / TLS 1.3.',
        });
      }
      if (!headersObj['strict-transport-security']) {
        detectedIssues.push({
          key: 'MISSING_HSTS',
          title: `Missing Strict-Transport-Security (HSTS) Header on ${safeUrl.hostname}`,
          severity: 'MEDIUM',
          cvss: 5.9,
          evidence: `${safeUrl.origin}${safeUrl.pathname} returned HTTP ${probeRes.status} without Strict-Transport-Security.`,
          suggestedFix: 'Add "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload".',
        });
      }
    }

    if (!headersObj['content-security-policy']) {
      detectedIssues.push({
        key: 'MISSING_CSP',
        title: `Missing Content-Security-Policy Header on ${safeUrl.hostname}`,
        severity: 'MEDIUM',
        cvss: 5.4,
        evidence: `Response headers lack Content-Security-Policy, increasing XSS and script injection blast radius.`,
        suggestedFix: 'Configure a restrictive Content-Security-Policy with nonce-based script execution.',
      });
    }

    if (headersObj['x-content-type-options']?.toLowerCase() !== 'nosniff') {
      detectedIssues.push({
        key: 'MISSING_NOSNIFF',
        title: `Missing X-Content-Type-Options: nosniff on ${safeUrl.hostname}`,
        severity: 'LOW',
        cvss: 3.7,
        evidence: `Header X-Content-Type-Options is "${headersObj['x-content-type-options'] || 'absent'}".`,
        suggestedFix: 'Set "X-Content-Type-Options: nosniff" on all HTTP responses.',
      });
    }

    if (
      headersObj['access-control-allow-origin'] === '*' &&
      headersObj['access-control-allow-credentials']?.toLowerCase() === 'true'
    ) {
      detectedIssues.push({
        key: 'INSECURE_CORS_WILDCARD',
        title: `Wildcard CORS with Credentials Enabled on ${safeUrl.hostname}`,
        severity: 'CRITICAL',
        cvss: 9.1,
        evidence: `Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.`,
        suggestedFix: 'Replace wildcard origin with an explicit allowlist of trusted application domains.',
      });
    } else if (headersObj['access-control-allow-origin'] === '*') {
      detectedIssues.push({
        key: 'PERMISSIVE_CORS',
        title: `Permissive Wildcard CORS Policy (Access-Control-Allow-Origin: *) on ${safeUrl.hostname}`,
        severity: 'LOW',
        cvss: 4.3,
        evidence: `Endpoint returned Access-Control-Allow-Origin: *. Verify endpoint contains no tenant-private data.`,
        suggestedFix: 'Restrict Access-Control-Allow-Origin to explicit trusted origins.',
      });
    }

    if (headersObj['x-powered-by'] || (headersObj['server'] && /\d+\.\d+/.test(headersObj['server']))) {
      detectedIssues.push({
        key: 'SERVER_BANNER_EXPOSURE',
        title: `Verbose Server Technology Fingerprinting Exposed (${safeUrl.hostname})`,
        severity: 'LOW',
        cvss: 3.1,
        evidence: `Exposed headers: server="${headersObj['server'] || ''}" x-powered-by="${headersObj['x-powered-by'] || ''}".`,
        suggestedFix: 'Strip versioned Server and X-Powered-By response headers at reverse proxy.',
      });
    }

    const now = new Date().toISOString();
    const endpointName = `${safeUrl.origin}${safeUrl.pathname}`;
    let assetRow = db
      .prepare(`SELECT id FROM assets WHERE org_id = ? AND name = ? LIMIT 1`)
      .get(authResult.auth.orgId, endpointName) as { id: string } | undefined;

    if (!assetRow) {
      const newAssetId = `asset-${crypto.randomUUID().slice(0, 8)}`;
      db.prepare(
        `INSERT INTO assets (id, org_id, project_id, name, asset_type, owner, internet_exposed, criticality, created_at)
         VALUES (?, ?, ?, ?, 'API Endpoint', ?, 1, 'HIGH', ?)`
      ).run(newAssetId, authResult.auth.orgId, projectId, endpointName, owner, now);
      assetRow = { id: newAssetId };
    }

    let newFindingsInserted = 0;
    if (parsed.data.persistFindings) {
      for (const issue of detectedIssues) {
        const fp = crypto
          .createHash('sha256')
          .update(`http_probe|${safeUrl.origin}${safeUrl.pathname}|${issue.key}`)
          .digest('hex')
          .slice(0, 16);

        const existing = db
          .prepare('SELECT id FROM findings WHERE org_id = ? AND fingerprint = ?')
          .get(authResult.auth.orgId, fp);

        if (!existing) {
          newFindingsInserted += 1;
          db.prepare(
            `INSERT INTO findings (id, org_id, project_id, asset_id, fingerprint, title, severity, category, scanner, asset_name, file_path, line, cve, cvss, exploitability, status, evidence, suggested_fix, assigned_owner, discovered_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'API', 'trustrail-http-tls-probe', ?, ?, NULL, NULL, ?, ?, 'Open', ?, ?, ?, ?)`
          ).run(
            `finding-${crypto.randomUUID().slice(0, 8)}`,
            authResult.auth.orgId,
            projectId,
            assetRow.id,
            fp,
            issue.title,
            issue.severity,
            endpointName,
            safeUrl.pathname || '/',
            issue.cvss,
            issue.severity === 'CRITICAL' ? 'High' : 'Medium',
            issue.evidence,
            issue.suggestedFix,
            owner,
            now
          );
        }
      }
    }

    db.prepare(
      `UPDATE connectors SET status = 'Connected', availability_state = 'AVAILABLE', health_check = 'Healthy', last_sync = ? WHERE org_id = ? AND provider_key = 'http_probe'`
    ).run(now, authResult.auth.orgId);

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'HTTP_ENDPOINT_PROBED',
      resourceType: 'Asset',
      resourceId: assetRow.id,
      details: `Probed ${endpointName} (HTTP ${probeRes.status}, ${latencyMs}ms, redirects=${redirectCount}): ${detectedIssues.length} header/TLS findings (${newFindingsInserted} new).`,
    });

    return jsonOk({
      targetUrl: endpointName,
      httpStatus: probeRes.status,
      latencyMs,
      redirectCount,
      httpsEnforced: safeUrl.protocol === 'https:',
      tlsInspection,
      securityHeaders: {
        strictTransportSecurity: headersObj['strict-transport-security'] || null,
        contentSecurityPolicy: headersObj['content-security-policy'] || null,
        xContentTypeOptions: headersObj['x-content-type-options'] || null,
        xFrameOptions: headersObj['x-frame-options'] || null,
        referrerPolicy: headersObj['referrer-policy'] || null,
        accessControlAllowOrigin: headersObj['access-control-allow-origin'] || null,
        server: headersObj['server'] || null,
      },
      issuesDetected: detectedIssues,
      newFindingsInserted,
      organization: computeOrganizationSnapshot(db, authResult.auth.orgId),
      findings: listEnrichedFindings(db, authResult.auth.orgId),
    });
  } catch (err) {
    return jsonError(`HTTP endpoint probe failed: ${(err as Error).message}`, 502, 'HTTP_PROBE_FAILED');
  }
}

