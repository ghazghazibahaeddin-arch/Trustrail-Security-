import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { inspectOciImage } from '@/lib/integrations/oci-client';
import { scanContainerDockerfile } from '@/lib/engines/scanner-engine';
import { computeOrganizationSnapshot } from '@/lib/domain-mappers';

const OciInspectSchema = z.object({
  image: z.string().min(2).max(240),
  dockerfileContent: z.string().max(100_000).optional(),
  persistFindings: z.boolean().default(true),
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

  const parsed = OciInspectSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid OCI image inspection request.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const now = new Date().toISOString();

  try {
    const manifest = await inspectOciImage(parsed.data.image);
    const findings = parsed.data.dockerfileContent
      ? scanContainerDockerfile(parsed.data.dockerfileContent, parsed.data.image)
      : [];

    if (!manifest.pinnedByDigest) {
      findings.push({
        fingerprint: crypto
          .createHash('sha256')
          .update(`OCI|UNPINNED_DIGEST|${parsed.data.image}`)
          .digest('hex')
          .slice(0, 16),
        title: `Container Image Reference "${parsed.data.image}" Not Pinned to Immutable SHA256 Digest`,
        severity: 'MEDIUM',
        category: 'CONTAINER',
        scanner: 'trustrail-oci-registry-inspector',
        filePath: 'Dockerfile',
        cvss: 5.5,
        exploitability: 'Low',
        evidence: `Resolved tag "${manifest.reference}" on ${manifest.registry}/${manifest.repository} -> digest ${manifest.digest || 'unknown'}. Mutable tags can be overwritten upstream.`,
        suggestedFix: manifest.digest
          ? `Pin image reference to ${manifest.repository}@${manifest.digest}`
          : 'Pin container reference to @sha256:... immutable digest.',
        confidence: 0.98,
      });
    }

    let newFindingsInserted = 0;
    if (parsed.data.persistFindings) {
      for (const f of findings) {
        const existing = db
          .prepare('SELECT id FROM findings WHERE org_id = ? AND fingerprint = ?')
          .get(authResult.auth.orgId, f.fingerprint);
        if (!existing) {
          newFindingsInserted += 1;
          db.prepare(
            `INSERT INTO findings (id, org_id, project_id, asset_id, fingerprint, title, severity, category, scanner, asset_name, file_path, line, cve, cvss, exploitability, status, evidence, suggested_fix, assigned_owner, discovered_at)
             VALUES (?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, 'Open', ?, ?, ?, ?)`
          ).run(
            `finding-${crypto.randomUUID().slice(0, 8)}`,
            authResult.auth.orgId,
            f.fingerprint,
            f.title,
            f.severity,
            f.category,
            f.scanner,
            parsed.data.image,
            f.filePath || 'Dockerfile',
            f.cvss,
            f.exploitability,
            f.evidence,
            f.suggestedFix,
            authResult.auth.name,
            now
          );
        }
      }
    }

    db.prepare(
      `UPDATE connectors SET status = 'Connected', availability_state = 'AVAILABLE', health_check = 'Healthy', last_sync = ? WHERE org_id = ? AND provider_key = 'oci'`
    ).run(now, authResult.auth.orgId);

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'OCI_IMAGE_INSPECTED',
      resourceType: 'ContainerImage',
      resourceId: parsed.data.image,
      details: `Inspected OCI manifest for ${parsed.data.image} (digest=${manifest.digest || 'n/a'}, layers=${manifest.layersCount}, findings=${findings.length}).`,
    });

    return jsonOk({
      manifest,
      findingsDetected: findings,
      newFindingsInserted,
      organization: computeOrganizationSnapshot(db, authResult.auth.orgId),
    });
  } catch (err) {
    return jsonError(`OCI registry inspection failed: ${(err as Error).message}`, 502, 'OCI_INSPECT_FAILED');
  }
}
