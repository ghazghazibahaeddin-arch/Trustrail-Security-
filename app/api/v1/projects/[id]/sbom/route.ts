import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import type { CycloneDxSbom } from '@/lib/engines/scanner-engine';
import {
  convertCycloneDxToSpdx,
  validateSbomDocument,
  verifyArtifactAttestation,
} from '@/lib/engines/sbom-engine';

const AttestSchema = z.object({
  expectedDigestSha256: z.string().min(64).max(80),
  artifactContent: z.string().max(250_000).optional(),
  hmacSignature: z.string().max(200).optional(),
  signingSecret: z.string().max(200).optional(),
});

export async function GET(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Viewer', 'read');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const format = (req.nextUrl.searchParams.get('format') || 'cyclonedx').toLowerCase();
  const validate = req.nextUrl.searchParams.get('validate') === 'true';

  const db = getDb();
  const row = db
    .prepare('SELECT id, name, slsa_level as slsaLevel, sbom_json as sbomJson FROM projects WHERE id = ? AND org_id = ?')
    .get(id, authResult.auth.orgId) as
    | { id: string; name: string; slsaLevel: string; sbomJson: string | null }
    | undefined;

  if (!row) return jsonError('Project not found.', 404, 'NOT_FOUND');
  if (!row.sbomJson) {
    return jsonError('No SBOM has been generated for this project yet. Run a scan first.', 404, 'SBOM_NOT_FOUND');
  }

  const cyclone = JSON.parse(row.sbomJson) as CycloneDxSbom;
  const document = format === 'spdx' ? convertCycloneDxToSpdx(cyclone) : cyclone;

  return jsonOk({
    projectId: row.id,
    projectName: row.name,
    slsaLevel: row.slsaLevel,
    format: format === 'spdx' ? 'spdx' : 'cyclonedx',
    sbom: document,
    ...(validate ? { validation: validateSbomDocument(document) } : {}),
  });
}

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Developer', 'write');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = AttestSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid attestation verification payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const row = db
    .prepare('SELECT id, name, slsa_level FROM projects WHERE id = ? AND org_id = ?')
    .get(id, authResult.auth.orgId) as { id: string; name: string; slsa_level: string } | undefined;

  if (!row) return jsonError('Project not found.', 404, 'NOT_FOUND');

  const result = verifyArtifactAttestation({
    expectedDigestSha256: parsed.data.expectedDigestSha256,
    artifactContent: parsed.data.artifactContent,
    hmacSignature: parsed.data.hmacSignature,
    signingSecret: parsed.data.signingSecret || process.env.TRUSTRAIL_ATTESTATION_SECRET,
  });

  if (!result.verified) {
    return jsonError(result.reason, 422, 'ATTESTATION_VERIFICATION_FAILED', result);
  }

  db.prepare('UPDATE projects SET slsa_level = ? WHERE id = ? AND org_id = ?').run(
    result.recommendedSlsaLevel,
    row.id,
    authResult.auth.orgId
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'SLSA_ATTESTATION_VERIFIED',
    resourceType: 'Project',
    resourceId: row.id,
    details: `Verified artifact digest ${result.computedDigestSha256?.slice(0, 12)}... (${result.recommendedSlsaLevel}).`,
  });

  return jsonOk({
    projectId: row.id,
    slsaLevel: result.recommendedSlsaLevel,
    attestation: result,
  });
}
