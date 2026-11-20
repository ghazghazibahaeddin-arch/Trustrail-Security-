import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { listProjectsWithStats } from '@/lib/domain-mappers';
import { publishEvent } from '@/lib/fabric/event-bus';

const CreateProjectSchema = z.object({
  name: z.string().min(2).max(120),
  repoUrl: z.string().min(3).max(255),
  branch: z.string().min(1).max(60).default('main'),
  language: z.string().min(1).max(60).default('TypeScript'),
  framework: z.string().min(1).max(80).default('Node.js'),
  owner: z.string().min(1).max(100).optional(),
  connectedAwsAccount: z.string().max(120).optional(),
});

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const projects = listProjectsWithStats(db, authResult.auth.orgId);
  return jsonOk({ projects });
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

  const parsed = CreateProjectSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid project payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const projId = `proj-${crypto.randomUUID().slice(0, 8)}`;
  const assetId = `asset-${crypto.randomUUID().slice(0, 8)}`;
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO projects (id, org_id, name, repo_url, branch, language, framework, owner, status, last_scanned, connected_aws_account, sbom_json, slsa_level, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'protected', 'Never', ?, NULL, 'None', ?)`
  ).run(
    projId,
    authResult.auth.orgId,
    parsed.data.name.trim(),
    parsed.data.repoUrl.trim(),
    parsed.data.branch.trim(),
    parsed.data.language.trim(),
    parsed.data.framework.trim(),
    parsed.data.owner?.trim() || authResult.auth.name,
    parsed.data.connectedAwsAccount?.trim() || null,
    now
  );

  // Register repository in Unified Security Graph automatically
  db.prepare(
    `INSERT INTO assets (id, org_id, project_id, name, asset_type, owner, internet_exposed, criticality, created_at)
     VALUES (?, ?, ?, ?, 'Repository', ?, 0, 'HIGH', ?)`
  ).run(
    assetId,
    authResult.auth.orgId,
    projId,
    parsed.data.repoUrl.trim(),
    parsed.data.owner?.trim() || authResult.auth.name,
    now
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'PROJECT_CREATED',
    resourceType: 'Project',
    resourceId: projId,
    details: `Registered repository ${parsed.data.name} (${parsed.data.repoUrl}).`,
  });

  publishEvent(db, {
    orgId: authResult.auth.orgId,
    eventType: 'repository.connected',
    actorId: authResult.auth.email,
    sourceConnector: 'github',
    sourceResourceId: parsed.data.repoUrl.trim(),
    affectedAssetIds: [assetId],
    payload: { projectId: projId, name: parsed.data.name.trim(), branch: parsed.data.branch.trim() },
  });

  const projects = listProjectsWithStats(db, authResult.auth.orgId);
  const project = projects.find((p) => p.id === projId);
  return jsonOk({ project, projects }, 201);
}
