import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { buildCiPipelineSnippets, generateRunnerToken } from '@/lib/runner/runner-auth';

const RunnerActionSchema = z.discriminatedUnion('action', [
  z.object({
    action: z.literal('create_runner'),
    name: z.string().min(2).max(120),
    mode: z.enum(['scan', 'cicd', 'runtime_collector']).default('cicd'),
    environment: z.string().min(2).max(60).default('production'),
    capabilities: z.array(z.string().min(1).max(60)).optional(),
  }),
  z.object({
    action: z.literal('queue_job'),
    runnerId: z.string().optional(),
    jobType: z.enum(['repo_scan', 'iac_check', 'sbom_generate', 'k8s_collect']),
    target: z.record(z.string(), z.unknown()),
    timeoutSec: z.number().int().min(30).max(3600).default(300),
  }),
]);

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer', 'read');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const runners = db
    .prepare(
      `SELECT id, org_id as orgId, name, mode, status, token_prefix as tokenPrefix,
              device_fingerprint as deviceFingerprint, environment, version,
              capabilities_json as capabilitiesJson, last_heartbeat_at as lastHeartbeatAt,
              stats_json as statsJson, created_at as createdAt
       FROM runners WHERE org_id = ? ORDER BY created_at DESC`
    )
    .all(authResult.auth.orgId) as Array<Record<string, unknown>>;

  const jobs = db
    .prepare(
      `SELECT id, org_id as orgId, runner_id as runnerId, job_type as jobType,
              target_json as targetJson, status, timeout_sec as timeoutSec,
              result_json as resultJson, signature, created_at as createdAt,
              completed_at as completedAt
       FROM runner_jobs WHERE org_id = ? ORDER BY created_at DESC LIMIT 50`
    )
    .all(authResult.auth.orgId) as Array<Record<string, unknown>>;

  const origin = req.nextUrl?.origin || process.env.APP_URL || 'http://127.0.0.1:3000';

  return jsonOk({
    runners: runners.map((r) => ({
      ...r,
      capabilities: (() => {
        try {
          return JSON.parse(String(r.capabilitiesJson || '[]')) as string[];
        } catch {
          return [];
        }
      })(),
      stats: (() => {
        try {
          return JSON.parse(String(r.statsJson || '{}')) as Record<string, unknown>;
        } catch {
          return {};
        }
      })(),
    })),
    jobs: jobs.map((j) => ({
      ...j,
      target: (() => {
        try {
          return JSON.parse(String(j.targetJson || '{}')) as Record<string, unknown>;
        } catch {
          return {};
        }
      })(),
      result: (() => {
        try {
          return j.resultJson ? (JSON.parse(String(j.resultJson)) as Record<string, unknown>) : null;
        } catch {
          return null;
        }
      })(),
    })),
    ciSnippets: buildCiPipelineSnippets(origin),
  });
}

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Admin', 'write');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = RunnerActionSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid runner operation payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const now = new Date().toISOString();

  if (parsed.data.action === 'create_runner') {
    const id = `runner-${crypto.randomUUID().slice(0, 8)}`;
    const tok = generateRunnerToken();
    const capabilities = parsed.data.capabilities || ['sast', 'secrets', 'sca', 'iac', 'sbom'];

    db.prepare(
      `INSERT INTO runners (id, org_id, name, mode, status, token_hash, token_prefix, environment, version, capabilities_json, stats_json, created_at)
       VALUES (?, ?, ?, ?, 'Pending_Enrollment', ?, ?, ?, '1.2.0', ?, '{}', ?)`
    ).run(
      id,
      authResult.auth.orgId,
      parsed.data.name.trim(),
      parsed.data.mode,
      tok.tokenHash,
      tok.tokenPrefix,
      parsed.data.environment.trim(),
      JSON.stringify(capabilities),
      now
    );

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'RUNNER_TOKEN_ISSUED',
      resourceType: 'Runner',
      resourceId: id,
      details: `Issued enrollment token ${tok.tokenPrefix}... for ${parsed.data.mode} runner "${parsed.data.name}".`,
    });

    return jsonOk(
      {
        runner: {
          id,
          orgId: authResult.auth.orgId,
          name: parsed.data.name.trim(),
          mode: parsed.data.mode,
          status: 'Pending_Enrollment',
          tokenPrefix: tok.tokenPrefix,
          environment: parsed.data.environment.trim(),
          version: '1.2.0',
          capabilities,
          createdAt: now,
        },
        enrollmentToken: tok.rawToken,
      },
      201
    );
  }

  // action === 'queue_job'
  const jobId = `rjob-${crypto.randomUUID().slice(0, 8)}`;
  if (parsed.data.runnerId) {
    const runnerRow = db
      .prepare(`SELECT id FROM runners WHERE id = ? AND org_id = ? AND status != 'Revoked'`)
      .get(parsed.data.runnerId, authResult.auth.orgId);
    if (!runnerRow) {
      return jsonError('Target runner not found or revoked.', 404, 'RUNNER_NOT_FOUND');
    }
  }

  db.prepare(
    `INSERT INTO runner_jobs (id, org_id, runner_id, job_type, target_json, status, timeout_sec, created_at)
     VALUES (?, ?, ?, ?, ?, 'Queued', ?, ?)`
  ).run(
    jobId,
    authResult.auth.orgId,
    parsed.data.runnerId || null,
    parsed.data.jobType,
    JSON.stringify(parsed.data.target),
    parsed.data.timeoutSec,
    now
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'RUNNER_JOB_QUEUED',
    resourceType: 'RunnerJob',
    resourceId: jobId,
    details: `Queued ${parsed.data.jobType} job ${jobId} for runner ${parsed.data.runnerId || 'any-available'}.`,
  });

  return jsonOk(
    {
      job: {
        id: jobId,
        orgId: authResult.auth.orgId,
        runnerId: parsed.data.runnerId || null,
        jobType: parsed.data.jobType,
        target: parsed.data.target,
        status: 'Queued',
        timeoutSec: parsed.data.timeoutSec,
        createdAt: now,
      },
    },
    201
  );
}
