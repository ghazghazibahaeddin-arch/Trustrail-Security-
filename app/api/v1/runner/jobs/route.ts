import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk } from '@/lib/api-response';
import { authenticateRunnerRequest } from '@/lib/runner/runner-auth';
import { publishEvent } from '@/lib/fabric/event-bus';

const JobResultSchema = z.object({
  jobId: z.string().min(1),
  status: z.enum(['Completed', 'Failed']),
  summary: z.record(z.string(), z.unknown()).optional(),
  signature: z.string().min(8).max(256).optional(),
  findings: z
    .array(
      z.object({
        title: z.string().min(3).max(200),
        severity: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']),
        category: z.enum(['SAST', 'SCA', 'SECRET', 'IAC', 'CONTAINER', 'CLOUD', 'API', 'SUPPLY_CHAIN']).default('SAST'),
        filePath: z.string().max(255).optional(),
        line: z.number().int().positive().optional(),
        cve: z.string().max(40).optional(),
        cvss: z.number().min(0).max(10).default(7.5),
        evidence: z.string().max(1000).default('Detected by remote TRUSTRAIL Runner.'),
        suggestedFix: z.string().max(1000).default('Review runner output and remediate.'),
        assetName: z.string().max(200).optional(),
      })
    )
    .max(100)
    .optional(),
});

export async function GET(req: NextRequest) {
  const runner = authenticateRunnerRequest(req);
  if (!runner) {
    return jsonError('Valid runner token (Bearer tr_run_...) required.', 401, 'RUNNER_UNAUTHORIZED');
  }

  const db = getDb();
  const job = db
    .prepare(
      `SELECT id, job_type as jobType, target_json as targetJson, timeout_sec as timeoutSec, created_at as createdAt
       FROM runner_jobs
       WHERE org_id = ? AND status = 'Queued' AND (runner_id IS NULL OR runner_id = ?)
       ORDER BY created_at ASC LIMIT 1`
    )
    .get(runner.orgId, runner.id) as
    | { id: string; jobType: string; targetJson: string; timeoutSec: number; createdAt: string }
    | undefined;

  if (!job) {
    return jsonOk({ job: null });
  }

  db.prepare(`UPDATE runner_jobs SET status = 'Dispatched', runner_id = ? WHERE id = ? AND org_id = ?`).run(
    runner.id,
    job.id,
    runner.orgId
  );

  return jsonOk({
    job: {
      id: job.id,
      jobType: job.jobType,
      target: JSON.parse(job.targetJson || '{}') as Record<string, unknown>,
      timeoutSec: job.timeoutSec,
      status: 'Dispatched',
      createdAt: job.createdAt,
    },
  });
}

export async function POST(req: NextRequest) {
  const runner = authenticateRunnerRequest(req);
  if (!runner) {
    return jsonError('Valid runner token (Bearer tr_run_...) required.', 401, 'RUNNER_UNAUTHORIZED');
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = JobResultSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid runner job result payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const jobRow = db
    .prepare(`SELECT id, job_type, target_json FROM runner_jobs WHERE id = ? AND org_id = ?`)
    .get(parsed.data.jobId, runner.orgId) as { id: string; job_type: string; target_json: string } | undefined;

  if (!jobRow) {
    return jsonError('Runner job not found in organization.', 404, 'JOB_NOT_FOUND');
  }

  const now = new Date().toISOString();
  const findingsInput = parsed.data.findings || [];
  let newFindingsInserted = 0;

  for (const f of findingsInput) {
    const fingerprint = crypto
      .createHash('sha256')
      .update(`runner|${runner.orgId}|${f.category}|${f.title}|${f.filePath || ''}|${f.line || 0}`)
      .digest('hex')
      .slice(0, 16);

    const existing = db
      .prepare('SELECT id FROM findings WHERE org_id = ? AND fingerprint = ?')
      .get(runner.orgId, fingerprint);

    if (!existing) {
      newFindingsInserted += 1;
      db.prepare(
        `INSERT INTO findings (id, org_id, project_id, asset_id, fingerprint, title, severity, category, scanner, asset_name, file_path, line, cve, cvss, exploitability, status, evidence, suggested_fix, assigned_owner, discovered_at)
         VALUES (?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?)`
      ).run(
        `finding-${crypto.randomUUID().slice(0, 8)}`,
        runner.orgId,
        fingerprint,
        f.title,
        f.severity,
        f.category,
        `trustrail-runner:${runner.name}`,
        f.assetName || runner.name,
        f.filePath || null,
        f.line || null,
        f.cve || null,
        f.cvss,
        f.severity === 'CRITICAL' ? 'High' : 'Medium',
        f.evidence,
        f.suggestedFix,
        `runner:${runner.id}`,
        now
      );
    }
  }

  const computedSig =
    parsed.data.signature ||
    `sha256:${crypto
      .createHash('sha256')
      .update(`${parsed.data.jobId}|${runner.id}|${parsed.data.status}|${findingsInput.length}`)
      .digest('hex')
      .slice(0, 32)}`;

  db.prepare(
    `UPDATE runner_jobs
     SET status = ?,
         runner_id = ?,
         result_json = ?,
         signature = ?,
         completed_at = ?
     WHERE id = ? AND org_id = ?`
  ).run(
    parsed.data.status,
    runner.id,
    JSON.stringify({
      summary: parsed.data.summary || {},
      findingsReported: findingsInput.length,
      newFindingsInserted,
    }),
    computedSig,
    now,
    parsed.data.jobId,
    runner.orgId
  );

  const evt = publishEvent(db, {
    orgId: runner.orgId,
    eventType: 'runner.job_completed',
    actorId: `runner:${runner.id}`,
    sourceConnector: 'trustrail_runner',
    sourceResourceId: parsed.data.jobId,
    evidenceReference: computedSig,
    payload: {
      jobId: parsed.data.jobId,
      jobType: jobRow.job_type,
      status: parsed.data.status,
      findingsReported: findingsInput.length,
      newFindingsInserted,
    },
  });

  appendAuditLog(db, {
    orgId: runner.orgId,
    actorEmail: `runner:${runner.id}`,
    action: 'RUNNER_JOB_COMPLETED',
    resourceType: 'RunnerJob',
    resourceId: parsed.data.jobId,
    details: `Runner "${runner.name}" completed ${jobRow.job_type} (${parsed.data.status}, ${newFindingsInserted} new findings).`,
  });

  return jsonOk({
    jobId: parsed.data.jobId,
    status: parsed.data.status,
    findingsReported: findingsInput.length,
    newFindingsInserted,
    signature: computedSig,
    eventId: evt.event.eventId,
  });
}
