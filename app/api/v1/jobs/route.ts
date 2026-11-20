import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { enqueueBackgroundJob, processBackgroundJob } from '@/lib/observability';

const JobActionSchema = z.discriminatedUnion('action', [
  z.object({
    action: z.literal('enqueue'),
    jobType: z.string().min(2).max(80),
    payload: z.record(z.string(), z.unknown()).default({}),
    executeImmediately: z.boolean().default(true),
    simulateFailure: z.boolean().default(false),
  }),
  z.object({
    action: z.literal('retry'),
    jobId: z.string().min(1),
    simulateFailure: z.boolean().default(false),
  }),
]);

function listJobs(orgId: string) {
  const db = getDb();
  return db
    .prepare(
      `SELECT id, org_id as orgId, job_type as jobType, status, attempts, max_attempts as maxAttempts,
              last_error as lastError, created_at as createdAt, updated_at as updatedAt
       FROM background_jobs WHERE org_id = ? ORDER BY created_at DESC LIMIT 50`
    )
    .all(orgId);
}

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer', 'read');
  if ('error' in authResult) return authResult.error;

  return jsonOk({ jobs: listJobs(authResult.auth.orgId) });
}

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Developer', 'write');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = JobActionSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid job queue request.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();

  if (parsed.data.action === 'enqueue') {
    const jobId = enqueueBackgroundJob(db, authResult.auth.orgId, parsed.data.jobType, parsed.data.payload);
    let executionResult = null;
    if (parsed.data.executeImmediately) {
      executionResult = processBackgroundJob(
        db,
        authResult.auth.orgId,
        jobId,
        parsed.data.simulateFailure
      );
    }

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'BACKGROUND_JOB_ENQUEUED',
      resourceType: 'BackgroundJob',
      resourceId: jobId,
      details: `Enqueued job ${parsed.data.jobType} (status=${executionResult?.status || 'Queued'}).`,
    });

    return jsonOk({ jobId, executionResult, jobs: listJobs(authResult.auth.orgId) }, 201);
  }

  try {
    const result = processBackgroundJob(
      db,
      authResult.auth.orgId,
      parsed.data.jobId,
      parsed.data.simulateFailure
    );
    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'BACKGROUND_JOB_RETRIED',
      resourceType: 'BackgroundJob',
      resourceId: parsed.data.jobId,
      details: `Retried job ${parsed.data.jobId} (status=${result.status}, attempts=${result.attempts}).`,
    });
    return jsonOk({ result, jobs: listJobs(authResult.auth.orgId) });
  } catch (err) {
    return jsonError((err as Error).message, 404, 'NOT_FOUND');
  }
}
