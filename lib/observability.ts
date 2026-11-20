import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { redactEvidenceSecrets } from '@/lib/security/crypto';

export function logSecurityEvent(
  level: 'info' | 'warn' | 'error',
  event: string,
  meta: Record<string, unknown> = {}
): void {
  const sanitized = JSON.parse(redactEvidenceSecrets(JSON.stringify(meta))) as Record<string, unknown>;
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    event,
    ...sanitized,
  };
  if (process.env.NODE_ENV !== 'test') {
    console.log(JSON.stringify(entry));
  }
}

export function enqueueBackgroundJob(
  db: DatabaseSync,
  orgId: string,
  jobType: string,
  payload: Record<string, unknown>,
  maxAttempts = 3
): string {
  const id = `job-${crypto.randomUUID().slice(0, 8)}`;
  const now = new Date().toISOString();
  db.prepare(
    `INSERT INTO background_jobs (id, org_id, job_type, payload_json, status, attempts, max_attempts, last_error, created_at, updated_at)
     VALUES (?, ?, ?, ?, 'Queued', 0, ?, NULL, ?, ?)`
  ).run(id, orgId, jobType, JSON.stringify(payload), maxAttempts, now, now);
  return id;
}

export function processBackgroundJob(
  db: DatabaseSync,
  orgId: string,
  jobId: string,
  simulateFailure = false
): { id: string; status: string; attempts: number; lastError: string | null } {
  const row = db
    .prepare(
      `SELECT id, job_type, payload_json, status, attempts, max_attempts
       FROM background_jobs WHERE id = ? AND org_id = ?`
    )
    .get(jobId, orgId) as
    | {
        id: string;
        job_type: string;
        payload_json: string;
        status: string;
        attempts: number;
        max_attempts: number;
      }
    | undefined;

  if (!row) {
    throw new Error('Background job not found.');
  }

  const nextAttempts = row.attempts + 1;
  const now = new Date().toISOString();

  if (simulateFailure) {
    const nextStatus = nextAttempts >= row.max_attempts ? 'Dead_Letter' : 'Queued';
    const errMsg = `Attempt ${nextAttempts}/${row.max_attempts} failed during ${row.job_type} execution.`;
    db.prepare(
      `UPDATE background_jobs SET status = ?, attempts = ?, last_error = ?, updated_at = ? WHERE id = ? AND org_id = ?`
    ).run(nextStatus, nextAttempts, errMsg, now, row.id, orgId);
    return { id: row.id, status: nextStatus, attempts: nextAttempts, lastError: errMsg };
  }

  db.prepare(
    `UPDATE background_jobs SET status = 'Completed', attempts = ?, last_error = NULL, updated_at = ? WHERE id = ? AND org_id = ?`
  ).run(nextAttempts, now, row.id, orgId);

  return { id: row.id, status: 'Completed', attempts: nextAttempts, lastError: null };
}
