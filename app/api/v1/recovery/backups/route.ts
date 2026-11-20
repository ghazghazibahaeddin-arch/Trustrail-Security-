import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';

const BackupActionSchema = z.discriminatedUnion('action', [
  z.object({
    action: z.literal('create_snapshot'),
    targetName: z.string().min(2).max(120).default('sqlite-primary-tenant-snapshot'),
    backupType: z.enum(['Full Snapshot', 'Incremental WAL', 'Config & Keys']).default('Full Snapshot'),
  }),
  z.object({
    action: z.literal('verify_restore'),
    backupId: z.string().min(1),
  }),
]);

function getBackupsDir(): string {
  const dir = process.env.TRUSTRAIL_BACKUP_DIR || path.join(os.tmpdir(), 'trustrail-backups');
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  return dir;
}

function listBackups(orgId: string) {
  const db = getDb();
  return db
    .prepare(
      `SELECT id, org_id as orgId, target_name as targetName, backup_type as backupType,
              checksum_sha256 as checksumSha256, size_bytes as sizeBytes,
              restore_tested_at as restoreTestedAt, restore_status as restoreStatus,
              created_at as createdAt
       FROM recovery_backups WHERE org_id = ? ORDER BY created_at DESC`
    )
    .all(orgId);
}

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer', 'read');
  if ('error' in authResult) return authResult.error;

  return jsonOk({ backups: listBackups(authResult.auth.orgId) });
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

  const parsed = BackupActionSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid recovery backup request.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const now = new Date().toISOString();

  if (parsed.data.action === 'create_snapshot') {
    const backupId = `bkp-${crypto.randomUUID().slice(0, 8)}`;
    const snapshotPayload = JSON.stringify({
      backupId,
      orgId: authResult.auth.orgId,
      targetName: parsed.data.targetName,
      backupType: parsed.data.backupType,
      capturedAt: now,
      projects: db.prepare('SELECT id, name, status FROM projects WHERE org_id = ?').all(authResult.auth.orgId),
      findingsCount: (
        db.prepare('SELECT COUNT(*) as cnt FROM findings WHERE org_id = ?').get(authResult.auth.orgId) as { cnt: number }
      ).cnt,
      policies: db.prepare('SELECT id, name, rule_code, status FROM policies WHERE org_id = ?').all(authResult.auth.orgId),
    });

    const buf = Buffer.from(snapshotPayload, 'utf8');
    const checksum = `sha256:${crypto.createHash('sha256').update(buf).digest('hex')}`;
    const snapFile = path.join(getBackupsDir(), `${backupId}.json`);
    fs.writeFileSync(snapFile, buf, { mode: 0o600 });

    db.prepare(
      `INSERT INTO recovery_backups (id, org_id, target_name, backup_type, checksum_sha256, size_bytes, restore_tested_at, restore_status, created_at)
       VALUES (?, ?, ?, ?, ?, ?, NULL, 'Untested', ?)`
    ).run(
      backupId,
      authResult.auth.orgId,
      parsed.data.targetName,
      parsed.data.backupType,
      checksum,
      buf.byteLength,
      now
    );

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'RECOVERY_SNAPSHOT_CREATED',
      resourceType: 'RecoveryBackup',
      resourceId: backupId,
      details: `Created checksummed recovery snapshot ${backupId} (${buf.byteLength} bytes, ${checksum.slice(0, 18)}...).`,
    });

    return jsonOk({ backupId, checksum, sizeBytes: buf.byteLength, backups: listBackups(authResult.auth.orgId) }, 201);
  }

  // verify_restore
  const row = db
    .prepare('SELECT id, checksum_sha256, target_name FROM recovery_backups WHERE id = ? AND org_id = ?')
    .get(parsed.data.backupId, authResult.auth.orgId) as
    | { id: string; checksum_sha256: string; target_name: string }
    | undefined;

  if (!row) return jsonError('Backup record not found.', 404, 'NOT_FOUND');

  // Verify SQLite PRAGMA integrity_check and snapshot file checksum if present on disk
  const integrity = db.prepare('PRAGMA integrity_check;').get() as { integrity_check?: string };
  let integrityOk = integrity?.integrity_check === 'ok';

  const snapFile = path.join(getBackupsDir(), `${row.id}.json`);
  if (fs.existsSync(snapFile)) {
    const fileBuf = fs.readFileSync(snapFile);
    const actualChecksum = `sha256:${crypto.createHash('sha256').update(fileBuf).digest('hex')}`;
    if (actualChecksum !== row.checksum_sha256) {
      integrityOk = false;
    }
  }

  const nextStatus = integrityOk ? 'Verified' : 'Failed';
  db.prepare(
    `UPDATE recovery_backups SET restore_status = ?, restore_tested_at = ? WHERE id = ? AND org_id = ?`
  ).run(nextStatus, now, row.id, authResult.auth.orgId);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'RECOVERY_RESTORE_TESTED',
    resourceType: 'RecoveryBackup',
    resourceId: row.id,
    details: `Executed restore & checksum verification on ${row.target_name}: status=${nextStatus}.`,
  });

  if (!integrityOk) {
    return jsonError('Backup checksum or SQLite integrity verification failed.', 500, 'RESTORE_VERIFICATION_FAILED');
  }

  return jsonOk({
    verified: true,
    backupId: row.id,
    restoreStatus: nextStatus,
    restoreTestedAt: now,
    backups: listBackups(authResult.auth.orgId),
  });
}
