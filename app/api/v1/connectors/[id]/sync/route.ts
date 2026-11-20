import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { listSyncRunsForConnector, runConnectorSync } from '@/lib/connectors/hub';

const SyncSchema = z.object({
  mode: z.enum(['initial', 'incremental', 'manual']).default('incremental'),
});

export async function GET(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const existing = db
    .prepare('SELECT id FROM connectors WHERE id = ? AND org_id = ?')
    .get(id, authResult.auth.orgId);
  if (!existing) return jsonError('Connector not found.', 404, 'NOT_FOUND');

  return jsonOk({
    connectorId: id,
    syncRuns: listSyncRunsForConnector(db, authResult.auth.orgId, id),
  });
}

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Admin');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  let body: unknown = {};
  try {
    body = await req.json();
  } catch {
    body = {};
  }

  const parsed = SyncSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid sync payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  try {
    const result = await runConnectorSync(
      db,
      authResult.auth.orgId,
      id,
      authResult.auth.email,
      parsed.data.mode
    );
    return jsonOk({
      syncRun: result,
      syncRuns: listSyncRunsForConnector(db, authResult.auth.orgId, id),
    });
  } catch (err) {
    const msg = (err as Error).message;
    if (msg === 'Connector not found.') return jsonError(msg, 404, 'NOT_FOUND');
    return jsonError(msg, 424, 'SYNC_FAILED');
  }
}
