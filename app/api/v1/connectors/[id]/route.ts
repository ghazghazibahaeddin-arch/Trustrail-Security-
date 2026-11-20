import { NextRequest } from 'next/server';
import { getDb } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { deleteConnectorData } from '@/lib/connectors/hub';

export async function DELETE(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Admin');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const purgeConfig = req.nextUrl.searchParams.get('purgeConfig') !== 'false';
  const db = getDb();

  try {
    const summary = deleteConnectorData(db, authResult.auth.orgId, id, authResult.auth.email, purgeConfig);
    return jsonOk({ deleted: true, ...summary });
  } catch (err) {
    const msg = (err as Error).message;
    if (msg === 'Connector not found.') return jsonError(msg, 404, 'NOT_FOUND');
    return jsonError(msg, 400, 'DELETE_FAILED');
  }
}
