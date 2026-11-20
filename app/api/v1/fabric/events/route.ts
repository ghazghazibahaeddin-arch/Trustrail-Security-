import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { listInternalEvents, publishEvent, replayEvent } from '@/lib/fabric/event-bus';
import { INTEGRATION_DEPENDENCY_MAP } from '@/lib/fabric/dependency-map';
import type { TrustrailEventType } from '@/lib/fabric/event-types';

const FabricActionSchema = z.discriminatedUnion('action', [
  z.object({
    action: z.literal('publish'),
    eventType: z.string().min(3).max(80),
    sourceConnector: z.string().min(2).max(60).default('control_plane'),
    sourceResourceId: z.string().min(1).max(160).default('workspace'),
    affectedAssetIds: z.array(z.string()).optional(),
    correlationId: z.string().max(80).optional(),
    idempotencyKey: z.string().max(128).optional(),
    payload: z.record(z.string(), z.unknown()).default({}),
    simulateFailure: z.boolean().default(false),
  }),
  z.object({
    action: z.literal('replay'),
    eventId: z.string().min(3),
    simulateFailure: z.boolean().default(false),
  }),
]);

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer', 'read');
  if ('error' in authResult) return authResult.error;

  const status = req.nextUrl.searchParams.get('status') || undefined;
  const eventType = req.nextUrl.searchParams.get('eventType') || undefined;
  const limit = Number(req.nextUrl.searchParams.get('limit') || 50);

  const db = getDb();
  const events = listInternalEvents(db, authResult.auth.orgId, { status, eventType, limit });

  const statusCounts = db
    .prepare(
      `SELECT processing_status as status, COUNT(*) as count
       FROM internal_events WHERE org_id = ? GROUP BY processing_status`
    )
    .all(authResult.auth.orgId) as Array<{ status: string; count: number }>;

  return jsonOk({
    events,
    statusCounts,
    dependencyMap: INTEGRATION_DEPENDENCY_MAP,
  });
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

  const parsed = FabricActionSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid fabric event payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();

  if (parsed.data.action === 'replay') {
    try {
      const result = replayEvent(
        db,
        authResult.auth.orgId,
        parsed.data.eventId,
        authResult.auth.email,
        parsed.data.simulateFailure
      );
      return jsonOk({
        replayed: true,
        ...result,
        events: listInternalEvents(db, authResult.auth.orgId, { limit: 50 }),
      });
    } catch (err) {
      return jsonError((err as Error).message, 404, 'EVENT_NOT_FOUND');
    }
  }

  const result = publishEvent(db, {
    orgId: authResult.auth.orgId,
    eventType: parsed.data.eventType as TrustrailEventType,
    actorId: authResult.auth.email,
    sourceConnector: parsed.data.sourceConnector,
    sourceResourceId: parsed.data.sourceResourceId,
    affectedAssetIds: parsed.data.affectedAssetIds,
    correlationId: parsed.data.correlationId,
    idempotencyKey: parsed.data.idempotencyKey,
    payload: parsed.data.payload,
    simulateFailure: parsed.data.simulateFailure,
  });

  return jsonOk(
    {
      ...result,
      events: listInternalEvents(db, authResult.auth.orgId, { limit: 50 }),
    },
    result.deduplicated ? 200 : 201
  );
}
