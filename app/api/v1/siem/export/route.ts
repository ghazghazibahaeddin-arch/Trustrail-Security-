import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { exportEventToSiem } from '@/lib/integrations/siem-exporter';

const SiemExportSchema = z.object({
  destination: z.enum(['splunk', 'elastic', 'sentinel', 'webhook']).default('splunk'),
  resourceType: z.string().min(2).max(60).default('SecuritySnapshot'),
  resourceId: z.string().min(1).max(120).default('org-telemetry'),
  correlationId: z.string().max(80).optional(),
  eventData: z.record(z.string(), z.unknown()).default({}),
});

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer', 'read');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const exportsList = db
    .prepare(
      `SELECT id, destination, resource_type as resourceType, resource_id as resourceId,
              correlation_id as correlationId, status, http_status as httpStatus,
              attempts, error_message as errorMessage, exported_at as exportedAt
       FROM siem_exports WHERE org_id = ? ORDER BY exported_at DESC LIMIT 100`
    )
    .all(authResult.auth.orgId);

  return jsonOk({ exports: exportsList });
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

  const parsed = SiemExportSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid SIEM export payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const result = await exportEventToSiem(db, authResult.auth.orgId, parsed.data);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'SIEM_EVENT_EXPORTED',
    resourceType: 'SiemExport',
    resourceId: result.exportId,
    details: `Exported ${parsed.data.resourceType} to ${parsed.data.destination} (status=${result.status}, corr=${result.correlationId}).`,
  });

  return jsonOk(result, result.status === 'Delivered' ? 200 : 202);
}
