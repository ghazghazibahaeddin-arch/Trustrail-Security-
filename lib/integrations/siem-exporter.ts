import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { parseConnectorConfig } from '@/lib/security/connector-config';
import { assertSafeExternalUrl } from '@/lib/security/ssrf';

export interface SiemExportPayload {
  destination: 'splunk' | 'elastic' | 'sentinel' | 'webhook';
  resourceType: string;
  resourceId: string;
  correlationId?: string;
  eventData: Record<string, unknown>;
}

export async function exportEventToSiem(
  db: DatabaseSync,
  orgId: string,
  input: SiemExportPayload
): Promise<{
  exportId: string;
  status: 'Delivered' | 'Queued' | 'Failed';
  httpStatus: number | null;
  errorMessage: string | null;
  correlationId: string;
}> {
  const correlationId = input.correlationId || `corr-${crypto.randomUUID().slice(0, 10)}`;
  const exportId = `siem-${crypto.randomUUID().slice(0, 8)}`;
  const now = new Date().toISOString();

  const providerKey = input.destination === 'splunk' ? 'siem_splunk' : input.destination === 'webhook' ? 'slack' : 'siem_elastic';
  const conn = db
    .prepare('SELECT id, config_json FROM connectors WHERE org_id = ? AND provider_key = ?')
    .get(orgId, providerKey) as { id: string; config_json: string | null } | undefined;

  const cfg = conn ? parseConnectorConfig(conn.config_json, { orgId, connectorId: conn.id }) : {};

  let targetUrl: string | undefined;
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  let bodyPayload: Record<string, unknown> = {
    source: 'trustrail-security-cloud',
    correlationId,
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    timestamp: now,
    ...input.eventData,
  };

  if (input.destination === 'splunk') {
    targetUrl = cfg.splunkHecUrl || process.env.SPLUNK_HEC_URL;
    const token = cfg.splunkHecToken || process.env.SPLUNK_HEC_TOKEN;
    if (token) headers.Authorization = `Splunk ${token}`;
    bodyPayload = {
      time: Math.floor(Date.now() / 1000),
      sourcetype: 'trustrail:security:telemetry',
      event: bodyPayload,
    };
  } else if (input.destination === 'elastic' || input.destination === 'sentinel') {
    targetUrl = cfg.elasticEndpointUrl || process.env.ELASTIC_SIEM_URL;
    const apiKey = cfg.elasticApiKey || process.env.ELASTIC_SIEM_API_KEY;
    if (apiKey) headers.Authorization = `ApiKey ${apiKey}`;
  } else {
    targetUrl = cfg.webhookUrl || process.env.SLACK_WEBHOOK_URL;
  }

  if (!targetUrl) {
    db.prepare(
      `INSERT INTO siem_exports (id, org_id, destination, resource_type, resource_id, correlation_id, status, http_status, attempts, error_message, exported_at)
       VALUES (?, ?, ?, ?, ?, ?, 'Queued', NULL, 1, ?, ?)`
    ).run(
      exportId,
      orgId,
      input.destination,
      input.resourceType,
      input.resourceId,
      correlationId,
      `No ${input.destination} endpoint credentials configured.`,
      now
    );

    return {
      exportId,
      status: 'Queued',
      httpStatus: null,
      errorMessage: `No ${input.destination} endpoint configured. Event persisted in siem_exports queue.`,
      correlationId,
    };
  }

  try {
    const safeUrl = await assertSafeExternalUrl(targetUrl, { requireHttps: true });
    const res = await fetch(safeUrl.toString(), {
      method: 'POST',
      headers,
      body: JSON.stringify(bodyPayload),
      signal: AbortSignal.timeout(8000),
    });

    const status = res.ok ? 'Delivered' : 'Failed';
    const errMsg = res.ok ? null : `SIEM endpoint returned HTTP ${res.status}`;
    db.prepare(
      `INSERT INTO siem_exports (id, org_id, destination, resource_type, resource_id, correlation_id, status, http_status, attempts, error_message, exported_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)`
    ).run(exportId, orgId, input.destination, input.resourceType, input.resourceId, correlationId, status, res.status, errMsg, now);

    return { exportId, status, httpStatus: res.status, errorMessage: errMsg, correlationId };
  } catch (err) {
    const errMsg = (err as Error).message.slice(0, 240);
    db.prepare(
      `INSERT INTO siem_exports (id, org_id, destination, resource_type, resource_id, correlation_id, status, http_status, attempts, error_message, exported_at)
       VALUES (?, ?, ?, ?, ?, ?, 'Failed', NULL, 1, ?, ?)`
    ).run(exportId, orgId, input.destination, input.resourceType, input.resourceId, correlationId, errMsg, now);

    return { exportId, status: 'Failed', httpStatus: null, errorMessage: errMsg, correlationId };
  }
}
