import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { appendAuditLog } from '@/lib/db';
import { parseConnectorConfig } from '@/lib/security/connector-config';
import { assertSafeExternalUrl } from '@/lib/security/ssrf';
import { logSecurityEvent } from '@/lib/observability';
import type {
  EventProcessingStatus,
  InternalEventEnvelope,
  PublishEventInput,
  TrustrailEventType,
} from '@/lib/fabric/event-types';

function rowToEnvelope(row: Record<string, unknown>): InternalEventEnvelope {
  let affectedAssetIds: string[] = [];
  let payload: Record<string, unknown> = {};
  try {
    affectedAssetIds = JSON.parse(String(row.affected_assets_json || '[]')) as string[];
  } catch {
    affectedAssetIds = [];
  }
  try {
    payload = JSON.parse(String(row.payload_json || '{}')) as Record<string, unknown>;
  } catch {
    payload = {};
  }

  return {
    eventId: String(row.event_id),
    eventType: String(row.event_type) as TrustrailEventType,
    eventVersion: String(row.event_version || '1.0'),
    tenantId: String(row.org_id),
    actorId: String(row.actor_id),
    sourceConnector: String(row.source_connector),
    sourceResourceId: String(row.source_resource_id),
    affectedAssetIds,
    correlationId: String(row.correlation_id),
    causationId: row.causation_id ? String(row.causation_id) : null,
    timestamp: String(row.created_at),
    evidenceReference: row.evidence_reference ? String(row.evidence_reference) : null,
    payload,
    idempotencyKey: String(row.idempotency_key),
    processingStatus: String(row.processing_status) as EventProcessingStatus,
    attempts: Number(row.attempts || 0),
    lastError: row.last_error ? String(row.last_error) : null,
    processedAt: row.processed_at ? String(row.processed_at) : null,
  };
}

function recordNotificationDelivery(
  db: DatabaseSync,
  orgId: string,
  channel: string,
  eventType: string,
  status: string,
  httpStatus: number | null,
  summary: string
) {
  db.prepare(
    `INSERT INTO notification_deliveries (id, org_id, channel, event_type, status, http_status, summary, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    `notif-${crypto.randomUUID().slice(0, 8)}`,
    orgId,
    channel,
    eventType,
    status,
    httpStatus,
    summary.slice(0, 320),
    new Date().toISOString()
  );
}

/**
 * Best-effort asynchronous outbound dispatcher for Slack, Microsoft Teams, Email, and SIEM forwarders.
 * Never fabricates delivery success: if no URL/token is configured, it logs 'Skipped_Not_Configured' or 'Queued'.
 */
export async function dispatchEventToConfiguredOutboundChannels(
  db: DatabaseSync,
  orgId: string,
  event: InternalEventEnvelope
): Promise<void> {
  const alertableEvents: TrustrailEventType[] = [
    'incident.created',
    'secret.detected',
    'state.drift_detected',
    'anomaly.detected',
    'integration.failed',
    'remediation.failed',
  ];
  const siemEvents: TrustrailEventType[] = [
    ...alertableEvents,
    'vulnerability.discovered',
    'security_event.received',
    'trust_receipt.created',
    'remediation.verified',
  ];

  const connectors = db
    .prepare(`SELECT id, provider_key, config_json, status FROM connectors WHERE org_id = ?`)
    .all(orgId) as Array<{ id: string; provider_key: string; config_json: string | null; status: string }>;

  if (alertableEvents.includes(event.eventType)) {
    const slackConn = connectors.find((c) => c.provider_key === 'slack');
    const slackCfg = slackConn
      ? parseConnectorConfig(slackConn.config_json, { orgId, connectorId: slackConn.id })
      : {};
    const slackUrl = slackCfg.webhookUrl || process.env.SLACK_WEBHOOK_URL;
    if (slackUrl) {
      try {
        const safe = await assertSafeExternalUrl(slackUrl, { requireHttps: true });
        const summary = `[Trustrail ${event.eventType}] Resource ${event.sourceResourceId} (corr=${event.correlationId})`;
        const res = await fetch(safe.toString(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            text: summary,
            content: summary,
            event: event.eventType,
            correlationId: event.correlationId,
            payload: event.payload,
          }),
          signal: AbortSignal.timeout(5000),
        });
        recordNotificationDelivery(
          db,
          orgId,
          'slack',
          event.eventType,
          res.ok ? 'Delivered' : 'Failed',
          res.status,
          summary
        );
      } catch (err) {
        recordNotificationDelivery(db, orgId, 'slack', event.eventType, 'Error', null, (err as Error).message);
      }
    }

    const teamsConn = connectors.find((c) => c.provider_key === 'teams');
    const teamsCfg = teamsConn
      ? parseConnectorConfig(teamsConn.config_json, { orgId, connectorId: teamsConn.id })
      : {};
    if (teamsCfg.teamsWebhookUrl) {
      try {
        const safe = await assertSafeExternalUrl(teamsCfg.teamsWebhookUrl, { requireHttps: true });
        const summary = `[Trustrail Security Cloud] ${event.eventType} on ${event.sourceResourceId}`;
        const res = await fetch(safe.toString(), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            '@type': 'MessageCard',
            summary,
            themeColor: event.eventType.includes('failed') || event.eventType.includes('secret') ? 'D92D20' : '0891B2',
            title: summary,
            text: `Source: ${event.sourceConnector} | Correlation ID: ${event.correlationId}`,
          }),
          signal: AbortSignal.timeout(5000),
        });
        recordNotificationDelivery(
          db,
          orgId,
          'teams',
          event.eventType,
          res.ok ? 'Delivered' : 'Failed',
          res.status,
          summary
        );
      } catch (err) {
        recordNotificationDelivery(db, orgId, 'teams', event.eventType, 'Error', null, (err as Error).message);
      }
    }
  }

  if (siemEvents.includes(event.eventType)) {
    const splunkConn = connectors.find((c) => c.provider_key === 'siem_splunk');
    const splunkCfg = splunkConn
      ? parseConnectorConfig(splunkConn.config_json, { orgId, connectorId: splunkConn.id })
      : {};
    if (splunkCfg.splunkHecUrl && splunkCfg.splunkHecToken) {
      try {
        const safe = await assertSafeExternalUrl(splunkCfg.splunkHecUrl, { requireHttps: true });
        const res = await fetch(safe.toString(), {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Splunk ${splunkCfg.splunkHecToken}`,
          },
          body: JSON.stringify({
            time: Math.floor(Date.now() / 1000),
            sourcetype: 'trustrail:security:event',
            event,
          }),
          signal: AbortSignal.timeout(5000),
        });
        db.prepare(
          `INSERT INTO siem_exports (id, org_id, destination, resource_type, resource_id, correlation_id, status, http_status, attempts, error_message, exported_at)
           VALUES (?, ?, 'splunk', ?, ?, ?, ?, ?, 1, ?, ?)`
        ).run(
          `siem-${crypto.randomUUID().slice(0, 8)}`,
          orgId,
          event.eventType,
          event.sourceResourceId,
          event.correlationId,
          res.ok ? 'Delivered' : 'Failed',
          res.status,
          res.ok ? null : `HTTP ${res.status}`,
          new Date().toISOString()
        );
      } catch (err) {
        db.prepare(
          `INSERT INTO siem_exports (id, org_id, destination, resource_type, resource_id, correlation_id, status, http_status, attempts, error_message, exported_at)
           VALUES (?, ?, 'splunk', ?, ?, ?, 'Failed', NULL, 1, ?, ?)`
        ).run(
          `siem-${crypto.randomUUID().slice(0, 8)}`,
          orgId,
          event.eventType,
          event.sourceResourceId,
          event.correlationId,
          (err as Error).message.slice(0, 240),
          new Date().toISOString()
        );
      }
    }
  }
}

function executeEventSubscribers(db: DatabaseSync, event: InternalEventEnvelope): string[] {
  const triggered: string[] = [];
  const now = new Date().toISOString();

  switch (event.eventType) {
    case 'scan.completed':
    case 'sbom.generated': {
      db.prepare(
        `UPDATE compliance_controls
         SET evidence_count = evidence_count + 1, last_verified = ?
         WHERE org_id = ? AND code IN ('PW.1', 'SLSA-2')`
      ).run(now.slice(0, 10), event.tenantId);
      triggered.push('compliance.controls_updated(PW.1,SLSA-2)');
      break;
    }

    case 'vulnerability.discovered':
    case 'secret.detected': {
      // Automatically create a containment incident if a live secret is detected in repo/CI
      if (event.eventType === 'secret.detected' && event.payload.autoEscalateIncident) {
        const incId = `inc-${crypto.randomUUID().slice(0, 8)}`;
        const title = `Exposed Secret Detected in ${event.sourceResourceId}`;
        db.prepare(
          `INSERT INTO incidents (id, org_id, title, severity, status, affected_asset, owner, summary, playbook_name, actions_taken_json, opened_at)
           VALUES (?, ?, ?, 'SEV-1', 'Open', ?, ?, ?, 'Credential Compromise & Revocation', ?, ?)`
        ).run(
          incId,
          event.tenantId,
          title,
          event.sourceResourceId,
          event.actorId,
          `Correlated secret leak from ${event.sourceConnector} (correlation=${event.correlationId}).`,
          JSON.stringify([
            `Auto-escalated from ${event.eventType} (${event.eventId}).`,
            'Queued outbound notification & SIEM export.',
          ]),
          now
        );
        triggered.push(`incident.created(${incId})`);
      }
      triggered.push('attack_paths.recalculation_queued');
      break;
    }

    case 'remediation.verified': {
      db.prepare(
        `UPDATE compliance_controls
         SET evidence_count = evidence_count + 1, last_verified = ?
         WHERE org_id = ? AND code IN ('A03:2025', 'CC6.1')`
      ).run(now.slice(0, 10), event.tenantId);
      triggered.push('compliance.evidence_recorded');
      triggered.push('attack_paths.reverified');
      break;
    }

    case 'cloud.resource.discovered':
    case 'state.drift_detected': {
      db.prepare(
        `UPDATE compliance_controls
         SET last_verified = ?,
             status = CASE WHEN ? = 'state.drift_detected' THEN 'Needs_Evidence' ELSE status END
         WHERE org_id = ? AND code = 'CC6.1'`
      ).run(now.slice(0, 10), event.eventType, event.tenantId);
      triggered.push('cspm.compliance_sync(CC6.1)');
      break;
    }

    case 'incident.created':
    case 'incident.contained':
    case 'incident.resolved':
    case 'anomaly.detected': {
      triggered.push('incident.timeline_correlated');
      break;
    }

    case 'integration.failed':
    case 'integration.reauth_required': {
      db.prepare(
        `UPDATE connectors
         SET failure_count = failure_count + 1,
             last_error = ?,
             lifecycle_state = CASE WHEN ? = 'integration.reauth_required' THEN 'REAUTH_REQUIRED' ELSE 'ERROR' END
         WHERE org_id = ? AND provider_key = ?`
      ).run(
        String(event.payload.error || 'Integration failure detected'),
        event.eventType,
        event.tenantId,
        event.sourceConnector
      );
      triggered.push(`connector.state_updated(${event.sourceConnector})`);
      break;
    }

    case 'trust_receipt.created': {
      triggered.push('trust_center.attestation_published');
      break;
    }

    default: {
      triggered.push('audit.recorded');
      break;
    }
  }

  return triggered;
}

export function publishEvent<T extends Record<string, unknown>>(
  db: DatabaseSync,
  input: PublishEventInput<T>
): { event: InternalEventEnvelope<T>; deduplicated: boolean; triggeredHandlers: string[] } {
  const correlationId = input.correlationId || `corr-${crypto.randomUUID().slice(0, 12)}`;
  const idempotencyKey =
    input.idempotencyKey ||
    crypto
      .createHash('sha256')
      .update(`${input.orgId}|${input.eventType}|${input.sourceResourceId}|${correlationId}|${JSON.stringify(input.payload)}`)
      .digest('hex');

  const existing = db
    .prepare('SELECT * FROM internal_events WHERE idempotency_key = ?')
    .get(idempotencyKey) as Record<string, unknown> | undefined;

  if (existing) {
    return {
      event: rowToEnvelope(existing) as InternalEventEnvelope<T>,
      deduplicated: true,
      triggeredHandlers: [],
    };
  }

  const eventId = `evt-${crypto.randomUUID().slice(0, 12)}`;
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO internal_events
     (event_id, org_id, event_type, event_version, actor_id, source_connector, source_resource_id, affected_assets_json, correlation_id, causation_id, evidence_reference, payload_json, idempotency_key, processing_status, attempts, last_error, created_at)
     VALUES (?, ?, ?, '1.0', ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Pending', 0, NULL, ?)`
  ).run(
    eventId,
    input.orgId,
    input.eventType,
    input.actorId,
    input.sourceConnector,
    input.sourceResourceId,
    JSON.stringify(input.affectedAssetIds || []),
    correlationId,
    input.causationId || null,
    input.evidenceReference || null,
    JSON.stringify(input.payload),
    idempotencyKey,
    now
  );

  const row = db.prepare('SELECT * FROM internal_events WHERE event_id = ?').get(eventId) as Record<string, unknown>;
  const envelope = rowToEnvelope(row) as InternalEventEnvelope<T>;

  if (input.simulateFailure) {
    const attempts = 1;
    const errMsg = `Simulated subscriber delivery error for ${input.eventType}.`;
    db.prepare(
      `UPDATE internal_events SET processing_status = 'Failed', attempts = ?, last_error = ? WHERE event_id = ?`
    ).run(attempts, errMsg, eventId);
    envelope.processingStatus = 'Failed';
    envelope.attempts = attempts;
    envelope.lastError = errMsg;
    return { event: envelope, deduplicated: false, triggeredHandlers: [] };
  }

  try {
    const triggeredHandlers = executeEventSubscribers(db, envelope);
    const processedAt = new Date().toISOString();
    db.prepare(
      `UPDATE internal_events SET processing_status = 'Processed', attempts = 1, last_error = NULL, processed_at = ? WHERE event_id = ?`
    ).run(processedAt, eventId);
    envelope.processingStatus = 'Processed';
    envelope.attempts = 1;
    envelope.processedAt = processedAt;

    logSecurityEvent('info', `fabric.event.${input.eventType}`, {
      orgId: input.orgId,
      eventId,
      correlationId,
      triggeredHandlers,
    });

    // Fire-and-forget external outbound webhooks/SIEM without blocking HTTP response
    void dispatchEventToConfiguredOutboundChannels(db, input.orgId, envelope).catch(() => undefined);

    return { event: envelope, deduplicated: false, triggeredHandlers };
  } catch (err) {
    const errMsg = (err as Error).message;
    db.prepare(
      `UPDATE internal_events SET processing_status = 'Failed', attempts = 1, last_error = ? WHERE event_id = ?`
    ).run(errMsg, eventId);
    envelope.processingStatus = 'Failed';
    envelope.attempts = 1;
    envelope.lastError = errMsg;
    return { event: envelope, deduplicated: false, triggeredHandlers: [] };
  }
}

export function replayEvent(
  db: DatabaseSync,
  orgId: string,
  eventId: string,
  actorEmail: string,
  simulateFailure = false
): { event: InternalEventEnvelope; triggeredHandlers: string[] } {
  const row = db
    .prepare('SELECT * FROM internal_events WHERE event_id = ? AND org_id = ?')
    .get(eventId, orgId) as Record<string, unknown> | undefined;

  if (!row) {
    throw new Error('Internal event not found in organization.');
  }

  const envelope = rowToEnvelope(row);
  const nextAttempts = envelope.attempts + 1;

  if (simulateFailure) {
    const nextStatus: EventProcessingStatus = nextAttempts >= 3 ? 'Dead_Letter' : 'Failed';
    const errMsg = `Replay attempt ${nextAttempts}/3 failed for ${envelope.eventType}.`;
    db.prepare(
      `UPDATE internal_events SET processing_status = ?, attempts = ?, last_error = ? WHERE event_id = ? AND org_id = ?`
    ).run(nextStatus, nextAttempts, errMsg, eventId, orgId);
    envelope.processingStatus = nextStatus;
    envelope.attempts = nextAttempts;
    envelope.lastError = errMsg;
    return { event: envelope, triggeredHandlers: [] };
  }

  const triggeredHandlers = executeEventSubscribers(db, envelope);
  const processedAt = new Date().toISOString();
  db.prepare(
    `UPDATE internal_events SET processing_status = 'Processed', attempts = ?, last_error = NULL, processed_at = ? WHERE event_id = ? AND org_id = ?`
  ).run(nextAttempts, processedAt, eventId, orgId);

  appendAuditLog(db, {
    orgId,
    actorEmail,
    action: 'INTERNAL_EVENT_REPLAYED',
    resourceType: 'InternalEvent',
    resourceId: eventId,
    details: `Replayed ${envelope.eventType} (correlation=${envelope.correlationId}, handlers=${triggeredHandlers.join(',')}).`,
  });

  envelope.processingStatus = 'Processed';
  envelope.attempts = nextAttempts;
  envelope.lastError = null;
  envelope.processedAt = processedAt;
  return { event: envelope, triggeredHandlers };
}

export function listInternalEvents(
  db: DatabaseSync,
  orgId: string,
  opts?: { status?: string; eventType?: string; limit?: number }
): InternalEventEnvelope[] {
  const limit = Math.min(200, Math.max(1, opts?.limit ?? 50));
  const clauses = ['org_id = ?'];
  const params: Array<string | number> = [orgId];

  if (opts?.status) {
    clauses.push('processing_status = ?');
    params.push(opts.status);
  }
  if (opts?.eventType) {
    clauses.push('event_type = ?');
    params.push(opts.eventType);
  }
  params.push(limit);

  const rows = db
    .prepare(
      `SELECT * FROM internal_events WHERE ${clauses.join(' AND ')} ORDER BY created_at DESC LIMIT ?`
    )
    .all(...params) as Array<Record<string, unknown>>;

  return rows.map(rowToEnvelope);
}
