import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { parseConnectorConfig } from '@/lib/security/connector-config';
import { assertSafeExternalUrl } from '@/lib/security/ssrf';
import { computeOrganizationSnapshot } from '@/lib/domain-mappers';

const OutboundTestSchema = z.object({
  webhookUrl: z.string().max(500).optional(),
  summaryOnly: z.boolean().default(true),
});

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Admin');
  if ('error' in authResult) return authResult.error;

  let body: unknown = {};
  try {
    body = await req.json();
  } catch {
    body = {};
  }

  const parsed = OutboundTestSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid outbound webhook request.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const conn = db
    .prepare(`SELECT id, config_json FROM connectors WHERE org_id = ? AND provider_key = 'slack'`)
    .get(authResult.auth.orgId) as { id: string; config_json: string | null } | undefined;
  const cfg = parseConnectorConfig(
    conn?.config_json,
    conn ? { orgId: authResult.auth.orgId, connectorId: conn.id } : undefined
  );

  const targetUrl = parsed.data.webhookUrl?.trim() || cfg.webhookUrl || process.env.SLACK_WEBHOOK_URL;
  if (!targetUrl) {
    return jsonError(
      'No outbound webhook URL configured. Save a Slack, Discord, or custom HTTPS webhook URL in Integrations.',
      424,
      'CREDENTIALS_REQUIRED'
    );
  }

  let safeUrl: URL;
  try {
    safeUrl = await assertSafeExternalUrl(targetUrl, { requireHttps: true });
  } catch (err) {
    return jsonError((err as Error).message, 400, 'INVALID_WEBHOOK_URL');
  }

  const snapshot = computeOrganizationSnapshot(db, authResult.auth.orgId);
  if (!snapshot) {
    return jsonError('Organization not found.', 404, 'NOT_FOUND');
  }
  const now = new Date().toISOString();
  const textSummary = `[Trustrail Security Cloud] ${snapshot.name} (${snapshot.securityRating}, Risk ${snapshot.riskScore}/100): ${snapshot.openFindingsCount} open findings, ${snapshot.criticalPathsCount} critical attack paths, ${snapshot.activeIncidentsCount} active incidents.`;

  try {
    const res = await fetch(safeUrl.toString(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: textSummary,
        content: textSummary,
        event: 'trustrail.security_digest',
        organization: {
          id: snapshot.id,
          name: snapshot.name,
          rating: snapshot.securityRating,
          riskScore: snapshot.riskScore,
          openFindings: snapshot.openFindingsCount,
        },
        dispatchedAt: now,
      }),
      signal: AbortSignal.timeout(8000),
    });

    db.prepare(
      `INSERT INTO notification_deliveries (id, org_id, channel, event_type, status, http_status, summary, created_at)
       VALUES (?, ?, 'webhook', 'trustrail.security_digest', ?, ?, ?, ?)`
    ).run(
      `notif-${crypto.randomUUID().slice(0, 8)}`,
      authResult.auth.orgId,
      res.ok ? 'Delivered' : 'Failed',
      res.status,
      textSummary,
      now
    );

    if (!res.ok) {
      return jsonError(`Webhook receiver returned HTTP ${res.status}.`, 502, 'WEBHOOK_DELIVERY_FAILED');
    }

    if (conn) {
      db.prepare(
        `UPDATE connectors SET status = 'Connected', availability_state = 'CONNECTED', health_check = 'Healthy', last_sync = ? WHERE id = ? AND org_id = ?`
      ).run(now, conn.id, authResult.auth.orgId);
    }

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'OUTBOUND_WEBHOOK_DISPATCHED',
      resourceType: 'Webhook',
      resourceId: conn?.id || 'outbound',
      details: `Dispatched security digest alert via HTTPS webhook (HTTP ${res.status}).`,
    });

    return jsonOk({
      delivered: true,
      httpStatus: res.status,
      dispatchedAt: now,
      summary: textSummary,
    });
  } catch (err) {
    db.prepare(
      `INSERT INTO notification_deliveries (id, org_id, channel, event_type, status, http_status, summary, created_at)
       VALUES (?, ?, 'webhook', 'trustrail.security_digest', 'Error', NULL, ?, ?)`
    ).run(
      `notif-${crypto.randomUUID().slice(0, 8)}`,
      authResult.auth.orgId,
      (err as Error).message.slice(0, 240),
      now
    );
    return jsonError(`Outbound webhook dispatch error: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
  }
}

