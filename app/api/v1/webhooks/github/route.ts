import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk } from '@/lib/api-response';
import { verifyGithubWebhookSignature } from '@/lib/security/crypto';
import { publishEvent } from '@/lib/fabric/event-bus';

export async function POST(req: NextRequest) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret) {
    return jsonError(
      'GITHUB_WEBHOOK_SECRET is not configured on the server; webhook processing rejected.',
      503,
      'WEBHOOK_SECRET_NOT_CONFIGURED'
    );
  }

  const rawBody = await req.text();
  const sigHeader = req.headers.get('x-hub-signature-256');
  const deliveryId = req.headers.get('x-github-delivery') || crypto.randomUUID();
  const eventType = req.headers.get('x-github-event') || 'unknown';

  if (!verifyGithubWebhookSignature(rawBody, sigHeader, secret)) {
    return jsonError('Invalid GitHub webhook HMAC-SHA256 signature.', 401, 'INVALID_WEBHOOK_SIGNATURE');
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(rawBody) as Record<string, unknown>;
  } catch {
    return jsonError('Malformed webhook JSON payload.', 400, 'INVALID_JSON');
  }

  const db = getDb();
  const existingDelivery = db
    .prepare('SELECT delivery_id FROM webhook_deliveries WHERE delivery_id = ?')
    .get(deliveryId);

  if (existingDelivery) {
    return jsonOk({ accepted: true, duplicate: true, deliveryId });
  }

  const repoFullName =
    ((payload.repository as Record<string, unknown> | undefined)?.full_name as string | undefined) || '';

  const matchedProject = db
    .prepare('SELECT id, org_id, name FROM projects WHERE repo_url LIKE ? LIMIT 1')
    .get(`%${repoFullName}%`) as { id: string; org_id: string; name: string } | undefined;

  const targetOrgId = matchedProject?.org_id || 'org-acme';
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO webhook_deliveries (delivery_id, org_id, provider, event_type, received_at)
     VALUES (?, ?, 'github', ?, ?)`
  ).run(deliveryId, targetOrgId, eventType, now);

  appendAuditLog(db, {
    orgId: targetOrgId,
    actorEmail: 'webhook@github.com',
    action: 'GITHUB_WEBHOOK_PROCESSED',
    resourceType: 'Webhook',
    resourceId: deliveryId,
    details: `Verified GitHub ${eventType} webhook for ${repoFullName || 'repository'}.`,
  });

  const actionStr = String(payload.action || '');
  const mappedEvent =
    eventType === 'pull_request'
      ? actionStr === 'synchronize'
        ? 'pull_request.updated'
        : 'pull_request.opened'
      : 'repository.connected';

  publishEvent(db, {
    orgId: targetOrgId,
    eventType: mappedEvent,
    actorId: 'webhook@github.com',
    sourceConnector: 'github',
    sourceResourceId: repoFullName || deliveryId,
    affectedAssetIds: matchedProject ? [matchedProject.id] : [],
    correlationId: `corr-${deliveryId}`,
    payload: { deliveryId, githubEvent: eventType, action: actionStr || null },
  });

  return jsonOk({
    accepted: true,
    duplicate: false,
    deliveryId,
    eventType,
    matchedProjectId: matchedProject?.id || null,
  });
}
