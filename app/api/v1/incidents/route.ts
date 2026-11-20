import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { computeOrganizationSnapshot } from '@/lib/domain-mappers';
import { publishEvent } from '@/lib/fabric/event-bus';

const CreateIncidentSchema = z.object({
  title: z.string().min(3).max(200),
  severity: z.enum(['SEV-1', 'SEV-2', 'SEV-3']),
  affectedAsset: z.string().min(2).max(200),
  summary: z.string().max(1000).optional(),
  playbookName: z.string().max(160).optional(),
});

function formatIncident(r: {
  id: string;
  title: string;
  severity: 'SEV-1' | 'SEV-2' | 'SEV-3';
  status: 'Open' | 'Contained' | 'Recovered' | 'Closed';
  affected_asset: string;
  owner: string;
  summary: string;
  playbook_name: string;
  actions_taken_json: string;
  opened_at: string;
  closed_at: string | null;
}) {
  return {
    id: r.id,
    title: r.title,
    severity: r.severity,
    status: r.status,
    affectedAsset: r.affected_asset,
    owner: r.owner,
    summary: r.summary,
    playbookName: r.playbook_name,
    actionsTaken: JSON.parse(r.actions_taken_json || '[]') as string[],
    openedAt: r.opened_at,
    closedAt: r.closed_at || undefined,
  };
}

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const rows = db
    .prepare(
      `SELECT id, title, severity, status, affected_asset, owner, summary, playbook_name, actions_taken_json, opened_at, closed_at
       FROM incidents WHERE org_id = ? ORDER BY opened_at DESC`
    )
    .all(authResult.auth.orgId) as Array<{
    id: string;
    title: string;
    severity: 'SEV-1' | 'SEV-2' | 'SEV-3';
    status: 'Open' | 'Contained' | 'Recovered' | 'Closed';
    affected_asset: string;
    owner: string;
    summary: string;
    playbook_name: string;
    actions_taken_json: string;
    opened_at: string;
    closed_at: string | null;
  }>;

  return jsonOk({ incidents: rows.map(formatIncident) });
}

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = CreateIncidentSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid incident payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const id = `inc-${crypto.randomUUID().slice(0, 8)}`;
  const now = new Date().toISOString();
  const actions = [
    `Incident created by ${authResult.auth.email} in Trustrail Incident Command.`,
    'Recorded immutable audit chain entry.',
  ];

  // Attempt Slack notification ONLY if SLACK_WEBHOOK_URL is genuinely configured
  let slackNotified = false;
  if (process.env.SLACK_WEBHOOK_URL) {
    try {
      const resp = await fetch(process.env.SLACK_WEBHOOK_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: `[Trustrail ${parsed.data.severity}] ${parsed.data.title} — Asset: ${parsed.data.affectedAsset}`,
        }),
      });
      if (resp.ok) {
        slackNotified = true;
        actions.push('Dispatched real-time alert via configured Slack webhook.');
      }
    } catch {
      actions.push('Slack webhook configured but dispatch failed; incident persisted locally.');
    }
  } else {
    actions.push('Slack integration not configured (SLACK_WEBHOOK_URL unset); alert queued locally.');
  }

  db.prepare(
    `INSERT INTO incidents (id, org_id, title, severity, status, affected_asset, owner, summary, playbook_name, actions_taken_json, opened_at)
     VALUES (?, ?, ?, ?, 'Open', ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    authResult.auth.orgId,
    parsed.data.title.trim(),
    parsed.data.severity,
    parsed.data.affectedAsset.trim(),
    authResult.auth.name,
    parsed.data.summary?.trim() || 'Security incident initiated via Trustrail Incident Command.',
    parsed.data.playbookName?.trim() || 'Containment & Credential Rotation Playbook',
    JSON.stringify(actions),
    now
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'INCIDENT_OPENED',
    resourceType: 'Incident',
    resourceId: id,
    details: `${parsed.data.severity} "${parsed.data.title}" on ${parsed.data.affectedAsset}.`,
  });

  publishEvent(db, {
    orgId: authResult.auth.orgId,
    eventType: 'incident.created',
    actorId: authResult.auth.email,
    sourceConnector: 'incident_command',
    sourceResourceId: id,
    payload: {
      title: parsed.data.title.trim(),
      severity: parsed.data.severity,
      affectedAsset: parsed.data.affectedAsset.trim(),
    },
  });

  const rows = db
    .prepare(
      `SELECT id, title, severity, status, affected_asset, owner, summary, playbook_name, actions_taken_json, opened_at, closed_at
       FROM incidents WHERE org_id = ? ORDER BY opened_at DESC`
    )
    .all(authResult.auth.orgId) as Array<{
    id: string;
    title: string;
    severity: 'SEV-1' | 'SEV-2' | 'SEV-3';
    status: 'Open' | 'Contained' | 'Recovered' | 'Closed';
    affected_asset: string;
    owner: string;
    summary: string;
    playbook_name: string;
    actions_taken_json: string;
    opened_at: string;
    closed_at: string | null;
  }>;

  const incidents = rows.map(formatIncident);
  return jsonOk(
    {
      incident: incidents.find((i) => i.id === id),
      incidents,
      slackNotified,
      organization: computeOrganizationSnapshot(db, authResult.auth.orgId),
    },
    201
  );
}
