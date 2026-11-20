import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';

const ActionSchema = z.object({
  status: z.enum(['Active', 'Quarantine', 'Revoked']).default('Revoked'),
  reason: z.string().max(300).optional(),
});

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Admin');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const agent = db
    .prepare('SELECT id, name FROM ai_agents WHERE id = ? AND org_id = ?')
    .get(id, authResult.auth.orgId) as { id: string; name: string } | undefined;

  if (!agent) return jsonError('AI Agent not found.', 404, 'NOT_FOUND');

  let body: unknown = {};
  try {
    body = await req.json();
  } catch {
    body = {};
  }

  const parsed = ActionSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid agent state transition.', 400, 'VALIDATION_ERROR');
  }

  const lastActionText =
    parsed.data.status === 'Revoked'
      ? `Credentials revoked by ${authResult.auth.email}${parsed.data.reason ? `: ${parsed.data.reason}` : ''}`
      : parsed.data.status === 'Quarantine'
      ? `Quarantined by ${authResult.auth.email}`
      : `Re-activated by ${authResult.auth.email}`;

  db.prepare(
    `UPDATE ai_agents SET status = ?, last_action = ? WHERE id = ? AND org_id = ?`
  ).run(parsed.data.status, lastActionText, id, authResult.auth.orgId);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: `AI_AGENT_${parsed.data.status.toUpperCase()}`,
    resourceType: 'AIAgent',
    resourceId: id,
    details: `${agent.name} transitioned to ${parsed.data.status}.`,
  });

  return jsonOk({ id, status: parsed.data.status, lastAction: lastActionText });
}
