import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { evaluatePolicies, type PolicyRule } from '@/lib/engines/policy-engine';

const ExecuteAgentToolSchema = z.object({
  toolName: z.string().min(1).max(120),
  hasHumanApproval: z.boolean().optional(),
  requiresHumanApproval: z.boolean().optional(),
});

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Developer');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const agent = db
    .prepare(
      `SELECT id, name, allowlisted_tools_json, status, actions_used, action_limit
       FROM ai_agents WHERE id = ? AND org_id = ?`
    )
    .get(id, authResult.auth.orgId) as
    | {
        id: string;
        name: string;
        allowlisted_tools_json: string;
        status: string;
        actions_used: number;
        action_limit: number;
      }
    | undefined;

  if (!agent) {
    return jsonError('AI Agent not found.', 404, 'NOT_FOUND');
  }

  if (agent.status === 'Revoked' || agent.status === 'Quarantine') {
    return jsonError(
      `Agent "${agent.name}" is currently ${agent.status} and cannot execute tools.`,
      403,
      'AGENT_BLOCKED'
    );
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = ExecuteAgentToolSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('toolName is required.', 400, 'VALIDATION_ERROR');
  }

  const allowlist = JSON.parse(agent.allowlisted_tools_json || '[]') as string[];
  const toolAllowed = allowlist.includes(parsed.data.toolName);

  const policies = db
    .prepare('SELECT id, name, engine, severity, status, rule_code as ruleCode FROM policies WHERE org_id = ?')
    .all(authResult.auth.orgId) as unknown as PolicyRule[];

  const decision = evaluatePolicies(policies, {
    type: 'agent_action',
    agentToolAllowlisted: toolAllowed,
    agentActionsUsed: agent.actions_used,
    agentActionLimit: agent.action_limit,
    requiresHumanApproval: parsed.data.requiresHumanApproval,
    hasHumanApproval: parsed.data.hasHumanApproval,
  });

  if (!decision.allowed) {
    // If disallowed tool attempted, quarantine agent & record alert
    if (!toolAllowed) {
      db.prepare(
        `UPDATE ai_agents SET status = 'Quarantine', canary_triggered = 1, last_action = ? WHERE id = ? AND org_id = ?`
      ).run(`Blocked unauthorized tool invocation: ${parsed.data.toolName}`, id, authResult.auth.orgId);
    }

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'AI_AGENT_ACTION_DENIED',
      resourceType: 'AIAgent',
      resourceId: id,
      details: `Blocked ${agent.name} invoking "${parsed.data.toolName}": ${decision.violatedRules.map((v) => v.reason).join('; ')}`,
    });

    return jsonError(
      `Agent tool call denied: ${decision.violatedRules.map((v) => v.reason).join('; ') || decision.decision}`,
      403,
      'AGENT_POLICY_DENIED',
      { decision }
    );
  }

  const nextUsed = agent.actions_used + 1;
  db.prepare(
    `UPDATE ai_agents SET actions_used = ?, last_action = ? WHERE id = ? AND org_id = ?`
  ).run(nextUsed, `Executed allowlisted tool "${parsed.data.toolName}" (${nextUsed}/${agent.action_limit})`, id, authResult.auth.orgId);

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'AI_AGENT_TOOL_EXECUTED',
    resourceType: 'AIAgent',
    resourceId: id,
    details: `${agent.name} executed allowlisted tool "${parsed.data.toolName}" (${nextUsed}/${agent.action_limit}).`,
  });

  return jsonOk({
    allowed: true,
    agentId: id,
    toolName: parsed.data.toolName,
    actionsUsed: nextUsed,
    actionLimit: agent.action_limit,
    decision,
  });
}
