import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';

const CreateAgentSchema = z.object({
  name: z.string().min(2).max(120),
  type: z.enum(['LLM Agent', 'MCP Server', 'Autonomous Worker']),
  ownerTeam: z.string().min(2).max(100),
  permissions: z.array(z.string()).default([]),
  allowlistedTools: z.array(z.string()).min(1),
  riskLevel: z.enum(['High', 'Medium', 'Low']).default('Medium'),
  actionLimit: z.number().int().min(1).max(1000).default(25),
});

function formatAgentRow(r: {
  id: string;
  name: string;
  type: string;
  owner_team: string;
  permissions_json: string;
  allowlisted_tools_json: string;
  status: string;
  risk_level: string;
  actions_used: number;
  action_limit: number;
  last_action: string;
  canary_triggered: number;
}) {
  return {
    id: r.id,
    name: r.name,
    type: r.type,
    ownerTeam: r.owner_team,
    permissions: JSON.parse(r.permissions_json || '[]') as string[],
    allowlistedTools: JSON.parse(r.allowlisted_tools_json || '[]') as string[],
    status: r.status,
    riskLevel: r.risk_level,
    actionsUsed: r.actions_used,
    actionLimit: r.action_limit,
    lastAction: r.last_action,
    canaryTriggered: Boolean(r.canary_triggered),
  };
}

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const rows = db
    .prepare(
      `SELECT id, name, type, owner_team, permissions_json, allowlisted_tools_json, status, risk_level, actions_used, action_limit, last_action, canary_triggered
       FROM ai_agents WHERE org_id = ? ORDER BY created_at DESC`
    )
    .all(authResult.auth.orgId) as Array<{
    id: string;
    name: string;
    type: string;
    owner_team: string;
    permissions_json: string;
    allowlisted_tools_json: string;
    status: string;
    risk_level: string;
    actions_used: number;
    action_limit: number;
    last_action: string;
    canary_triggered: number;
  }>;

  return jsonOk({ aiAgents: rows.map(formatAgentRow) });
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

  const parsed = CreateAgentSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid AI agent registration payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const id = `agent-${crypto.randomUUID().slice(0, 8)}`;
  const now = new Date().toISOString();

  db.prepare(
    `INSERT INTO ai_agents (id, org_id, name, type, owner_team, permissions_json, allowlisted_tools_json, status, risk_level, actions_used, action_limit, last_action, canary_triggered, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, 'Active', ?, 0, ?, 'Registered in Trustrail AI Agent Guard.', 0, ?)`
  ).run(
    id,
    authResult.auth.orgId,
    parsed.data.name.trim(),
    parsed.data.type,
    parsed.data.ownerTeam.trim(),
    JSON.stringify(parsed.data.permissions),
    JSON.stringify(parsed.data.allowlistedTools),
    parsed.data.riskLevel,
    parsed.data.actionLimit,
    now
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'AI_AGENT_REGISTERED',
    resourceType: 'AIAgent',
    resourceId: id,
    details: `Registered ${parsed.data.name} (${parsed.data.type}) with allowlisted tools [${parsed.data.allowlistedTools.join(', ')}].`,
  });

  const rows = db
    .prepare(
      `SELECT id, name, type, owner_team, permissions_json, allowlisted_tools_json, status, risk_level, actions_used, action_limit, last_action, canary_triggered
       FROM ai_agents WHERE org_id = ? ORDER BY created_at DESC`
    )
    .all(authResult.auth.orgId) as Array<{
    id: string;
    name: string;
    type: string;
    owner_team: string;
    permissions_json: string;
    allowlisted_tools_json: string;
    status: string;
    risk_level: string;
    actions_used: number;
    action_limit: number;
    last_action: string;
    canary_triggered: number;
  }>;

  const formatted = rows.map(formatAgentRow);
  return jsonOk({ aiAgent: formatted.find((a) => a.id === id), aiAgents: formatted }, 201);
}
