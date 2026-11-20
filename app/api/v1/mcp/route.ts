import crypto from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';
import { getDb, appendAuditLog } from '@/lib/db';
import { requireAuth } from '@/lib/api-response';
import { computeOrganizationSnapshot, listEnrichedFindings } from '@/lib/domain-mappers';
import { synthesizeAttackPaths } from '@/lib/engines/attack-path-engine';
import { evaluatePolicies, type PolicyRule } from '@/lib/engines/policy-engine';
import { executeUnifiedScan } from '@/lib/engines/scanner-engine';
import { computeChangeStateHash } from '@/lib/engines/intent-lock';
import { sha256 } from '@/lib/security/crypto';
import { formatConnectorRow } from '@/lib/connectors/hub';
import { publishEvent } from '@/lib/fabric/event-bus';

const MCP_TOOLS = [
  {
    name: 'trustrail_list_findings',
    description: 'List prioritized open security findings for the authenticated organization.',
    inputSchema: {
      type: 'object',
      properties: {
        severity: { type: 'string', enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'ALL'] },
      },
    },
  },
  {
    name: 'trustrail_get_attack_paths',
    description: 'Compute active multi-hop attack paths from open vulnerabilities to crown-jewel assets.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'trustrail_evaluate_policy',
    description: 'Evaluate a CI/CD pipeline, Terraform plan, or AI agent action against enforced OPA policies.',
    inputSchema: {
      type: 'object',
      properties: {
        type: { type: 'string', enum: ['change_contract', 'terraform_plan', 'ci_pipeline', 'agent_action'] },
        hasPublicS3: { type: 'boolean' },
        hasOpenAdminPort: { type: 'boolean' },
        hasCosignSignature: { type: 'boolean' },
        maxCvss: { type: 'number' },
      },
      required: ['type'],
    },
  },
  {
    name: 'trustrail_run_scan',
    description: 'Run SAST/Secret/SCA/IaC static analysis on supplied code or manifests (requires Developer+).',
    inputSchema: {
      type: 'object',
      properties: {
        projectName: { type: 'string' },
        codeContent: { type: 'string' },
        packageJsonContent: { type: 'string' },
        terraformContent: { type: 'string' },
      },
      required: ['projectName'],
    },
  },
  {
    name: 'trustrail_request_remediation',
    description: 'Propose a remediation change contract under IntentLock human approval (never auto-executes high-risk changes).',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        targetAsset: { type: 'string' },
        purpose: { type: 'string' },
        patchPayload: { type: 'object' },
      },
      required: ['title', 'targetAsset', 'purpose'],
    },
  },
  {
    name: 'trustrail_get_security_posture',
    description: 'Get real-time security posture score, rating, open findings count, and compliance percentage.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'trustrail_get_integration_health',
    description: 'Inspect lifecycle health, sync cursors, and errors across all configured organization connectors.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'trustrail_get_incidents',
    description: 'List active and historical security incidents for the authenticated organization.',
    inputSchema: {
      type: 'object',
      properties: { status: { type: 'string', enum: ['Open', 'Contained', 'Recovered', 'Closed', 'ALL'] } },
    },
  },
  {
    name: 'trustrail_analyze_change',
    description: 'Compute IntentLock SHA-256 state hash and evaluate policy compliance before applying a proposed change.',
    inputSchema: {
      type: 'object',
      properties: {
        targetAsset: { type: 'string' },
        purpose: { type: 'string' },
        payload: { type: 'object' },
      },
      required: ['targetAsset', 'purpose'],
    },
  },
  {
    name: 'trustrail_create_incident',
    description: 'Create a tracked security incident and emit event bus notifications (requires Developer+).',
    inputSchema: {
      type: 'object',
      properties: {
        title: { type: 'string' },
        severity: { type: 'string', enum: ['SEV-1', 'SEV-2', 'SEV-3'] },
        affectedAsset: { type: 'string' },
        summary: { type: 'string' },
      },
      required: ['title', 'severity', 'affectedAsset'],
    },
  },
  {
    name: 'trustrail_create_remediation_pr',
    description: 'Generate a gated remediation patch run & IntentLock proposal for a finding (requires Developer+; human approval required).',
    inputSchema: {
      type: 'object',
      properties: {
        findingId: { type: 'string' },
        patchDiff: { type: 'string' },
      },
      required: ['findingId'],
    },
  },
];

function rpcResult(id: unknown, result: unknown) {
  return NextResponse.json({ jsonrpc: '2.0', id: id ?? null, result });
}

function rpcError(id: unknown, code: number, message: string, status = 400) {
  return NextResponse.json({ jsonrpc: '2.0', id: id ?? null, error: { code, message } }, { status });
}

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) {
    return rpcError(null, -32001, 'Unauthorized: valid Bearer token or session required.', 401);
  }

  let body: { jsonrpc?: string; id?: unknown; method?: string; params?: Record<string, unknown> };
  try {
    body = (await req.json()) as typeof body;
  } catch {
    return rpcError(null, -32700, 'Parse error: invalid JSON.');
  }

  if (body.jsonrpc !== '2.0' || !body.method) {
    return rpcError(body.id, -32600, 'Invalid JSON-RPC 2.0 Request.');
  }

  if (body.method === 'initialize') {
    return rpcResult(body.id, {
      protocolVersion: '2025-03-26',
      serverInfo: { name: 'trustrail-mcp-server', version: '1.0.0' },
      capabilities: { tools: {} },
    });
  }

  if (body.method === 'tools/list') {
    return rpcResult(body.id, { tools: MCP_TOOLS });
  }

  if (body.method === 'tools/call') {
    const toolName = String(body.params?.name || '');
    const args = (body.params?.arguments || {}) as Record<string, unknown>;
    const db = getDb();

    if (toolName === 'trustrail_list_findings') {
      let findings = listEnrichedFindings(db, authResult.auth.orgId);
      const sev = typeof args.severity === 'string' ? args.severity : 'ALL';
      if (sev !== 'ALL') {
        findings = findings.filter((f) => f.severity === sev);
      }
      appendAuditLog(db, {
        orgId: authResult.auth.orgId,
        actorEmail: authResult.auth.email,
        action: 'MCP_TOOL_CALL',
        resourceType: 'MCP',
        resourceId: toolName,
        details: `Returned ${findings.length} tenant-isolated findings via MCP.`,
      });
      return rpcResult(body.id, {
        content: [{ type: 'text', text: JSON.stringify({ findings }) }],
      });
    }

    if (toolName === 'trustrail_get_attack_paths') {
      const assets = db
        .prepare('SELECT id, org_id as orgId, name, asset_type as assetType, owner, internet_exposed as internetExposed, criticality FROM assets WHERE org_id = ?')
        .all(authResult.auth.orgId) as Array<{
        id: string;
        orgId: string;
        name: string;
        assetType: string;
        owner: string;
        internetExposed: number;
        criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
      }>;
      const edges = db
        .prepare('SELECT id, org_id as orgId, source_asset_id as sourceAssetId, target_asset_id as targetAssetId, relation, evidence FROM graph_edges WHERE org_id = ?')
        .all(authResult.auth.orgId) as Array<{
        id: string;
        orgId: string;
        sourceAssetId: string;
        targetAssetId: string;
        relation: string;
        evidence: string;
      }>;
      const findings = db
        .prepare('SELECT id, title, severity, category, asset_id as assetId, asset_name as assetName, status, cvss FROM findings WHERE org_id = ?')
        .all(authResult.auth.orgId) as Array<{
        id: string;
        title: string;
        severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
        category: string;
        assetId: string | null;
        assetName: string;
        status: string;
        cvss: number;
      }>;

      const attackPaths = synthesizeAttackPaths(
        assets.map((a) => ({ ...a, internetExposed: Boolean(a.internetExposed) })),
        edges,
        findings.filter((f) => f.assetId).map((f) => ({ ...f, assetId: f.assetId! }))
      );

      return rpcResult(body.id, {
        content: [{ type: 'text', text: JSON.stringify({ attackPaths }) }],
      });
    }

    if (toolName === 'trustrail_evaluate_policy') {
      const policies = db
        .prepare('SELECT id, name, engine, severity, status, rule_code as ruleCode FROM policies WHERE org_id = ?')
        .all(authResult.auth.orgId) as unknown as PolicyRule[];
      const orgRow = db
        .prepare('SELECT enforcement_mode FROM organizations WHERE id = ?')
        .get(authResult.auth.orgId) as { enforcement_mode?: 'Observe' | 'Recommend' | 'Enforce' } | undefined;
      const decision = evaluatePolicies(
        policies,
        {
          type: (args.type as 'change_contract' | 'terraform_plan' | 'ci_pipeline' | 'agent_action') || 'ci_pipeline',
          hasPublicS3: Boolean(args.hasPublicS3),
          hasOpenAdminPort: Boolean(args.hasOpenAdminPort),
          hasCosignSignature: args.hasCosignSignature === undefined ? undefined : Boolean(args.hasCosignSignature),
          maxCvss: typeof args.maxCvss === 'number' ? args.maxCvss : undefined,
        },
        orgRow?.enforcement_mode || 'Enforce'
      );
      return rpcResult(body.id, {
        content: [{ type: 'text', text: JSON.stringify(decision) }],
      });
    }

    if (toolName === 'trustrail_run_scan') {
      if (authResult.auth.role === 'Viewer') {
        return rpcError(body.id, -32003, 'Forbidden: Viewer role cannot trigger scans via MCP.', 403);
      }
      const scanRes = executeUnifiedScan({
        projectName: String(args.projectName || 'mcp-target'),
        codeContent: typeof args.codeContent === 'string' ? args.codeContent : undefined,
        packageJsonContent: typeof args.packageJsonContent === 'string' ? args.packageJsonContent : undefined,
        terraformContent: typeof args.terraformContent === 'string' ? args.terraformContent : undefined,
      });
      appendAuditLog(db, {
        orgId: authResult.auth.orgId,
        actorEmail: authResult.auth.email,
        action: 'MCP_SCAN_EXECUTED',
        resourceType: 'MCP',
        resourceId: String(args.projectName || 'mcp-target'),
        details: `MCP scan detected ${scanRes.findings.length} findings across ${scanRes.filesScanned} file(s).`,
      });
      return rpcResult(body.id, {
        content: [{ type: 'text', text: JSON.stringify(scanRes) }],
      });
    }

    if (toolName === 'trustrail_request_remediation') {
      if (authResult.auth.role === 'Viewer') {
        return rpcError(body.id, -32003, 'Forbidden: Viewer role cannot propose remediation changes.', 403);
      }
      const id = `change-${crypto.randomUUID().slice(0, 8)}`;
      const now = new Date().toISOString();
      const targetAsset = String(args.targetAsset || 'unknown-asset');
      const purpose = String(args.purpose || 'Automated remediation proposal');
      const payload = (args.patchPayload as Record<string, unknown>) || { proposedBy: 'mcp' };
      const prevHash = `sha256:${sha256(targetAsset + now)}`;
      const newHash = computeChangeStateHash({
        targetAsset,
        previousStateHash: prevHash,
        newStatePayload: payload,
        purpose,
      });

      // Always enters 'Locked' state awaiting human approval — never auto-approved or executed!
      db.prepare(
        `INSERT INTO change_contracts (id, org_id, title, actor, project, target_asset, previous_state_hash, new_state_payload, new_state_hash, approved_hash, purpose, risk_level, intent_lock_status, approved_by, evidence_summary, created_at)
         VALUES (?, ?, ?, ?, 'mcp-proposal', ?, ?, ?, ?, NULL, ?, 'High', 'Locked', NULL, 'Proposed via MCP; awaiting human IntentLock approval.', ?)`
      ).run(
        id,
        authResult.auth.orgId,
        String(args.title || 'MCP Remediation Proposal'),
        `MCP (${authResult.auth.email})`,
        targetAsset,
        prevHash,
        JSON.stringify(payload),
        newHash,
        purpose,
        now
      );

      appendAuditLog(db, {
        orgId: authResult.auth.orgId,
        actorEmail: authResult.auth.email,
        action: 'MCP_REMEDIATION_PROPOSED',
        resourceType: 'ChangeContract',
        resourceId: id,
        details: `MCP created IntentLock contract ${id} in Locked state (requires human approval).`,
      });

      return rpcResult(body.id, {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              contractId: id,
              intentLockStatus: 'Locked',
              requiresHumanApproval: true,
              hash: newHash,
            }),
          },
        ],
      });
    }

    if (toolName === 'trustrail_get_security_posture') {
      const posture = computeOrganizationSnapshot(db, authResult.auth.orgId);
      return rpcResult(body.id, {
        content: [{ type: 'text', text: JSON.stringify({ posture }) }],
      });
    }

    if (toolName === 'trustrail_get_integration_health') {
      const rows = db
        .prepare('SELECT * FROM connectors WHERE org_id = ? ORDER BY name ASC')
        .all(authResult.auth.orgId) as Array<Record<string, unknown>>;
      const connectors = rows.map((r) => formatConnectorRow(r, authResult.auth.orgId));
      return rpcResult(body.id, {
        content: [{ type: 'text', text: JSON.stringify({ connectors }) }],
      });
    }

    if (toolName === 'trustrail_get_incidents') {
      const rows = db
        .prepare(
          `SELECT id, title, severity, status, affected_asset as affectedAsset, owner, opened_at as openedAt
           FROM incidents WHERE org_id = ? ORDER BY opened_at DESC`
        )
        .all(authResult.auth.orgId) as Array<Record<string, unknown>>;
      const statusFilter = typeof args.status === 'string' ? args.status : 'ALL';
      const filtered = statusFilter === 'ALL' ? rows : rows.filter((r) => r.status === statusFilter);
      return rpcResult(body.id, {
        content: [{ type: 'text', text: JSON.stringify({ incidents: filtered }) }],
      });
    }

    if (toolName === 'trustrail_analyze_change') {
      const targetAsset = String(args.targetAsset || 'unknown-asset');
      const purpose = String(args.purpose || 'MCP change analysis');
      const payload = (args.payload as Record<string, unknown>) || {};
      const stateHash = computeChangeStateHash({
        targetAsset,
        previousStateHash: 'baseline',
        newStatePayload: payload,
        purpose,
      });
      const policies = db
        .prepare('SELECT id, name, engine, severity, status, rule_code as ruleCode FROM policies WHERE org_id = ?')
        .all(authResult.auth.orgId) as unknown as PolicyRule[];
      const decision = evaluatePolicies(
        policies,
        {
          type: 'change_contract',
          hasPublicS3: Boolean(payload.acl === 'public-read' || payload.acl === 'public-read-write'),
          hasOpenAdminPort: Boolean(payload.openAdminPort),
        },
        'Enforce'
      );
      return rpcResult(body.id, {
        content: [{ type: 'text', text: JSON.stringify({ targetAsset, stateHash, policyDecision: decision }) }],
      });
    }

    if (toolName === 'trustrail_create_incident') {
      if (authResult.auth.role === 'Viewer') {
        return rpcError(body.id, -32003, 'Forbidden: Viewer role cannot create incidents via MCP.', 403);
      }
      const incId = `inc-${crypto.randomUUID().slice(0, 8)}`;
      const now = new Date().toISOString();
      const severity = args.severity === 'SEV-1' || args.severity === 'SEV-2' || args.severity === 'SEV-3' ? args.severity : 'SEV-2';
      const title = String(args.title || 'MCP Reported Security Incident');
      const affectedAsset = String(args.affectedAsset || 'unknown-asset');
      db.prepare(
        `INSERT INTO incidents (id, org_id, title, severity, status, affected_asset, owner, summary, playbook_name, actions_taken_json, opened_at)
         VALUES (?, ?, ?, ?, 'Open', ?, ?, ?, 'MCP Automated Triage', ?, ?)`
      ).run(
        incId,
        authResult.auth.orgId,
        title,
        severity,
        affectedAsset,
        authResult.auth.name,
        String(args.summary || 'Created via MCP server.'),
        JSON.stringify([`Created via MCP by ${authResult.auth.email}`]),
        now
      );
      publishEvent(db, {
        orgId: authResult.auth.orgId,
        eventType: 'incident.created',
        actorId: authResult.auth.email,
        sourceConnector: 'mcp_server',
        sourceResourceId: incId,
        payload: { title, severity, affectedAsset },
      });
      return rpcResult(body.id, {
        content: [{ type: 'text', text: JSON.stringify({ incidentId: incId, severity, status: 'Open' }) }],
      });
    }

    if (toolName === 'trustrail_create_remediation_pr') {
      if (authResult.auth.role === 'Viewer') {
        return rpcError(body.id, -32003, 'Forbidden: Viewer role cannot create remediation runs via MCP.', 403);
      }
      const findingId = String(args.findingId || '');
      const finding = db
        .prepare('SELECT id, title, file_path, suggested_fix FROM findings WHERE id = ? AND org_id = ?')
        .get(findingId, authResult.auth.orgId) as
        | { id: string; title: string; file_path: string | null; suggested_fix: string }
        | undefined;
      if (!finding) {
        return rpcError(body.id, -32602, `Finding "${findingId}" not found in organization.`);
      }
      const runId = `rem-${crypto.randomUUID().slice(0, 8)}`;
      const now = new Date().toISOString();
      const patchDiff =
        typeof args.patchDiff === 'string' && args.patchDiff.trim()
          ? args.patchDiff
          : `--- a/${finding.file_path || 'src/app.ts'}\n+++ b/${finding.file_path || 'src/app.ts'}\n+ // ${finding.suggested_fix}`;
      db.prepare(
        `INSERT INTO remediation_runs (id, org_id, finding_id, status, patch_diff, verification_command, verification_passed, rescan_clean, created_by, created_at)
         VALUES (?, ?, ?, 'Patch_Generated', ?, 'npm test && trustrail scan .', 0, 0, ?, ?)`
      ).run(runId, authResult.auth.orgId, finding.id, patchDiff, authResult.auth.email, now);
      publishEvent(db, {
        orgId: authResult.auth.orgId,
        eventType: 'remediation.proposed',
        actorId: authResult.auth.email,
        sourceConnector: 'mcp_server',
        sourceResourceId: runId,
        payload: { findingId: finding.id, requiresHumanApproval: true },
      });
      return rpcResult(body.id, {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              remediationRunId: runId,
              findingId: finding.id,
              status: 'Patch_Generated',
              requiresHumanApproval: true,
            }),
          },
        ],
      });
    }

    return rpcError(body.id, -32601, `Unknown MCP tool: ${toolName}`);
  }

  return rpcError(body.id, -32601, `Method not found: ${body.method}`);
}
