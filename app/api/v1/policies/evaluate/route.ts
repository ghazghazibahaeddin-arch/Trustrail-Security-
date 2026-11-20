import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { evaluatePolicies, type PolicyRule } from '@/lib/engines/policy-engine';
import { scanTerraformAndIaC } from '@/lib/engines/scanner-engine';

const EvaluateSchema = z.object({
  type: z.enum(['change_contract', 'terraform_plan', 'ci_pipeline', 'agent_action']),
  terraformContent: z.string().max(250_000).optional(),
  maxCvss: z.number().min(0).max(10).optional(),
  hasCosignSignature: z.boolean().optional(),
  hasPublicS3: z.boolean().optional(),
  hasOpenAdminPort: z.boolean().optional(),
  intentLockValid: z.boolean().optional(),
  requiresHumanApproval: z.boolean().optional(),
  hasHumanApproval: z.boolean().optional(),
  agentToolAllowlisted: z.boolean().optional(),
  agentActionsUsed: z.number().int().min(0).optional(),
  agentActionLimit: z.number().int().min(1).optional(),
});

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = EvaluateSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid policy evaluation payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const policies = db
    .prepare(
      `SELECT id, name, engine, severity, status, rule_code as ruleCode
       FROM policies WHERE org_id = ?`
    )
    .all(authResult.auth.orgId) as unknown as PolicyRule[];

  let hasPublicS3 = parsed.data.hasPublicS3 ?? false;
  let hasOpenAdminPort = parsed.data.hasOpenAdminPort ?? false;
  let hasWildcardIam = false;
  let iacFindingsCount = 0;

  if (parsed.data.terraformContent) {
    const iac = scanTerraformAndIaC(parsed.data.terraformContent, 'policy-eval');
    iacFindingsCount = iac.findings.length;
    if (iac.findings.some((f) => f.title.includes('S3'))) hasPublicS3 = true;
    if (iac.findings.some((f) => f.title.includes('22/3389'))) hasOpenAdminPort = true;
    if (iac.findings.some((f) => f.title.includes('IAM'))) hasWildcardIam = true;
  }

  const orgRow = db
    .prepare('SELECT enforcement_mode FROM organizations WHERE id = ?')
    .get(authResult.auth.orgId) as { enforcement_mode?: 'Observe' | 'Recommend' | 'Enforce' } | undefined;
  const enforcementMode = orgRow?.enforcement_mode || 'Enforce';

  const result = evaluatePolicies(
    policies,
    {
      type: parsed.data.type,
      maxCvss: parsed.data.maxCvss,
      hasCosignSignature: parsed.data.hasCosignSignature,
      hasPublicS3,
      hasOpenAdminPort,
      hasWildcardIam,
      intentLockValid: parsed.data.intentLockValid,
      requiresHumanApproval: parsed.data.requiresHumanApproval,
      hasHumanApproval: parsed.data.hasHumanApproval,
      agentToolAllowlisted: parsed.data.agentToolAllowlisted,
      agentActionsUsed: parsed.data.agentActionsUsed,
      agentActionLimit: parsed.data.agentActionLimit,
    },
    enforcementMode
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'POLICY_EVALUATED',
    resourceType: 'PolicyEvaluation',
    resourceId: parsed.data.type,
    details: `Decision=${result.decision} (mode=${enforcementMode}, violations=${result.violatedRules.length}, iacFindings=${iacFindingsCount}).`,
  });

  return jsonOk({ ...result, iacFindingsCount });
}
