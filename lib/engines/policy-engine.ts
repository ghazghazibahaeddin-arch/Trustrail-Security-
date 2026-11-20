export interface PolicyRule {
  id: string;
  name: string;
  engine: 'OPA Rego' | 'Cloud Guard' | 'IntentLock' | 'SCA Guard' | 'Agent Guard';
  severity: 'Critical' | 'High' | 'Medium';
  status: 'Enforced' | 'Audit_Only' | 'Disabled';
  ruleCode: string;
}

export interface PolicyEvaluationTarget {
  type: 'change_contract' | 'terraform_plan' | 'ci_pipeline' | 'agent_action';
  criticalFindingsCount?: number;
  maxCvss?: number;
  hasPublicS3?: boolean;
  hasOpenAdminPort?: boolean;
  hasWildcardIam?: boolean;
  hasCosignSignature?: boolean;
  intentLockValid?: boolean;
  agentToolAllowlisted?: boolean;
  agentActionsUsed?: number;
  agentActionLimit?: number;
  requiresHumanApproval?: boolean;
  hasHumanApproval?: boolean;
}

export type EnforcementMode = 'Observe' | 'Recommend' | 'Enforce';

export interface PolicyDecision {
  decision: 'ALLOW' | 'DENY' | 'REQUIRE_APPROVAL';
  allowed: boolean;
  wouldBlock: boolean;
  enforcementMode: EnforcementMode;
  violatedRules: Array<{ ruleId: string; ruleName: string; reason: string; remediation: string }>;
  evaluatedAt: string;
}

export function evaluatePolicies(
  policies: PolicyRule[],
  target: PolicyEvaluationTarget,
  enforcementMode: EnforcementMode = 'Enforce'
): PolicyDecision {
  const violatedRules: PolicyDecision['violatedRules'] = [];
  let needsApproval = false;

  const activePolicies = policies.filter((p) => p.status === 'Enforced');

  for (const p of activePolicies) {
    if (p.ruleCode === 'REQUIRE_COSIGN_SIGNATURE' && target.hasCosignSignature === false) {
      violatedRules.push({
        ruleId: p.id,
        ruleName: p.name,
        reason: 'Release artifact lacks a valid Sigstore/Cosign signature.',
        remediation: 'Sign artifact in CI using cosign sign before deployment.',
      });
    }

    if (p.ruleCode === 'BLOCK_PUBLIC_S3_ACL' && target.hasPublicS3) {
      violatedRules.push({
        ruleId: p.id,
        ruleName: p.name,
        reason: 'Terraform plan or cloud resource sets public-read or public-read-write S3 ACL.',
        remediation: 'Set acl="private" and enable aws_s3_bucket_public_access_block.',
      });
    }

    if (p.ruleCode === 'BLOCK_OPEN_ADMIN_PORTS' && target.hasOpenAdminPort) {
      violatedRules.push({
        ruleId: p.id,
        ruleName: p.name,
        reason: 'Security group rule exposes SSH/RDP (22/3389) to 0.0.0.0/0.',
        remediation: 'Restrict ingress cidr_blocks to corporate VPN CIDR.',
      });
    }

    if (p.ruleCode === 'BLOCK_HIGH_CVSS' && typeof target.maxCvss === 'number' && target.maxCvss >= 9.0) {
      violatedRules.push({
        ruleId: p.id,
        ruleName: p.name,
        reason: `Critical vulnerability detected (CVSS ${target.maxCvss.toFixed(1)} >= 9.0 threshold).`,
        remediation: 'Patch or upgrade vulnerable package before merging.',
      });
    }

    if (p.ruleCode === 'INTENT_LOCK_APPROVAL') {
      if (target.intentLockValid === false) {
        violatedRules.push({
          ruleId: p.id,
          ruleName: p.name,
          reason: 'IntentLock verification failed: change payload was altered after approval.',
          remediation: 'Re-submit change for fresh human approval against the updated state hash.',
        });
      } else if (target.requiresHumanApproval && !target.hasHumanApproval) {
        needsApproval = true;
      }
    }

    if (p.ruleCode === 'AGENT_LEAST_PRIVILEGE' && target.type === 'agent_action') {
      if (target.agentToolAllowlisted === false) {
        violatedRules.push({
          ruleId: p.id,
          ruleName: p.name,
          reason: 'Requested tool is not on the AI Agent allowlist.',
          remediation: 'Request security admin approval to add tool to agent manifest.',
        });
      }
      if (
        typeof target.agentActionsUsed === 'number' &&
        typeof target.agentActionLimit === 'number' &&
        target.agentActionsUsed >= target.agentActionLimit
      ) {
        violatedRules.push({
          ruleId: p.id,
          ruleName: p.name,
          reason: `Cumulative agent action limit reached (${target.agentActionsUsed}/${target.agentActionLimit}).`,
          remediation: 'Reset session quota or elevate session authority after review.',
        });
      }
    }
  }

  const strictDecision: PolicyDecision['decision'] =
    violatedRules.length > 0 ? 'DENY' : needsApproval ? 'REQUIRE_APPROVAL' : 'ALLOW';

  let finalDecision = strictDecision;
  if (enforcementMode === 'Observe') {
    finalDecision = 'ALLOW';
  } else if (enforcementMode === 'Recommend' && strictDecision === 'DENY' && target.intentLockValid !== false) {
    finalDecision = 'REQUIRE_APPROVAL';
  }

  return {
    decision: finalDecision,
    allowed: finalDecision === 'ALLOW',
    wouldBlock: strictDecision !== 'ALLOW',
    enforcementMode,
    violatedRules,
    evaluatedAt: new Date().toISOString(),
  };
}

