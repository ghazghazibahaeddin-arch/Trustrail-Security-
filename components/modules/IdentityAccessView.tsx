'use client';

import React from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { KeyRound } from 'lucide-react';

export function IdentityAccessView() {
  const { teamMembers, aiAgents, graphNodes, org } = useTrustrail();

  const iamMachineNodes = graphNodes.filter((n) => n.assetType === 'IAM Identity');

  const unifiedIdentities = [
    ...teamMembers.map((m) => ({
      id: `human-${m.membershipId}`,
      name: `${m.name} (${m.email})`,
      category: 'Human Operator',
      authMethod: m.mfaEnabled ? 'MFA Enabled' : 'Password Only',
      privilege: m.role,
      risky: !m.mfaEnabled || m.role === 'Owner',
    })),
    ...aiAgents.map((a) => ({
      id: `agent-${a.id}`,
      name: a.name,
      category: `AI / ${a.type}`,
      authMethod: 'Allowlist + Quota',
      privilege: a.permissions.join(', '),
      risky: a.status !== 'Active' || a.riskLevel === 'High',
    })),
    ...iamMachineNodes.map((n) => ({
      id: `iam-${n.id}`,
      name: n.name,
      category: 'Cloud IAM Machine Identity',
      authMethod: 'OIDC / AssumeRole',
      privilege: n.openFindingsCount > 0 ? `Over-privileged (${n.openFindingsCount} findings)` : 'Least Privilege',
      risky: n.openFindingsCount > 0,
    })),
  ];

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <KeyRound className="w-5 h-5 text-cyan-500" />
              <span>Identity &amp; Privilege Intelligence</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Unified human, AI agent, and cloud machine identity inventory for {org.name}.
            </p>
          </div>
          <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-cyan-500/15 text-cyan-600 dark:text-cyan-300 border border-cyan-500/30 self-start">
            {unifiedIdentities.length} Identities Tracked
          </span>
        </div>

        <div className="space-y-3">
          {unifiedIdentities.map((ident) => (
            <div
              key={ident.id}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div className="flex items-center space-x-3">
                <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-500 shrink-0">
                  <KeyRound className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-sm font-bold text-slate-900 dark:text-white font-mono">{ident.name}</div>
                  <div className="text-xs text-slate-500">
                    Type: {ident.category} • Auth: {ident.authMethod}
                  </div>
                </div>
              </div>
              <span
                className={`px-2.5 py-1 rounded border text-xs font-mono self-start sm:self-center ${
                  ident.risky
                    ? 'bg-amber-500/15 text-amber-500 border-amber-500/30'
                    : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 text-cyan-600 dark:text-cyan-400'
                }`}
              >
                {ident.privilege}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
