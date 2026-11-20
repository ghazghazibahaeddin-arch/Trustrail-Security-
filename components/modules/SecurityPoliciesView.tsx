'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { PolicyItem } from '@/lib/trustrail-store';
import { FileCode2, Plus, Play } from 'lucide-react';

export function SecurityPoliciesView() {
  const { policies, createPolicy, togglePolicy, evaluatePolicy, user } = useTrustrail();
  const [showAdd, setShowAdd] = useState(false);
  const [name, setName] = useState('');
  const [engine, setEngine] = useState<PolicyItem['engine']>('OPA Rego');
  const [severity, setSeverity] = useState<PolicyItem['severity']>('Critical');
  const [ruleCode, setRuleCode] = useState('BLOCK_PUBLIC_S3_ACL');

  const [tfSnippet, setTfSnippet] = useState('resource "aws_s3_bucket" "data" { acl = "public-read-write" }');
  const [evalResult, setEvalResult] = useState<{
    decision: string;
    allowed: boolean;
    violatedRules: Array<{ ruleName: string; reason: string; remediation: string }>;
  } | null>(null);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    await createPolicy({ name, engine, severity, ruleCode });
    setName('');
    setShowAdd(false);
  };

  const handleEvaluate = async () => {
    const res = await evaluatePolicy({
      type: 'terraform_plan',
      terraformContent: tfSnippet,
    });
    if (res) setEvalResult(res);
  };

  const isAdmin = user?.role === 'Owner' || user?.role === 'Admin';

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <FileCode2 className="w-5 h-5 text-cyan-500" />
              <span>Security Policies & Policy-as-Code (OPA)</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Deterministic policy rules enforced across Terraform plans, CI/CD pipelines, and AI agent tool calls.
            </p>
          </div>
          {isAdmin && (
            <button
              type="button"
              onClick={() => setShowAdd(!showAdd)}
              className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition whitespace-nowrap shrink-0 self-start"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Add Policy Rule</span>
            </button>
          )}
        </div>

        {showAdd && (
          <form
            onSubmit={handleAdd}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 mb-6 grid grid-cols-1 md:grid-cols-4 gap-3 items-end"
          >
            <input
              type="text"
              required
              placeholder="Policy Rule Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
            />
            <select
              value={engine}
              onChange={(e) => setEngine(e.target.value as PolicyItem['engine'])}
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
            >
              <option value="OPA Rego">OPA Rego</option>
              <option value="Cloud Guard">Cloud Guard</option>
              <option value="IntentLock">IntentLock</option>
              <option value="SCA Guard">SCA Guard</option>
              <option value="Agent Guard">Agent Guard</option>
            </select>
            <select
              value={ruleCode}
              onChange={(e) => setRuleCode(e.target.value)}
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono"
            >
              <option value="BLOCK_PUBLIC_S3_ACL">BLOCK_PUBLIC_S3_ACL</option>
              <option value="BLOCK_OPEN_ADMIN_PORTS">BLOCK_OPEN_ADMIN_PORTS</option>
              <option value="REQUIRE_COSIGN_SIGNATURE">REQUIRE_COSIGN_SIGNATURE</option>
              <option value="BLOCK_HIGH_CVSS">BLOCK_HIGH_CVSS</option>
              <option value="INTENT_LOCK_APPROVAL">INTENT_LOCK_APPROVAL</option>
              <option value="AGENT_LEAST_PRIVILEGE">AGENT_LEAST_PRIVILEGE</option>
            </select>
            <button type="submit" className="px-4 py-2 rounded-lg bg-cyan-600 text-white text-xs font-semibold">
              Save Policy
            </button>
          </form>
        )}

        <div className="space-y-3 mb-6">
          {policies.map((p) => (
            <div
              key={p.id}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div className="flex items-center space-x-3">
                <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-500 shrink-0">
                  <FileCode2 className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-sm font-bold text-slate-900 dark:text-white">{p.name}</div>
                  <div className="text-xs text-slate-500 font-mono">
                    {p.engine} • {p.ruleCode} • {p.severity}
                  </div>
                </div>
              </div>
              {isAdmin ? (
                <select
                  aria-label={`Enforcement mode for ${p.name}`}
                  value={p.status}
                  onChange={(e) => togglePolicy(p.id, e.target.value as PolicyItem['status'])}
                  className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono font-bold text-emerald-600 dark:text-emerald-400 shrink-0"
                >
                  <option value="Enforced">Enforced</option>
                  <option value="Audit_Only">Audit_Only</option>
                  <option value="Disabled">Disabled</option>
                </select>
              ) : (
                <span className="px-2.5 py-1 rounded bg-emerald-500/15 text-emerald-500 border border-emerald-500/30 text-xs font-mono font-bold">
                  {p.status}
                </span>
              )}
            </div>
          ))}
        </div>

        {/* Live Terraform / Policy Simulator */}
        <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
              Live Policy-as-Code Evaluator (Terraform HCL / Plan JSON)
            </h2>
            <button
              type="button"
              onClick={handleEvaluate}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Evaluate Policy</span>
            </button>
          </div>
          <textarea
            rows={3}
            value={tfSnippet}
            onChange={(e) => setTfSnippet(e.target.value)}
            className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-3 text-xs font-mono"
          />
          {evalResult && (
            <div
              className={`p-4 rounded-lg border text-xs ${
                evalResult.allowed
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-300'
                  : 'bg-rose-500/10 border-rose-500/30 text-rose-600 dark:text-rose-300'
              }`}
            >
              <div className="font-mono font-bold mb-1">Decision: {evalResult.decision}</div>
              {evalResult.violatedRules.map((v, idx) => (
                <div key={idx} className="mt-1">
                  • <strong>{v.ruleName}:</strong> {v.reason} — <em>{v.remediation}</em>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
