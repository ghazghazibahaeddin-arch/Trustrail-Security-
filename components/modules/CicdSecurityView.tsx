'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Workflow, Play, ShieldCheck, ShieldAlert, ScanSearch } from 'lucide-react';

export function CicdSecurityView() {
  const { projects, policies, findings, evaluatePolicy, runScan, org, user } = useTrustrail();
  const [gateResults, setGateResults] = useState<
    Record<string, { decision: string; allowed: boolean; violatedRules: Array<{ ruleName: string; reason: string }> }>
  >({});
  const [workflowYaml, setWorkflowYaml] = useState(
    `name: deploy\non: pull_request_target\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - run: curl https://example.com/install.sh | bash`
  );

  const enforcedCount = policies.filter((p) => p.status === 'Enforced').length;
  const enforcementMode = org.enforcementMode || 'Enforce';

  const verifyPipelineGate = async (projectId: string, projectName: string, slsaLevel: string) => {
    const projectFindings = findings.filter((f) => f.projectId === projectId && f.status !== 'Resolved');
    const maxCvss = projectFindings.reduce((max, f) => Math.max(max, f.cvss || 0), 0);
    const hasPublicS3 = projectFindings.some(
      (f) => f.category === 'IAC' && /s3|public/i.test(f.title)
    );
    const hasOpenAdminPort = projectFindings.some(
      (f) => f.category === 'IAC' && /22|3389|ssh|rdp|0\.0\.0\.0/i.test(f.title + f.evidence)
    );

    const res = await evaluatePolicy({
      type: 'ci_pipeline',
      projectName,
      criticalFindingsCount: projectFindings.filter((f) => f.severity === 'CRITICAL').length,
      maxCvss,
      hasPublicS3,
      hasOpenAdminPort,
      hasCosignSignature: slsaLevel !== 'None',
    });
    if (res) {
      setGateResults((prev) => ({ ...prev, [projectId]: res }));
    }
  };

  const handleScanWorkflow = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!workflowYaml.trim()) return;
    await runScan({
      projectId: projects[0]?.id,
      projectName: projects[0]?.name || 'github-actions-pipeline',
      githubWorkflowContent: workflowYaml,
      filePath: '.github/workflows/deploy.yml',
    });
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Workflow className="w-5 h-5 text-cyan-500" />
              <span>CI/CD Security Guardian &amp; OPA Guardrails</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Live pre-merge policy gates &amp; GitHub Actions workflow analyzer across {projects.length} repositories in {org.name}.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 self-start">
            <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-cyan-500/15 text-cyan-500 border border-cyan-500/30">
              Mode: {enforcementMode}
            </span>
            <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-emerald-500/15 text-emerald-500 border border-emerald-500/30">
              {enforcedCount} Enforced Policy Rules
            </span>
          </div>
        </div>

        {/* GitHub Actions Workflow Security Analyzer */}
        {user?.role !== 'Viewer' && (
          <form
            onSubmit={handleScanWorkflow}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-3"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                <ScanSearch className="w-4 h-4 text-cyan-500" />
                <span>GitHub Actions YAML Workflow Security Scanner</span>
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                Checks unpinned actions, pull_request_target, write-all &amp; curl|bash
              </span>
            </div>
            <textarea
              rows={5}
              value={workflowYaml}
              onChange={(e) => setWorkflowYaml(e.target.value)}
              className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-3 text-xs font-mono"
            />
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition inline-flex items-center gap-1.5"
            >
              <ScanSearch className="w-3.5 h-3.5" />
              <span>Scan CI/CD Workflow YAML</span>
            </button>
          </form>
        )}

        <div className="space-y-4">
          {projects.length === 0 ? (
            <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-8 text-center text-xs text-slate-500">
              No repositories onboarded yet for {org.name}. Add a project to enable CI/CD pipeline guardrails.
            </div>
          ) : (
            projects.map((p) => {
              const openCrit = p.findingsCount.critical;
              const openHigh = p.findingsCount.high;
              const gate = gateResults[p.id];
              const gateStatus = gate ? (gate.allowed ? 'ALLOW' : gate.decision) : openCrit > 0 ? 'Blocked' : 'Guarded';

              return (
                <div
                  key={p.id}
                  className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-3"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                    <div className="flex items-center space-x-3">
                      <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-500 shrink-0">
                        <Workflow className="w-4 h-4" />
                      </div>
                      <div>
                        <div className="text-sm font-bold text-slate-900 dark:text-white font-mono">
                          {p.name}-ci.yml
                        </div>
                        <div className="text-xs text-slate-500">
                          Branch: {p.branch} • {p.slsaLevel} • {openCrit} Critical / {openHigh} High open
                        </div>
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`px-2.5 py-1 rounded text-xs font-mono font-bold border ${
                          gateStatus === 'ALLOW' || gateStatus === 'Guarded'
                            ? 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                            : 'bg-rose-500/15 text-rose-500 border-rose-500/30'
                        }`}
                      >
                        {gateStatus}
                      </span>
                      <button
                        type="button"
                        onClick={() => verifyPipelineGate(p.id, p.name, p.slsaLevel)}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition"
                      >
                        <Play className="w-3 h-3" />
                        <span>Verify Pipeline Gate</span>
                      </button>
                    </div>
                  </div>

                  {gate && (
                    <div
                      className={`p-3 rounded-lg border text-xs ${
                        gate.allowed
                          ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-600 dark:text-emerald-300'
                          : 'bg-rose-500/10 border-rose-500/30 text-rose-600 dark:text-rose-300'
                      }`}
                    >
                      <div className="font-mono font-bold flex items-center gap-1.5">
                        {gate.allowed ? <ShieldCheck className="w-3.5 h-3.5" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                        <span>OPA Gate Decision: {gate.decision}</span>
                      </div>
                      {gate.violatedRules.map((v, idx) => (
                        <div key={idx} className="mt-1">
                          • <strong>{v.ruleName}:</strong> {v.reason}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
