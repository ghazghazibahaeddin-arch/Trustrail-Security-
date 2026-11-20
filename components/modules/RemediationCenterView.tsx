'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Wrench, Sparkles, Loader2, CheckCircle2, AlertTriangle, Play, ShieldCheck } from 'lucide-react';

export function RemediationCenterView() {
  const {
    findings,
    remediationRuns,
    startRemediation,
    progressRemediation,
    resolveFinding,
    user,
  } = useTrustrail();
  const openFindings = findings.filter((f) => f.status !== 'Resolved' && f.status !== 'False_Positive');
  const [selectedFindingId, setSelectedFindingId] = useState<string>('');
  const [isGeneratingPatch, setIsGeneratingPatch] = useState(false);
  const [patchResult, setPatchResult] = useState<string | null>(null);
  const [patchError, setPatchError] = useState<string | null>(null);
  const [patchedCodeSample, setPatchedCodeSample] = useState(
    '// Patched: replaced hardcoded credential and enabled parameterized query'
  );
  const [resolutionEvidence, setResolutionEvidence] = useState('PR merged and verified via Trustrail re-scan');

  const selectedFinding = findings.find((f) => f.id === selectedFindingId) || openFindings[0] || findings[0];
  const findingRuns = selectedFinding
    ? remediationRuns.filter((r) => r.findingId === selectedFinding.id)
    : [];
  const activeRun = findingRuns[0];

  const handleGeneratePatch = async () => {
    if (!selectedFinding) return;
    setIsGeneratingPatch(true);
    setPatchResult(null);
    setPatchError(null);

    try {
      const res = await fetch('/api/gemini', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mode: 'remediation_patch',
          prompt: `Generate a safe remediation git diff and verification checklist for: Title="${selectedFinding.title}", File="${selectedFinding.filePath || 'N/A'}", Evidence="${selectedFinding.evidence}", SuggestedFix="${selectedFinding.suggestedFix}".`,
          context: selectedFinding as unknown as Record<string, unknown>,
          systemInstruction:
            'You are a defensive DevSecOps remediation autopilot. Provide a minimal, verifiable code patch and re-scan verification steps.',
        }),
      });

      const data = await res.json();
      if (!res.ok || data.error) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }

      setPatchResult(data.text);
    } catch (err) {
      setPatchError((err as Error).message);
    } finally {
      setIsGeneratingPatch(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Wrench className="w-5 h-5 text-cyan-500" />
              <span>Gated Remediation &amp; Verification Pipeline</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Patch generation → deterministic scanner verification tests → clean re-scan closure gate.
            </p>
          </div>
          <span className="px-3 py-1 rounded-lg text-xs font-mono font-bold bg-cyan-500/15 text-cyan-600 dark:text-cyan-300 border border-cyan-500/30 whitespace-nowrap self-start">
            {openFindings.length} Open Targets
          </span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Finding Selector Column */}
          <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-3">
            <div className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-2">
              Select Vulnerability
            </div>
            <div className="space-y-2 max-h-[520px] overflow-y-auto">
              {findings.map((f) => (
                <button
                  type="button"
                  key={f.id}
                  onClick={() => {
                    setSelectedFindingId(f.id);
                    setPatchResult(null);
                    setPatchError(null);
                  }}
                  className={`w-full text-left p-3 rounded-lg border transition ${
                    selectedFinding?.id === f.id
                      ? 'bg-cyan-500/10 border-cyan-500/50'
                      : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-400'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span
                      className={`px-1.5 py-0.5 rounded text-[9px] font-mono font-bold ${
                        f.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-500' : 'bg-amber-500/20 text-amber-500'
                      }`}
                    >
                      {f.severity}
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">
                      {f.status}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-slate-900 dark:text-white truncate">{f.title}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Autopilot + Gated Verification Column */}
          <div className="lg:col-span-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-6 flex flex-col justify-between space-y-5">
            {selectedFinding ? (
              <div className="space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-200 dark:border-slate-900">
                  <div>
                    <div className="text-xs font-mono text-cyan-600 dark:text-cyan-400 mb-1">
                      {selectedFinding.assetName} {selectedFinding.filePath ? `• ${selectedFinding.filePath}` : ''}
                    </div>
                    <h2 className="text-base font-bold text-slate-900 dark:text-white">{selectedFinding.title}</h2>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      type="button"
                      onClick={handleGeneratePatch}
                      disabled={isGeneratingPatch}
                      className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white text-xs font-semibold transition disabled:opacity-50 whitespace-nowrap"
                    >
                      {isGeneratingPatch ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Sparkles className="w-3.5 h-3.5" />}
                      <span>{isGeneratingPatch ? 'Generating...' : 'AI Patch Preview'}</span>
                    </button>
                    {user?.role !== 'Viewer' && selectedFinding.status !== 'Resolved' && (
                      <button
                        type="button"
                        onClick={() => startRemediation(selectedFinding.id, patchResult || undefined)}
                        className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition whitespace-nowrap"
                      >
                        <Wrench className="w-3.5 h-3.5" />
                        <span>Start Gated Remediation</span>
                      </button>
                    )}
                  </div>
                </div>

                <div className="space-y-3">
                  <div>
                    <div className="text-[10px] font-mono text-slate-500 uppercase">Redacted Evidence</div>
                    <div className="text-xs font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-3 rounded-lg text-slate-700 dark:text-slate-300 mt-1">
                      {selectedFinding.evidence}
                    </div>
                  </div>

                  <div>
                    <div className="text-[10px] font-mono text-slate-500 uppercase">Deterministic Engine Fix Guidance</div>
                    <div className="text-xs font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-3 rounded-lg text-emerald-700 dark:text-emerald-400 mt-1">
                      {selectedFinding.suggestedFix}
                    </div>
                  </div>

                  {/* Gated Verification Workflow Card */}
                  {activeRun && (
                    <div className="p-4 rounded-xl bg-white dark:bg-slate-900 border border-cyan-500/40 space-y-3">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                          <ShieldCheck className="w-4 h-4 text-cyan-500" />
                          <span>Verification Gate Run ({activeRun.id})</span>
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-500">
                          {activeRun.status}
                        </span>
                      </div>

                      <div className="text-[11px] font-mono text-slate-500">
                        Command: {activeRun.verificationCommand}
                      </div>

                      <pre className="bg-slate-950 text-emerald-300 text-[11px] font-mono p-2.5 rounded-lg overflow-x-auto">
                        {activeRun.patchDiff}
                      </pre>

                      {user?.role !== 'Viewer' && activeRun.status !== 'Rescan_Verified' && (
                        <div className="space-y-2 pt-2 border-t border-slate-200 dark:border-slate-800">
                          <label className="text-[10px] font-mono uppercase text-slate-500">
                            Patched Code Sample for Deterministic Scanner Verification
                          </label>
                          <textarea
                            rows={2}
                            value={patchedCodeSample}
                            onChange={(e) => setPatchedCodeSample(e.target.value)}
                            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-2 text-xs font-mono"
                          />
                          <div className="flex flex-wrap items-center gap-2">
                            <button
                              type="button"
                              onClick={() => progressRemediation(activeRun.id, 'run_verification', patchedCodeSample)}
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold"
                            >
                              <Play className="w-3.5 h-3.5" />
                              <span>1. Run Verification Tests</span>
                            </button>
                            <button
                              type="button"
                              disabled={!activeRun.verificationPassed}
                              onClick={() => progressRemediation(activeRun.id, 'rescan_and_resolve', patchedCodeSample)}
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white text-xs font-semibold"
                            >
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              <span>2. Clean Re-Scan &amp; Resolve Finding</span>
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {patchError && (
                    <div className="p-3 rounded-lg bg-amber-500/10 border border-amber-500/30 text-xs text-amber-700 dark:text-amber-300 flex items-start space-x-2">
                      <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                      <span>AI Patch Unavailable: {patchError}</span>
                    </div>
                  )}

                  {patchResult && (
                    <div>
                      <div className="text-[10px] font-mono text-slate-500 uppercase">AI-Generated Patch &amp; PR Preview</div>
                      <div className="text-xs font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-4 rounded-lg text-emerald-700 dark:text-emerald-300 mt-1 max-h-64 overflow-y-auto whitespace-pre-wrap">
                        {patchResult}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="text-xs text-slate-500 text-center py-16">
                No vulnerabilities found in this organization.
              </div>
            )}

            {selectedFinding && selectedFinding.status !== 'Resolved' && user?.role !== 'Viewer' && (
              <div className="pt-4 border-t border-slate-200 dark:border-slate-900 flex flex-col sm:flex-row items-stretch sm:items-center justify-end gap-3">
                <input
                  type="text"
                  value={resolutionEvidence}
                  onChange={(e) => setResolutionEvidence(e.target.value)}
                  placeholder="Manual override / PR commit verification evidence..."
                  className="flex-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-900 dark:text-slate-200"
                />
                <button
                  type="button"
                  onClick={() => resolveFinding(selectedFinding.id, resolutionEvidence, 'Resolved')}
                  className="px-4 py-2 rounded-lg bg-emerald-600/90 hover:bg-emerald-500 text-white text-xs font-semibold transition flex items-center justify-center space-x-1.5 whitespace-nowrap shrink-0"
                >
                  <CheckCircle2 className="w-4 h-4" />
                  <span>Record Direct Resolution</span>
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
