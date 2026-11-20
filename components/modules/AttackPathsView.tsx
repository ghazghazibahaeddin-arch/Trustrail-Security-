'use client';

import React from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { GitPullRequest, ShieldCheck, CheckCircle2 } from 'lucide-react';

export function AttackPathsView() {
  const { attackPaths, mitigateAttackPath, user } = useTrustrail();

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <GitPullRequest className="w-5 h-5 text-amber-500" />
              <span>Attack Path Intelligence</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Deterministic multi-step exploit chains computed live from open vulnerabilities and graph edges.
            </p>
          </div>
          <span className="px-3 py-1 rounded-lg text-xs font-mono font-bold bg-amber-500/15 text-amber-600 dark:text-amber-300 border border-amber-500/30 tabular-nums">
            {attackPaths.length} Active Paths
          </span>
        </div>

        {attackPaths.length === 0 ? (
          <div className="p-10 text-center bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl space-y-2">
            <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto" />
            <div className="text-sm font-bold text-slate-900 dark:text-white">Zero Active Attack Paths</div>
            <div className="text-xs text-slate-500">
              All multi-hop exposure paths reaching crown-jewel assets have been mitigated.
            </div>
          </div>
        ) : (
          <div className="space-y-6">
            {attackPaths.map((path) => (
              <div
                key={path.id}
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-6"
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-4 pb-4 border-b border-slate-200 dark:border-slate-900">
                  <div>
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/20 text-rose-500 border border-rose-500/30 tabular-nums">
                        Risk Score {path.riskScore}/100
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">Target: {path.targetAsset}</span>
                    </div>
                    <h2 className="text-base font-bold text-slate-900 dark:text-white">{path.title}</h2>
                  </div>
                  <div className="text-xs text-slate-500">
                    Likelihood: <span className="text-rose-500 font-bold">{path.likelihood}</span>
                  </div>
                </div>

                <div className="text-xs text-slate-700 dark:text-slate-300 mb-4 bg-white dark:bg-slate-900/60 p-3 rounded-lg border border-slate-200 dark:border-slate-800">
                  <span className="font-bold text-slate-900 dark:text-white">Business Impact: </span>
                  {path.impact}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-3 mb-6">
                  {path.steps.map((step) => (
                    <div
                      key={step.order}
                      className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-4 rounded-xl flex flex-col justify-between"
                    >
                      <div>
                        <div className="flex items-center justify-between mb-2">
                          <span className="w-5 h-5 rounded-full bg-cyan-500/20 text-cyan-600 dark:text-cyan-400 font-mono text-[10px] flex items-center justify-center font-bold">
                            {step.order}
                          </span>
                          <span className="text-[10px] font-mono text-slate-500">{step.assetType}</span>
                        </div>
                        <div className="text-xs font-semibold text-slate-900 dark:text-white mb-1">{step.assetName}</div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400">{step.description}</div>
                      </div>
                    </div>
                  ))}
                </div>

                <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="flex items-center space-x-3">
                    <ShieldCheck className="w-5 h-5 text-emerald-500 shrink-0" />
                    <div className="text-xs text-slate-800 dark:text-slate-200">
                      <span className="font-bold text-emerald-600 dark:text-emerald-400">Mitigation: </span>
                      {path.mitigation}
                    </div>
                  </div>
                  {user?.role !== 'Viewer' && (
                    <button
                      type="button"
                      onClick={() => mitigateAttackPath(path.id)}
                      className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold whitespace-nowrap transition shrink-0"
                    >
                      Break & Mitigate Path
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
