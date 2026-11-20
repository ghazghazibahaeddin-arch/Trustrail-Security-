'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { AlertTriangle, CheckCircle2, Wrench, Search } from 'lucide-react';

export function VulnerabilitiesView() {
  const { findings, resolveFinding, setActiveTab, user } = useTrustrail();
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [filterStatus, setFilterStatus] = useState<string>('ALL');
  const [searchTerm, setSearchTerm] = useState<string>('');

  const filteredFindings = findings.filter((f) => {
    if (filterSeverity !== 'ALL' && f.severity !== filterSeverity) return false;
    if (filterStatus !== 'ALL' && f.status !== filterStatus) return false;
    if (
      searchTerm &&
      !f.title.toLowerCase().includes(searchTerm.toLowerCase()) &&
      !f.assetName.toLowerCase().includes(searchTerm.toLowerCase()) &&
      !(f.cve && f.cve.toLowerCase().includes(searchTerm.toLowerCase()))
    ) {
      return false;
    }
    return true;
  });

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-rose-500" />
              <span>Vulnerability & Risk Intelligence Center</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Deduplicated SAST, SCA, Secret, IaC, and Container findings ranked by explainable business risk.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                type="button"
                key={sev}
                onClick={() => setFilterSeverity(sev)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-bold transition ${
                  filterSeverity === sev
                    ? 'bg-cyan-500/20 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30'
                    : 'bg-slate-100 dark:bg-slate-950 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {sev}
              </button>
            ))}
            <select
              aria-label="Filter by status"
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-700 dark:text-slate-300"
            >
              <option value="ALL">All Statuses</option>
              <option value="Open">Open</option>
              <option value="In_Remediation">In Remediation</option>
              <option value="Resolved">Resolved</option>
            </select>
          </div>
        </div>

        <div className="mb-6 relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search findings by title, CVE, or asset..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl pl-9 pr-4 py-2 text-xs text-slate-900 dark:text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500 transition"
          />
        </div>

        {filteredFindings.length === 0 ? (
          <div className="p-10 text-center text-xs text-slate-500 bg-slate-50 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800">
            No findings match the active filter criteria.
          </div>
        ) : (
          <div className="space-y-4">
            {filteredFindings.map((f) => (
              <div
                key={f.id}
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col md:flex-row md:items-center justify-between gap-4"
              >
                <div className="space-y-2 flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold tabular-nums ${
                        f.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-500 border border-rose-500/30'
                          : f.severity === 'HIGH'
                          ? 'bg-amber-500/20 text-amber-500 border border-amber-500/30'
                          : 'bg-cyan-500/20 text-cyan-600 dark:text-cyan-300 border border-cyan-500/30'
                      }`}
                    >
                      {f.severity} • CVSS {f.cvss}
                    </span>
                    {f.priorityTier && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/15 text-indigo-500 border border-indigo-500/30 tabular-nums">
                        {f.priorityTier} ({f.riskScore}/100)
                      </span>
                    )}
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-white dark:bg-slate-900 text-slate-600 dark:text-slate-300 border border-slate-200 dark:border-slate-800">
                      {f.category}
                    </span>
                    {f.cve && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300">
                        {f.cve}
                      </span>
                    )}
                    <span className="text-xs font-mono text-cyan-600 dark:text-cyan-400 truncate">{f.assetName}</span>
                  </div>
                  <div className="text-sm font-bold text-slate-900 dark:text-white">{f.title}</div>
                  <div className="text-xs text-slate-600 dark:text-slate-400 font-mono bg-white dark:bg-slate-900/60 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 break-words">
                    <strong>Evidence:</strong> {f.evidence}
                  </div>
                  {f.riskReasons && f.riskReasons.length > 0 && (
                    <div className="text-[11px] font-mono text-slate-500">
                      Risk Factors: {f.riskReasons.join(' | ')}
                    </div>
                  )}
                  <div className="text-xs text-slate-700 dark:text-slate-300">
                    <strong className="text-emerald-600 dark:text-emerald-400">Fix:</strong> {f.suggestedFix}
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row items-center gap-2 shrink-0">
                  {f.status === 'Resolved' ? (
                    <span className="px-3 py-2 rounded-lg bg-emerald-500/15 text-emerald-600 dark:text-emerald-300 border border-emerald-500/30 text-xs font-semibold flex items-center space-x-1.5 whitespace-nowrap">
                      <CheckCircle2 className="w-4 h-4" />
                      <span>Resolved</span>
                    </span>
                  ) : (
                    <>
                      <button
                        type="button"
                        onClick={() => setActiveTab('remediation')}
                        className="w-full sm:w-auto px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition flex items-center justify-center space-x-1.5 whitespace-nowrap"
                      >
                        <Wrench className="w-3.5 h-3.5" />
                        <span>Remediate</span>
                      </button>
                      {user?.role !== 'Viewer' && (
                        <button
                          type="button"
                          onClick={() => resolveFinding(f.id, `Verified fixed by ${user?.email || 'engineer'}`)}
                          className="w-full sm:w-auto px-4 py-2 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 text-xs font-semibold transition border border-slate-200 dark:border-slate-800 whitespace-nowrap"
                        >
                          Mark Resolved
                        </button>
                      )}
                    </>
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
