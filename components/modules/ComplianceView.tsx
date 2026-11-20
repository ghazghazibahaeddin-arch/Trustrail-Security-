'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { ComplianceControl } from '@/lib/trustrail-store';
import { FileCheck2, Download, Filter } from 'lucide-react';

export function ComplianceView() {
  const { complianceControls, updateComplianceControl, user, org } = useTrustrail();
  const [frameworkFilter, setFrameworkFilter] = useState<string>('ALL');
  const canEdit = user?.role === 'Owner' || user?.role === 'Admin' || user?.role === 'Developer';

  const frameworks = ['ALL', ...Array.from(new Set(complianceControls.map((c) => c.framework)))];
  const filtered =
    frameworkFilter === 'ALL'
      ? complianceControls
      : complianceControls.filter((c) => c.framework === frameworkFilter);

  const handleDownload = (format: 'json' | 'csv') => {
    window.location.href = `/api/v1/compliance/export?format=${format}`;
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <FileCheck2 className="w-5 h-5 text-cyan-500" />
              <span>Compliance &amp; Evidence Center</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Real-time control posture across SOC 2 Type II, OWASP Top 10, NIST SSDF, and SLSA ({org.compliancePercentage}% verified).
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => handleDownload('csv')}
              className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-900 dark:text-white text-xs font-semibold transition border border-slate-200 dark:border-slate-700"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export CSV</span>
            </button>
            <button
              type="button"
              onClick={() => handleDownload('json')}
              className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Evidence Pack (JSON)</span>
            </button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2 mb-5">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          {frameworks.map((fw) => (
            <button
              key={fw}
              type="button"
              onClick={() => setFrameworkFilter(fw)}
              className={`px-3 py-1 rounded-lg text-xs font-mono font-semibold border transition ${
                frameworkFilter === fw
                  ? 'bg-cyan-600 text-white border-cyan-500'
                  : 'bg-slate-50 dark:bg-slate-950 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-800 hover:border-cyan-500/40'
              }`}
            >
              {fw}
            </button>
          ))}
        </div>

        <div className="space-y-3">
          {filtered.map((c) => (
            <div
              key={c.id}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
            >
              <div className="flex items-center space-x-3">
                <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-500 shrink-0">
                  <FileCheck2 className="w-4 h-4" />
                </div>
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs font-mono font-bold text-cyan-600 dark:text-cyan-400">
                      {c.framework} ({c.code})
                    </span>
                    <span className="text-xs text-slate-500">• Owner: {c.owner}</span>
                    <span className="text-[11px] font-mono text-slate-500">• Verified: {c.lastVerified}</span>
                  </div>
                  <div className="text-sm font-bold text-slate-900 dark:text-white mt-0.5">{c.title}</div>
                </div>
              </div>
              <div className="flex items-center space-x-3 shrink-0">
                <span className="text-xs text-slate-500 font-mono">{c.evidenceCount} Evidences</span>
                {canEdit ? (
                  <select
                    aria-label={`Control status for ${c.code}`}
                    value={c.status}
                    onChange={(e) => updateComplianceControl(c.id, e.target.value as ComplianceControl['status'])}
                    className={`px-2.5 py-1.5 rounded-lg text-xs font-mono font-bold border bg-white dark:bg-slate-900 ${
                      c.status === 'Verified'
                        ? 'text-emerald-600 dark:text-emerald-300 border-emerald-500/30'
                        : c.status === 'Needs_Evidence'
                        ? 'text-amber-600 dark:text-amber-300 border-amber-500/30'
                        : 'text-rose-600 dark:text-rose-300 border-rose-500/30'
                    }`}
                  >
                    <option value="Verified">Verified</option>
                    <option value="Needs_Evidence">Needs_Evidence</option>
                    <option value="Non_Compliant">Non_Compliant</option>
                  </select>
                ) : (
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-mono font-bold border ${
                      c.status === 'Verified'
                        ? 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                        : c.status === 'Needs_Evidence'
                        ? 'bg-amber-500/15 text-amber-500 border-amber-500/30'
                        : 'bg-rose-500/15 text-rose-500 border-rose-500/30'
                    }`}
                  >
                    {c.status}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
