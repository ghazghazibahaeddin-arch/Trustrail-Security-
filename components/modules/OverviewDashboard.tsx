'use client';

import React from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import {
  ShieldAlert,
  GitPullRequest,
  FolderGit2,
  AlertTriangle,
  ArrowUpRight,
  Flame,
  CheckCircle2,
  GitBranch,
  Globe,
  KeyRound,
} from 'lucide-react';

export function OverviewDashboard() {
  const { org, findings, attackPaths, projects, incidents, setActiveTab } = useTrustrail();

  const openFindings = findings.filter((f) => f.status !== 'Resolved' && f.status !== 'False_Positive');
  const criticalCount = openFindings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = openFindings.filter((f) => f.severity === 'HIGH').length;
  const sbomCount = projects.filter((p) => p.sbomGenerated).length;
  const activeIncidentsCount = incidents.filter((i) => i.status === 'Open' || i.status === 'Contained').length;
  const prioritizedOpen = [...openFindings].sort((a, b) => (b.riskScore ?? 0) - (a.riskScore ?? 0));

  return (
    <div className="space-y-6">
      {/* Top Posture Banner */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="text-xs font-mono text-cyan-600 dark:text-cyan-400 mb-1 uppercase tracking-wider">
              Unified Security Control Plane • {org.tierName}
            </div>
            <h1 className="text-2xl font-bold text-slate-900 dark:text-white tracking-tight">
              {org.name} Security Posture
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Continuous discovery, deterministic attack path synthesis, and IntentLock verification across{' '}
              <span className="font-mono tabular-nums">{org.assetsCount}</span> tracked assets.
            </p>
          </div>
          <div className="flex items-center space-x-3 shrink-0">
            <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl px-4 py-3 text-center">
              <div className="text-[10px] text-slate-500 font-mono uppercase">Rating</div>
              <div className="text-xl font-bold text-emerald-600 dark:text-emerald-400 font-mono tabular-nums">
                {org.securityRating}
              </div>
            </div>
            <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl px-4 py-3 text-center">
              <div className="text-[10px] text-slate-500 font-mono uppercase">Risk Index</div>
              <div className="text-xl font-bold text-amber-600 dark:text-amber-400 font-mono tabular-nums">
                {org.riskScore}/100
              </div>
            </div>
            <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl px-4 py-3 text-center">
              <div className="text-[10px] text-slate-500 font-mono uppercase">Compliance</div>
              <div className="text-xl font-bold text-cyan-600 dark:text-cyan-400 font-mono tabular-nums">
                {org.compliancePercentage}%
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Onboarding Quick-Start for New Workspaces */}
      {projects.length === 0 && (
        <div className="bg-white dark:bg-slate-900 border border-cyan-500/30 rounded-2xl p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-white">
                Launch Your Workspace Security Baseline
              </h2>
              <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                Your isolated workspace is active with 6 enforced policies and live OSV.dev / HTTP-TLS / GitHub scanners. Start with any real check below:
              </p>
            </div>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <button
              type="button"
              onClick={() => setActiveTab('integrations')}
              className="text-left p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-cyan-500/40 transition space-y-1.5"
            >
              <div className="flex items-center gap-2 text-xs font-bold text-slate-900 dark:text-white">
                <GitBranch className="w-4 h-4 text-cyan-500" />
                <span>1. Scan Live GitHub Repository</span>
              </div>
              <p className="text-[11px] text-slate-500">
                Fetch real manifests, Dockerfile, Terraform &amp; source code to generate SBOM and OSV CVE findings.
              </p>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('integrations')}
              className="text-left p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-emerald-500/40 transition space-y-1.5"
            >
              <div className="flex items-center gap-2 text-xs font-bold text-slate-900 dark:text-white">
                <Globe className="w-4 h-4 text-emerald-500" />
                <span>2. Probe Live HTTPS Endpoint</span>
              </div>
              <p className="text-[11px] text-slate-500">
                Inspect HSTS, CSP, CORS, and server banners on your public web app or API.
              </p>
            </button>
            <button
              type="button"
              onClick={() => setActiveTab('settings')}
              className="text-left p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-indigo-500/40 transition space-y-1.5"
            >
              <div className="flex items-center gap-2 text-xs font-bold text-slate-900 dark:text-white">
                <KeyRound className="w-4 h-4 text-indigo-500" />
                <span>3. Issue CI/CD API Key</span>
              </div>
              <p className="text-[11px] text-slate-500">
                Create scoped tr_live_ keys for GitHub Actions, CLI, TypeScript SDK, and MCP calls.
              </p>
            </button>
          </div>
        </div>
      )}

      {/* Quick Metrics Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <button
          type="button"
          onClick={() => setActiveTab('vulnerabilities')}
          className="text-left bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 hover:border-cyan-500/40 transition group"
        >
          <div className="flex items-center justify-between mb-3">
            <div className="w-10 h-10 rounded-lg bg-rose-500/10 border border-rose-500/30 flex items-center justify-center text-rose-500">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <ArrowUpRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 transition" />
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white font-mono tabular-nums">
            {openFindings.length}
          </div>
          <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">Open Security Findings</div>
          <div className="text-[11px] font-mono text-rose-500 mt-2 tabular-nums">
            {criticalCount} Critical • {highCount} High
          </div>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('attack-paths')}
          className="text-left bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 hover:border-cyan-500/40 transition group"
        >
          <div className="flex items-center justify-between mb-3">
            <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-500">
              <GitPullRequest className="w-5 h-5" />
            </div>
            <ArrowUpRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 transition" />
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white font-mono tabular-nums">
            {attackPaths.length}
          </div>
          <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">Active Attack Paths</div>
          <div className="text-[11px] font-mono text-amber-600 dark:text-amber-400 mt-2">
            {attackPaths.length === 0 ? 'No exploitable chains detected' : 'Multi-step exploit chains'}
          </div>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('projects')}
          className="text-left bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 hover:border-cyan-500/40 transition group"
        >
          <div className="flex items-center justify-between mb-3">
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-500">
              <FolderGit2 className="w-5 h-5" />
            </div>
            <ArrowUpRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 transition" />
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white font-mono tabular-nums">
            {projects.length}
          </div>
          <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">Connected Projects</div>
          <div className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400 mt-2 tabular-nums">
            {sbomCount}/{projects.length} SBOM Generated
          </div>
        </button>

        <button
          type="button"
          onClick={() => setActiveTab('incidents')}
          className="text-left bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-5 hover:border-cyan-500/40 transition group"
        >
          <div className="flex items-center justify-between mb-3">
            <div className="w-10 h-10 rounded-lg bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-indigo-500">
              <Flame className="w-5 h-5" />
            </div>
            <ArrowUpRight className="w-4 h-4 text-slate-400 group-hover:text-cyan-500 transition" />
          </div>
          <div className="text-2xl font-bold text-slate-900 dark:text-white font-mono tabular-nums">
            {incidents.length}
          </div>
          <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">Security Incidents</div>
          <div className="text-[11px] font-mono text-indigo-500 mt-2 tabular-nums">
            {activeIncidentsCount} Active / Contained
          </div>
        </button>
      </div>

      {/* Top Prioritized Findings & Attack Path */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-rose-500" />
              <span>Prioritized Risks to Address Now</span>
            </h2>
            <button
              type="button"
              onClick={() => setActiveTab('vulnerabilities')}
              className="text-xs text-cyan-600 dark:text-cyan-400 hover:underline font-medium"
            >
              View All ({findings.length})
            </button>
          </div>
          <div className="space-y-3">
            {prioritizedOpen.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500 bg-slate-50 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800 flex flex-col items-center space-y-2">
                <CheckCircle2 className="w-6 h-6 text-emerald-500" />
                <span>All open vulnerabilities are currently resolved.</span>
              </div>
            ) : (
              prioritizedOpen.slice(0, 3).map((f) => (
                <div
                  key={f.id}
                  className="p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
                >
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-500/15 text-rose-600 dark:text-rose-300 border border-rose-500/30 tabular-nums">
                        {f.priorityTier || f.severity} • CVSS {f.cvss}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500">{f.category}</span>
                      <span className="text-[10px] font-mono text-cyan-600 dark:text-cyan-400 truncate">
                        {f.assetName}
                      </span>
                    </div>
                    <div className="text-sm font-semibold text-slate-900 dark:text-white">{f.title}</div>
                    <div className="text-xs text-slate-500 dark:text-slate-400 mt-1">{f.suggestedFix}</div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setActiveTab('remediation')}
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold whitespace-nowrap transition shrink-0 self-start sm:self-center"
                  >
                    Remediate
                  </button>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Critical Attack Path Summary */}
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider flex items-center gap-2">
                <GitPullRequest className="w-4 h-4 text-amber-500" />
                <span>Top Attack Path</span>
              </h2>
              {attackPaths[0] && (
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-500/20 text-amber-600 dark:text-amber-300 border border-amber-500/30 tabular-nums">
                  Score {attackPaths[0].riskScore}/100
                </span>
              )}
            </div>
            {attackPaths[0] ? (
              <>
                <div className="text-xs font-semibold text-slate-900 dark:text-slate-200 mb-2">
                  {attackPaths[0].title}
                </div>
                <div className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed mb-4">
                  {attackPaths[0].impact}
                </div>
                <div className="space-y-2 mb-4">
                  {attackPaths[0].steps.map((s) => (
                    <div
                      key={s.order}
                      className="flex items-center space-x-2 text-[11px] text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-950 p-2 rounded-lg border border-slate-200 dark:border-slate-800"
                    >
                      <span className="w-4 h-4 rounded-full bg-cyan-500/20 text-cyan-600 dark:text-cyan-400 flex items-center justify-center font-mono text-[10px] shrink-0">
                        {s.order}
                      </span>
                      <span className="truncate font-medium">{s.assetName}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <div className="text-xs text-slate-500 py-8 text-center">
                No active multi-hop attack paths exist for this organization.
              </div>
            )}
          </div>
          <button
            type="button"
            onClick={() => setActiveTab('attack-paths')}
            className="w-full py-2.5 rounded-xl bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-cyan-700 dark:text-cyan-400 text-xs font-semibold transition border border-slate-200 dark:border-slate-700"
          >
            Inspect Attack Paths
          </button>
        </div>
      </div>
    </div>
  );
}
