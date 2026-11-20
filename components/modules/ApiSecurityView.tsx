'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Network, CheckCircle2, FileJson, Globe, Loader2, Lock } from 'lucide-react';

export function ApiSecurityView() {
  const { graphNodes, findings, org, setActiveTab, probeHttpEndpoint, user } = useTrustrail();
  const [specRouteCount, setSpecRouteCount] = useState<number | null>(null);
  const [targetUrl, setTargetUrl] = useState('');
  const [probing, setProbing] = useState(false);
  const [lastProbe, setLastProbe] = useState<Record<string, unknown> | null>(null);

  const apiNodes = graphNodes.filter((n) => n.assetType === 'API Endpoint');
  const apiFindings = findings.filter((f) => f.category === 'API' || (f.category === 'SAST' && /auth|api|sql/i.test(f.title)));
  const openCount = apiFindings.filter((f) => f.status !== 'Resolved').length;

  const inspectOpenApiSpec = async () => {
    try {
      const res = await fetch('/api/v1/openapi.json');
      if (res.ok) {
        const spec = (await res.json()) as { paths?: Record<string, unknown> };
        setSpecRouteCount(Object.keys(spec.paths || {}).length);
      }
    } catch {
      // Ignore transient network errors
    }
  };

  const handleProbe = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetUrl.trim()) return;
    setProbing(true);
    try {
      const res = await probeHttpEndpoint(targetUrl.trim());
      if (res) {
        setLastProbe(res);
        setTargetUrl('');
      }
    } finally {
      setProbing(false);
    }
  };

  const tlsInfo = lastProbe?.tls as
    | { protocol?: string; subject?: string; issuer?: string; daysRemaining?: number; validTo?: string }
    | undefined;

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Network className="w-5 h-5 text-cyan-500" />
              <span>API &amp; Application Exposure Security</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Internet-exposed endpoints, live HTTP/X.509 TLS certificate probes, and API security findings for {org.name}.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={inspectOpenApiSpec}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 text-xs font-semibold hover:border-cyan-500/40 whitespace-nowrap"
            >
              <FileJson className="w-3.5 h-3.5 text-cyan-500" />
              <span>
                {specRouteCount !== null
                  ? `OpenAPI Verified (${specRouteCount} paths)`
                  : 'Inspect Platform OpenAPI 3.1'}
              </span>
            </button>
            <span
              className={`px-3 py-1 rounded-full text-xs font-mono font-bold border whitespace-nowrap tabular-nums ${
                openCount > 0
                  ? 'bg-amber-500/15 text-amber-500 border-amber-500/30'
                  : 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
              }`}
            >
              {openCount} Open API Risks
            </span>
          </div>
        </div>

        {user?.role !== 'Viewer' && (
          <form
            onSubmit={handleProbe}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 mb-5 space-y-3"
          >
            <div className="flex flex-col sm:flex-row gap-3 items-stretch sm:items-center">
              <div className="flex-1 flex items-center gap-2">
                <Globe className="w-4 h-4 text-emerald-500 shrink-0" />
                <input
                  type="url"
                  required
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  placeholder="https://api.yourdomain.com (runs live SSRF-safe TLS cert, HSTS, CSP & CORS audit)"
                  className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono"
                />
              </div>
              <button
                type="submit"
                disabled={probing}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold transition inline-flex items-center justify-center gap-1.5 whitespace-nowrap shrink-0"
              >
                {probing ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Globe className="w-3.5 h-3.5" />}
                <span>{probing ? 'Probing...' : 'Probe Live Endpoint'}</span>
              </button>
            </div>

            {lastProbe && (
              <div className="p-3 rounded-lg bg-white dark:bg-slate-900 border border-emerald-500/30 text-xs font-mono space-y-1">
                <div className="text-emerald-500 font-bold">
                  {String(lastProbe.targetUrl)} — HTTP {String(lastProbe.httpStatus)} ({String(lastProbe.latencyMs)}ms)
                </div>
                {tlsInfo && (
                  <div className="text-slate-600 dark:text-slate-300 flex flex-wrap items-center gap-2">
                    <Lock className="w-3.5 h-3.5 text-cyan-500" />
                    <span>
                      TLS: {tlsInfo.protocol || 'n/a'} • Subject: {tlsInfo.subject || 'n/a'} • Issuer: {tlsInfo.issuer || 'n/a'} • Expires in{' '}
                      {tlsInfo.daysRemaining ?? '?'} day(s)
                    </span>
                  </div>
                )}
              </div>
            )}
          </form>
        )}

        <div className="space-y-3">
          {apiNodes.length === 0 && apiFindings.length === 0 ? (
            <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-8 text-center text-xs text-slate-500">
              No exposed API endpoints or API vulnerabilities recorded for {org.name}. Scan an API route file in Projects to inspect exposure.
            </div>
          ) : (
            <>
              {apiNodes.map((node) => (
                <div
                  key={node.id}
                  className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="flex items-center space-x-3">
                    <div
                      className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 border ${
                        node.openFindingsCount > 0
                          ? 'bg-rose-500/10 text-rose-500 border-rose-500/30'
                          : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30'
                      }`}
                    >
                      <Network className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="text-sm font-bold text-slate-900 dark:text-white font-mono">{node.name}</div>
                      <div className="text-xs text-slate-500">
                        Owner: {node.owner} • Exposure:{' '}
                        {node.internetExposed ? 'Public Internet' : 'Internal Mesh'} • Criticality: {node.criticality}
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => setActiveTab('vulnerabilities')}
                    className={`px-2.5 py-1 rounded text-xs font-mono font-bold border self-start sm:self-center ${
                      node.openFindingsCount > 0
                        ? 'bg-rose-500/15 text-rose-500 border-rose-500/30'
                        : 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                    }`}
                  >
                    {node.openFindingsCount > 0 ? `${node.openFindingsCount} Vulnerable` : 'Protected'}
                  </button>
                </div>
              ))}

              {apiFindings.map((f) => (
                <div
                  key={f.id}
                  className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex items-center justify-between gap-3"
                >
                  <div>
                    <div className="text-xs font-bold text-slate-900 dark:text-white">{f.title}</div>
                    <div className="text-[11px] font-mono text-slate-500">
                      {f.filePath || f.assetName} • Status: {f.status}
                    </div>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-cyan-500/15 text-cyan-500 flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>{f.severity}</span>
                  </span>
                </div>
              ))}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
