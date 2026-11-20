'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Connector } from '@/lib/trustrail-store';
import {
  Plug,
  RefreshCw,
  Power,
  AlertTriangle,
  SlidersHorizontal,
  GitBranch,
  Globe,
  ShieldAlert,
  Loader2,
  Send,
  CheckCircle2,
  Container,
  Lock,
} from 'lucide-react';

export function IntegrationsView() {
  const {
    connectors,
    projects,
    testConnector,
    configureConnector,
    disconnectConnector,
    scanGithubRepo,
    queryOsv,
    probeHttpEndpoint,
    inspectOciImage,
    dispatchTestWebhook,
    user,
  } = useTrustrail();

  const isAdmin = user?.role === 'Owner' || user?.role === 'Admin';
  const canRunTools = user?.role !== 'Viewer';

  // Live Workbench State
  const [ghRepoInput, setGhRepoInput] = useState('expressjs/express');
  const [ghBranchInput, setGhBranchInput] = useState('');
  const [ghBusy, setGhBusy] = useState(false);
  const [ghLastResult, setGhLastResult] = useState<Record<string, unknown> | null>(null);

  const [osvEcosystem, setOsvEcosystem] = useState<'npm' | 'PyPI' | 'Go' | 'Maven'>('npm');
  const [osvPackage, setOsvPackage] = useState('lodash');
  const [osvVersion, setOsvVersion] = useState('4.17.15');
  const [osvProjectId, setOsvProjectId] = useState('');
  const [osvBusy, setOsvBusy] = useState(false);
  const [osvLastResult, setOsvLastResult] = useState<Record<string, unknown> | null>(null);

  const [probeUrl, setProbeUrl] = useState('https://example.com');
  const [probeBusy, setProbeBusy] = useState(false);
  const [probeLastResult, setProbeLastResult] = useState<Record<string, unknown> | null>(null);

  const [ociImage, setOciImage] = useState('library/nginx:latest');
  const [ociBusy, setOciBusy] = useState(false);
  const [ociLastResult, setOciLastResult] = useState<Record<string, unknown> | null>(null);

  // Per-connector configuration drawer state
  const [editingConn, setEditingConn] = useState<Connector | null>(null);
  const [cfgGithubToken, setCfgGithubToken] = useState('');
  const [cfgDefaultRepo, setCfgDefaultRepo] = useState('');
  const [cfgWebhookUrl, setCfgWebhookUrl] = useState('');
  const [cfgAwsRoleArn, setCfgAwsRoleArn] = useState('');
  const [cfgAwsExternalId, setCfgAwsExternalId] = useState('');
  const [cfgAwsAccessKeyId, setCfgAwsAccessKeyId] = useState('');
  const [cfgAwsSecretAccessKey, setCfgAwsSecretAccessKey] = useState('');
  const [cfgAwsRegion, setCfgAwsRegion] = useState('us-east-1');
  const [cfgAzureTenantId, setCfgAzureTenantId] = useState('');
  const [cfgAzureSubId, setCfgAzureSubId] = useState('');
  const [cfgGcpProjectId, setCfgGcpProjectId] = useState('');
  const [cfgSaving, setCfgSaving] = useState(false);

  const openConfigure = (conn: Connector) => {
    if (editingConn?.id === conn.id) {
      setEditingConn(null);
      return;
    }
    setEditingConn(conn);
    setCfgGithubToken('');
    setCfgDefaultRepo(conn.config?.defaultRepo || '');
    setCfgWebhookUrl('');
    setCfgAwsRoleArn(conn.config?.awsRoleArn || '');
    setCfgAwsExternalId('');
    setCfgAwsAccessKeyId('');
    setCfgAwsSecretAccessKey('');
    setCfgAwsRegion(conn.config?.awsRegion || 'us-east-1');
    setCfgAzureTenantId(conn.config?.azureTenantId || '');
    setCfgAzureSubId(conn.config?.azureSubscriptionId || '');
    setCfgGcpProjectId(conn.config?.gcpProjectId || '');
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingConn) return;
    setCfgSaving(true);
    try {
      const payload: Record<string, unknown> = { verifyNow: true };
      if (editingConn.providerKey === 'github') {
        if (cfgGithubToken.trim()) payload.githubToken = cfgGithubToken.trim();
        if (cfgDefaultRepo.trim()) payload.defaultRepo = cfgDefaultRepo.trim();
      } else if (editingConn.providerKey === 'slack') {
        if (cfgWebhookUrl.trim()) payload.webhookUrl = cfgWebhookUrl.trim();
      } else if (editingConn.providerKey === 'aws') {
        if (cfgAwsRoleArn.trim()) payload.awsRoleArn = cfgAwsRoleArn.trim();
        if (cfgAwsExternalId.trim()) payload.awsExternalId = cfgAwsExternalId.trim();
        if (cfgAwsAccessKeyId.trim()) payload.awsAccessKeyId = cfgAwsAccessKeyId.trim();
        if (cfgAwsSecretAccessKey.trim()) payload.awsSecretAccessKey = cfgAwsSecretAccessKey.trim();
        if (cfgAwsRegion.trim()) payload.awsRegion = cfgAwsRegion.trim();
      } else if (editingConn.providerKey === 'azure') {
        if (cfgAzureTenantId.trim()) payload.azureTenantId = cfgAzureTenantId.trim();
        if (cfgAzureSubId.trim()) payload.azureSubscriptionId = cfgAzureSubId.trim();
      } else if (editingConn.providerKey === 'gcp') {
        if (cfgGcpProjectId.trim()) payload.gcpProjectId = cfgGcpProjectId.trim();
      }
      const ok = await configureConnector(editingConn.id, payload);
      if (ok) {
        setEditingConn(null);
      }
    } finally {
      setCfgSaving(false);
    }
  };

  const handleGithubScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ghRepoInput.trim()) return;
    setGhBusy(true);
    try {
      const res = await scanGithubRepo(ghRepoInput.trim(), ghBranchInput.trim() || undefined);
      if (res) setGhLastResult(res);
    } finally {
      setGhBusy(false);
    }
  };

  const handleOsvQuery = async (e: React.FormEvent) => {
    e.preventDefault();
    setOsvBusy(true);
    try {
      const payload = osvProjectId
        ? { projectId: osvProjectId }
        : { packages: [{ ecosystem: osvEcosystem, name: osvPackage.trim(), version: osvVersion.trim() }] };
      const res = await queryOsv(payload);
      if (res) setOsvLastResult(res);
    } finally {
      setOsvBusy(false);
    }
  };

  const handleHttpProbe = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!probeUrl.trim()) return;
    setProbeBusy(true);
    try {
      const res = await probeHttpEndpoint(probeUrl.trim());
      if (res) setProbeLastResult(res);
    } finally {
      setProbeBusy(false);
    }
  };

  const handleOciInspect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ociImage.trim()) return;
    setOciBusy(true);
    try {
      const res = await inspectOciImage(ociImage.trim());
      if (res) setOciLastResult(res);
    } finally {
      setOciBusy(false);
    }
  };

  const sbomProjects = projects.filter((p) => p.sbomGenerated);

  return (
    <div className="space-y-6">
      {/* Live Integrations Workbench */}
      {canRunTools && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-5">
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Plug className="w-4 h-4 text-cyan-500" />
              <span>Live External Security Integrations</span>
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Execute real-time external scans against GitHub repositories, OSV.dev CVE advisories, public HTTPS/TLS endpoints, and OCI Container Registries.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
            {/* 1. Live GitHub Repo Scanner */}
            <form
              onSubmit={handleGithubScan}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-3"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                    <GitBranch className="w-4 h-4 text-cyan-500" />
                    <span>GitHub Repo Scanner</span>
                  </span>
                  <span className="text-[10px] font-mono text-emerald-500">LIVE API</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Fetches repo tree, package.json, Terraform, Dockerfile &amp; source files to generate SBOM + SAST/CVE findings.
                </p>
                <div className="space-y-2">
                  <input
                    type="text"
                    required
                    value={ghRepoInput}
                    onChange={(e) => setGhRepoInput(e.target.value)}
                    placeholder="owner/repo"
                    className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono"
                  />
                  <input
                    type="text"
                    value={ghBranchInput}
                    onChange={(e) => setGhBranchInput(e.target.value)}
                    placeholder="Branch (optional)"
                    className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono"
                  />
                </div>
                {ghLastResult && (
                  <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-[11px] font-mono text-emerald-600 dark:text-emerald-300 space-y-0.5">
                    <div>Repo: {String(ghLastResult.repository)}</div>
                    <div>
                      Files: {Array.isArray(ghLastResult.filesInspected) ? ghLastResult.filesInspected.length : 0} • Findings:{' '}
                      {String(ghLastResult.findingsDetected)}
                    </div>
                  </div>
                )}
              </div>
              <button
                type="submit"
                disabled={ghBusy}
                className="w-full py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold transition flex items-center justify-center gap-1.5 whitespace-nowrap"
              >
                {ghBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <GitBranch className="w-3.5 h-3.5" />}
                <span>{ghBusy ? 'Scanning...' : 'Import & Scan GitHub'}</span>
              </button>
            </form>

            {/* 2. Live OSV.dev CVE Intelligence */}
            <form
              onSubmit={handleOsvQuery}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-3"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                    <ShieldAlert className="w-4 h-4 text-amber-500" />
                    <span>OSV.dev Live CVE Feed</span>
                  </span>
                  <span className="text-[10px] font-mono text-emerald-500">api.osv.dev</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Query Google OSV vulnerability advisories for any dependency or project CycloneDX SBOM.
                </p>
                <div className="space-y-2">
                  {sbomProjects.length > 0 && (
                    <select
                      value={osvProjectId}
                      onChange={(e) => setOsvProjectId(e.target.value)}
                      className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs"
                    >
                      <option value="">Custom package lookup</option>
                      {sbomProjects.map((p) => (
                        <option key={p.id} value={p.id}>
                          SBOM: {p.name}
                        </option>
                      ))}
                    </select>
                  )}
                  {!osvProjectId && (
                    <div className="grid grid-cols-3 gap-1.5">
                      <select
                        value={osvEcosystem}
                        onChange={(e) => setOsvEcosystem(e.target.value as 'npm' | 'PyPI' | 'Go' | 'Maven')}
                        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2 py-1.5 text-xs font-mono"
                      >
                        <option value="npm">npm</option>
                        <option value="PyPI">PyPI</option>
                        <option value="Go">Go</option>
                        <option value="Maven">Maven</option>
                      </select>
                      <input
                        type="text"
                        required
                        value={osvPackage}
                        onChange={(e) => setOsvPackage(e.target.value)}
                        placeholder="pkg"
                        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2 py-1.5 text-xs font-mono"
                      />
                      <input
                        type="text"
                        required
                        value={osvVersion}
                        onChange={(e) => setOsvVersion(e.target.value)}
                        placeholder="ver"
                        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2 py-1.5 text-xs font-mono"
                      />
                    </div>
                  )}
                </div>
                {osvLastResult && (
                  <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30 text-[11px] font-mono text-amber-600 dark:text-amber-300 space-y-0.5">
                    <div>Checked: {String(osvLastResult.queriedCount)} pkg(s)</div>
                    <div>Advisories: {String(osvLastResult.advisoriesCount)}</div>
                  </div>
                )}
              </div>
              <button
                type="submit"
                disabled={osvBusy}
                className="w-full py-2 rounded-lg bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white text-xs font-semibold transition flex items-center justify-center gap-1.5 whitespace-nowrap"
              >
                {osvBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                <span>{osvBusy ? 'Querying...' : 'Query Live CVE Feed'}</span>
              </button>
            </form>

            {/* 3. Live HTTP/TLS Header Probe */}
            <form
              onSubmit={handleHttpProbe}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-3"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                    <Globe className="w-4 h-4 text-emerald-500" />
                    <span>HTTP / X.509 TLS Probe</span>
                  </span>
                  <span className="text-[10px] font-mono text-emerald-500">SSRF-SAFE</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Audits HSTS, CSP, CORS, redirect hops &amp; live X.509 TLS certificate expiry and protocol.
                </p>
                <input
                  type="url"
                  required
                  value={probeUrl}
                  onChange={(e) => setProbeUrl(e.target.value)}
                  placeholder="https://example.com"
                  className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono"
                />
                {probeLastResult && (
                  <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-[11px] font-mono text-emerald-600 dark:text-emerald-300 space-y-0.5">
                    <div>
                      HTTP {String(probeLastResult.httpStatus)} • {String(probeLastResult.latencyMs)}ms
                    </div>
                    <div>
                      Flagged: {Array.isArray(probeLastResult.issuesDetected) ? probeLastResult.issuesDetected.length : 0} issue(s)
                    </div>
                  </div>
                )}
              </div>
              <button
                type="submit"
                disabled={probeBusy}
                className="w-full py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-semibold transition flex items-center justify-center gap-1.5 whitespace-nowrap"
              >
                {probeBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Globe className="w-3.5 h-3.5" />}
                <span>{probeBusy ? 'Probing...' : 'Probe Public URL'}</span>
              </button>
            </form>

            {/* 4. Live OCI Container Registry Inspector */}
            <form
              onSubmit={handleOciInspect}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-3"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                    <Container className="w-4 h-4 text-indigo-500" />
                    <span>OCI Registry Inspector</span>
                  </span>
                  <span className="text-[10px] font-mono text-indigo-400">DIST v2</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Resolves live OCI manifests, SHA256 immutable digests, and flags unpinned container tags.
                </p>
                <input
                  type="text"
                  required
                  value={ociImage}
                  onChange={(e) => setOciImage(e.target.value)}
                  placeholder="library/nginx:latest or ghcr.io/org/app:v1"
                  className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono"
                />
                {ociLastResult && (
                  <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-[11px] font-mono text-indigo-400 space-y-0.5">
                    <div>
                      Layers: {String((ociLastResult.manifest as { layersCount?: number })?.layersCount ?? 0)}
                    </div>
                    <div className="truncate">
                      Digest: {String((ociLastResult.manifest as { digest?: string })?.digest || 'n/a')}
                    </div>
                  </div>
                )}
              </div>
              <button
                type="submit"
                disabled={ociBusy}
                className="w-full py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white text-xs font-semibold transition flex items-center justify-center gap-1.5 whitespace-nowrap"
              >
                {ociBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Container className="w-3.5 h-3.5" />}
                <span>{ociBusy ? 'Inspecting...' : 'Inspect OCI Image'}</span>
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Connectors Grid */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Plug className="w-5 h-5 text-cyan-500" />
              <span>Unified Connector Framework (AES-256-GCM Vault)</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Configure per-organization GitHub tokens, AWS IAM/STS, Azure, GCP, and Slack/HTTPS webhooks. All secrets are encrypted with scoped AES-256-GCM envelopes.
            </p>
          </div>
          <div className="flex items-center gap-2 self-start">
            {isAdmin && (
              <button
                type="button"
                onClick={dispatchTestWebhook}
                className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-xs font-semibold border border-slate-200 dark:border-slate-700 whitespace-nowrap"
              >
                <Send className="w-3.5 h-3.5 text-cyan-500" />
                <span>Send Alert Digest</span>
              </button>
            )}
            <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-cyan-500/15 text-cyan-600 dark:text-cyan-300 border border-cyan-500/30 whitespace-nowrap tabular-nums">
              {connectors.filter((c) => c.status === 'Connected').length} / {connectors.length} Connected
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {connectors.map((conn) => {
            const isConnected = conn.status === 'Connected';
            const needsCreds = conn.healthCheck === 'Credentials_Required';
            const isConfigurable = ['github', 'slack', 'aws', 'azure', 'gcp'].includes(conn.providerKey);
            const isEditing = editingConn?.id === conn.id;

            return (
              <div
                key={conn.id}
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-3">
                    <div className="flex items-center space-x-2 min-w-0">
                      <Plug className="w-4 h-4 text-cyan-500 shrink-0" />
                      <span className="text-sm font-bold text-slate-900 dark:text-white truncate">{conn.name}</span>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0">
                      {conn.availabilityState && (
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                          {conn.availabilityState}
                        </span>
                      )}
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                          isConnected
                            ? 'bg-emerald-500/15 text-emerald-500 border border-emerald-500/30'
                            : needsCreds
                            ? 'bg-amber-500/15 text-amber-500 border border-amber-500/30'
                            : 'bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                        }`}
                      >
                        {conn.status} • {conn.healthCheck}
                      </span>
                    </div>
                  </div>

                  <div className="text-xs text-slate-500 font-mono mb-2 flex items-center justify-between">
                    <span>
                      Category: {conn.category} • Auth: {conn.authType}
                    </span>
                    {conn.config?.encrypted && (
                      <span className="inline-flex items-center gap-1 text-[10px] text-emerald-500">
                        <Lock className="w-3 h-3" />
                        AES-256-GCM v{conn.config.keyVersion ?? 1}
                      </span>
                    )}
                  </div>

                  <div className="text-xs text-slate-700 dark:text-slate-300 font-mono mb-3 bg-white dark:bg-slate-900 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800">
                    <strong>Scopes:</strong> {conn.permissions.join(', ')}
                  </div>

                  {conn.config?.configured && (
                    <div className="text-[11px] font-mono text-emerald-600 dark:text-emerald-300 bg-emerald-500/10 border border-emerald-500/20 rounded-lg p-2.5 mb-3 flex items-center gap-2">
                      <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
                      <span className="truncate">
                        Saved:{' '}
                        {[
                          conn.config.githubTokenHint && `Token ${conn.config.githubTokenHint}`,
                          conn.config.defaultRepo && `Repo ${conn.config.defaultRepo}`,
                          conn.config.webhookUrlHint && `Webhook ${conn.config.webhookUrlHint}`,
                          conn.config.awsRoleArn && `Role ${conn.config.awsRoleArn}`,
                          conn.config.awsAccessKeyIdHint && `Key ${conn.config.awsAccessKeyIdHint}`,
                          conn.config.awsRegion && `Region ${conn.config.awsRegion}`,
                          conn.config.azureTenantId && `Tenant ${conn.config.azureTenantId}`,
                          conn.config.gcpProjectId && `GCP ${conn.config.gcpProjectId}`,
                        ]
                          .filter(Boolean)
                          .join(' • ')}
                      </span>
                    </div>
                  )}

                  {!isConnected && conn.configHint && (
                    <div className="text-[11px] text-amber-600 dark:text-amber-300 bg-amber-500/10 border border-amber-500/20 rounded-lg p-2.5 mb-3 flex items-start gap-2">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                      <span>{conn.configHint}</span>
                    </div>
                  )}

                  {/* Inline Configuration Form */}
                  {isEditing && (
                    <form
                      onSubmit={handleSaveConfig}
                      className="mb-3 p-3.5 rounded-lg bg-white dark:bg-slate-900 border border-cyan-500/40 space-y-2.5"
                    >
                      {conn.providerKey === 'github' && (
                        <>
                          <div>
                            <label className="text-[10px] font-mono uppercase text-slate-500">
                              GitHub Personal Access Token (PAT)
                            </label>
                            <input
                              type="password"
                              value={cfgGithubToken}
                              onChange={(e) => setCfgGithubToken(e.target.value)}
                              placeholder="ghp_... or github_pat_..."
                              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono mt-1"
                            />
                          </div>
                          <div>
                            <label className="text-[10px] font-mono uppercase text-slate-500">
                              Default Repository (Optional)
                            </label>
                            <input
                              type="text"
                              value={cfgDefaultRepo}
                              onChange={(e) => setCfgDefaultRepo(e.target.value)}
                              placeholder="owner/repo"
                              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono mt-1"
                            />
                          </div>
                        </>
                      )}

                      {conn.providerKey === 'slack' && (
                        <div>
                          <label className="text-[10px] font-mono uppercase text-slate-500">
                            Slack / Discord / HTTPS Webhook URL
                          </label>
                          <input
                            type="url"
                            required
                            value={cfgWebhookUrl}
                            onChange={(e) => setCfgWebhookUrl(e.target.value)}
                            placeholder="https://hooks.slack.com/services/..."
                            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono mt-1"
                          />
                        </div>
                      )}

                      {conn.providerKey === 'aws' && (
                        <>
                          <div>
                            <label className="text-[10px] font-mono uppercase text-slate-500">AWS IAM Role ARN (Optional)</label>
                            <input
                              type="text"
                              value={cfgAwsRoleArn}
                              onChange={(e) => setCfgAwsRoleArn(e.target.value)}
                              placeholder="arn:aws:iam::123456789012:role/TrustrailReadOnly"
                              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono mt-1"
                            />
                          </div>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                            <div>
                              <label className="text-[10px] font-mono uppercase text-slate-500">AWS Access Key ID</label>
                              <input
                                type="text"
                                value={cfgAwsAccessKeyId}
                                onChange={(e) => setCfgAwsAccessKeyId(e.target.value)}
                                placeholder="AKIA..."
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono mt-1"
                              />
                            </div>
                            <div>
                              <label className="text-[10px] font-mono uppercase text-slate-500">AWS Secret Access Key</label>
                              <input
                                type="password"
                                value={cfgAwsSecretAccessKey}
                                onChange={(e) => setCfgAwsSecretAccessKey(e.target.value)}
                                placeholder="Secret access key"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono mt-1"
                              />
                            </div>
                          </div>
                          <div className="grid grid-cols-2 gap-2">
                            <div>
                              <label className="text-[10px] font-mono uppercase text-slate-500">Region</label>
                              <input
                                type="text"
                                value={cfgAwsRegion}
                                onChange={(e) => setCfgAwsRegion(e.target.value)}
                                placeholder="us-east-1"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono mt-1"
                              />
                            </div>
                            <div>
                              <label className="text-[10px] font-mono uppercase text-slate-500">External ID</label>
                              <input
                                type="text"
                                value={cfgAwsExternalId}
                                onChange={(e) => setCfgAwsExternalId(e.target.value)}
                                placeholder="trustrail-ext-..."
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono mt-1"
                              />
                            </div>
                          </div>
                        </>
                      )}

                      {conn.providerKey === 'azure' && (
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                          <div>
                            <label className="text-[10px] font-mono uppercase text-slate-500">Azure Tenant ID (UUID)</label>
                            <input
                              type="text"
                              required
                              value={cfgAzureTenantId}
                              onChange={(e) => setCfgAzureTenantId(e.target.value)}
                              placeholder="00000000-0000-0000-0000-000000000000"
                              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono mt-1"
                            />
                          </div>
                          <div>
                            <label className="text-[10px] font-mono uppercase text-slate-500">Subscription ID</label>
                            <input
                              type="text"
                              required
                              value={cfgAzureSubId}
                              onChange={(e) => setCfgAzureSubId(e.target.value)}
                              placeholder="sub-..."
                              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono mt-1"
                            />
                          </div>
                        </div>
                      )}

                      {conn.providerKey === 'gcp' && (
                        <div>
                          <label className="text-[10px] font-mono uppercase text-slate-500">GCP Project ID</label>
                          <input
                            type="text"
                            required
                            value={cfgGcpProjectId}
                            onChange={(e) => setCfgGcpProjectId(e.target.value)}
                            placeholder="my-gcp-security-project"
                            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono mt-1"
                          />
                        </div>
                      )}

                      <div className="flex justify-end gap-2 pt-1">
                        <button
                          type="button"
                          onClick={() => setEditingConn(null)}
                          className="px-2.5 py-1 rounded text-xs bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300"
                        >
                          Cancel
                        </button>
                        <button
                          type="submit"
                          disabled={cfgSaving}
                          className="px-3 py-1 rounded text-xs font-semibold bg-cyan-600 hover:bg-cyan-500 text-white disabled:opacity-50"
                        >
                          {cfgSaving ? 'Saving...' : 'Save & Encrypt'}
                        </button>
                      </div>
                    </form>
                  )}
                </div>

                <div className="pt-3 border-t border-slate-200 dark:border-slate-900 flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[11px] text-slate-500 font-mono">Last Sync: {conn.lastSync}</span>
                  {isAdmin && (
                    <div className="flex flex-wrap items-center gap-2">
                      {isConfigurable && (
                        <button
                          type="button"
                          onClick={() => openConfigure(conn)}
                          className="flex items-center space-x-1 px-2.5 py-1.5 rounded-lg text-xs font-semibold transition border bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700 whitespace-nowrap"
                        >
                          <SlidersHorizontal className="w-3 h-3" />
                          <span>Configure</span>
                        </button>
                      )}
                      <button
                        type="button"
                        onClick={() => testConnector(conn.id)}
                        className="flex items-center space-x-1 px-3 py-1.5 rounded-lg text-xs font-semibold transition border bg-cyan-600 hover:bg-cyan-500 text-white border-cyan-500 whitespace-nowrap"
                      >
                        <RefreshCw className="w-3 h-3" />
                        <span>Verify / Test</span>
                      </button>
                      {isConnected && (
                        <button
                          type="button"
                          onClick={() => disconnectConnector(conn.id)}
                          className="flex items-center space-x-1 px-3 py-1.5 rounded-lg text-xs font-semibold transition border bg-rose-500/15 hover:bg-rose-500/25 text-rose-500 border-rose-500/30 whitespace-nowrap"
                        >
                          <Power className="w-3 h-3" />
                          <span>Disconnect</span>
                        </button>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
