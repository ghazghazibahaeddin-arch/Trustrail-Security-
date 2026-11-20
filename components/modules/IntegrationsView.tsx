'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Connector, ConnectorSyncRun } from '@/lib/trustrail-store';
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
  Search,
  Trash2,
  History,
  Network,
  Boxes,
  KeyRound,
  Activity,
} from 'lucide-react';

const CONFIGURABLE_PROVIDERS = new Set([
  'github',
  'gitlab',
  'bitbucket',
  'slack',
  'teams',
  'email_alerts',
  'aws',
  'azure',
  'gcp',
  'kubernetes',
  'siem_splunk',
  'siem_elastic',
  'sso_oidc',
  'kms_vault',
]);

export function IntegrationsView() {
  const {
    connectors,
    dependencyMap,
    projects,
    siemExports,
    ssoConfig,
    scimTokens,
    testConnector,
    configureConnector,
    disconnectConnector,
    syncConnector,
    deleteConnectorData,
    fetchSyncRuns,
    scanGithubRepo,
    queryOsv,
    queryVulnerabilityIntel,
    probeHttpEndpoint,
    inspectOciImage,
    analyzeKubernetes,
    dispatchTestWebhook,
    exportToSiem,
    configureSso,
    issueScimToken,
    revokeScimToken,
    user,
  } = useTrustrail();

  const isAdmin = user?.role === 'Owner' || user?.role === 'Admin';
  const canRunTools = user?.role !== 'Viewer';

  const [viewMode, setViewMode] = useState<'hub' | 'dependencies' | 'siem_sso'>('hub');
  const [categoryFilter, setCategoryFilter] = useState<string>('All');
  const [searchQuery, setSearchQuery] = useState('');

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

  const [intelCveInput, setIntelCveInput] = useState('CVE-2021-44228');
  const [intelBusy, setIntelBusy] = useState(false);
  const [intelResult, setIntelResult] = useState<Record<string, unknown> | null>(null);

  const [probeUrl, setProbeUrl] = useState('https://example.com');
  const [probeBusy, setProbeBusy] = useState(false);
  const [probeLastResult, setProbeLastResult] = useState<Record<string, unknown> | null>(null);

  const [ociImage, setOciImage] = useState('library/nginx:latest');
  const [ociBusy, setOciBusy] = useState(false);
  const [ociLastResult, setOciLastResult] = useState<Record<string, unknown> | null>(null);

  const [k8sClusterName, setK8sClusterName] = useState('prod-eks-us-east-1');
  const [k8sManifestYaml, setK8sManifestYaml] = useState(
    'apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api-gateway\nspec:\n  template:\n    spec:\n      containers:\n      - name: api\n        securityContext:\n          privileged: true'
  );
  const [k8sBusy, setK8sBusy] = useState(false);
  const [k8sResult, setK8sResult] = useState<Record<string, unknown> | null>(null);

  // Sync History Drawer State
  const [historyConnId, setHistoryConnId] = useState<string | null>(null);
  const [syncRuns, setSyncRuns] = useState<ConnectorSyncRun[]>([]);
  const [loadingRuns, setLoadingRuns] = useState(false);

  // Per-connector configuration drawer state
  const [editingConn, setEditingConn] = useState<Connector | null>(null);
  const [cfgGithubToken, setCfgGithubToken] = useState('');
  const [cfgGithubAppId, setCfgGithubAppId] = useState('');
  const [cfgGithubInstallationId, setCfgGithubInstallationId] = useState('');
  const [cfgGithubPrivateKeyPem, setCfgGithubPrivateKeyPem] = useState('');
  const [cfgDefaultRepo, setCfgDefaultRepo] = useState('');
  const [cfgGitlabUrl, setCfgGitlabUrl] = useState('https://gitlab.com');
  const [cfgGitlabToken, setCfgGitlabToken] = useState('');
  const [cfgBitbucketWorkspace, setCfgBitbucketWorkspace] = useState('');
  const [cfgBitbucketAppPassword, setCfgBitbucketAppPassword] = useState('');
  const [cfgWebhookUrl, setCfgWebhookUrl] = useState('');
  const [cfgTeamsWebhookUrl, setCfgTeamsWebhookUrl] = useState('');
  const [cfgEmailProvider, setCfgEmailProvider] = useState('resend');
  const [cfgEmailApiKey, setCfgEmailApiKey] = useState('');
  const [cfgEmailFrom, setCfgEmailFrom] = useState('');
  const [cfgAwsRoleArn, setCfgAwsRoleArn] = useState('');
  const [cfgAwsExternalId, setCfgAwsExternalId] = useState('');
  const [cfgAwsAccessKeyId, setCfgAwsAccessKeyId] = useState('');
  const [cfgAwsSecretAccessKey, setCfgAwsSecretAccessKey] = useState('');
  const [cfgAwsRegion, setCfgAwsRegion] = useState('us-east-1');
  const [cfgAzureTenantId, setCfgAzureTenantId] = useState('');
  const [cfgAzureSubId, setCfgAzureSubId] = useState('');
  const [cfgGcpProjectId, setCfgGcpProjectId] = useState('');
  const [cfgKubeClusterName, setCfgKubeClusterName] = useState('');
  const [cfgKubeApiUrl, setCfgKubeApiUrl] = useState('');
  const [cfgKubeToken, setCfgKubeToken] = useState('');
  const [cfgSplunkHecUrl, setCfgSplunkHecUrl] = useState('');
  const [cfgSplunkHecToken, setCfgSplunkHecToken] = useState('');
  const [cfgElasticUrl, setCfgElasticUrl] = useState('');
  const [cfgElasticKey, setCfgElasticKey] = useState('');
  const [cfgVaultAddress, setCfgVaultAddress] = useState('');
  const [cfgVaultToken, setCfgVaultToken] = useState('');
  const [cfgKmsArn, setCfgKmsArn] = useState('');
  const [cfgSsoIssuerUrl, setCfgSsoIssuerUrl] = useState('');
  const [cfgSsoClientId, setCfgSsoClientId] = useState('');
  const [cfgSaving, setCfgSaving] = useState(false);

  // SIEM & SSO Tab state
  const [siemDest, setSiemDest] = useState<'splunk' | 'elastic' | 'sentinel' | 'webhook'>('splunk');
  const [ssoProvider, setSsoProvider] = useState<'oidc' | 'saml' | 'okta' | 'entra'>(ssoConfig?.provider || 'oidc');
  const [ssoIssuer, setSsoIssuer] = useState(ssoConfig?.issuerUrl || '');
  const [ssoClientIdInput, setSsoClientIdInput] = useState(ssoConfig?.clientId || '');
  const [ssoDomainHint, setSsoDomainHint] = useState(ssoConfig?.domainHint || '');
  const [scimTokenName, setScimTokenName] = useState('Okta SCIM Directory');
  const [newScimSecret, setNewScimSecret] = useState<string | null>(null);

  const openConfigure = (conn: Connector) => {
    if (editingConn?.id === conn.id) {
      setEditingConn(null);
      return;
    }
    setEditingConn(conn);
    setCfgGithubToken('');
    setCfgGithubAppId(conn.config?.githubAppId || '');
    setCfgGithubInstallationId(conn.config?.githubInstallationId || '');
    setCfgGithubPrivateKeyPem('');
    setCfgDefaultRepo(conn.config?.defaultRepo || '');
    setCfgGitlabUrl(conn.config?.gitlabUrl || 'https://gitlab.com');
    setCfgGitlabToken('');
    setCfgBitbucketWorkspace(conn.config?.bitbucketWorkspace || '');
    setCfgBitbucketAppPassword('');
    setCfgWebhookUrl('');
    setCfgTeamsWebhookUrl('');
    setCfgEmailProvider(conn.config?.emailProvider || 'resend');
    setCfgEmailApiKey('');
    setCfgEmailFrom(conn.config?.emailFrom || '');
    setCfgAwsRoleArn(conn.config?.awsRoleArn || '');
    setCfgAwsExternalId('');
    setCfgAwsAccessKeyId('');
    setCfgAwsSecretAccessKey('');
    setCfgAwsRegion(conn.config?.awsRegion || 'us-east-1');
    setCfgAzureTenantId(conn.config?.azureTenantId || '');
    setCfgAzureSubId(conn.config?.azureSubscriptionId || '');
    setCfgGcpProjectId(conn.config?.gcpProjectId || '');
    setCfgKubeClusterName(conn.config?.kubeClusterName || '');
    setCfgKubeApiUrl('');
    setCfgKubeToken('');
    setCfgSplunkHecUrl('');
    setCfgSplunkHecToken('');
    setCfgElasticUrl('');
    setCfgElasticKey('');
    setCfgVaultAddress(conn.config?.vaultAddress || '');
    setCfgVaultToken('');
    setCfgKmsArn(conn.config?.awsKmsKeyArn || '');
    setCfgSsoIssuerUrl(conn.config?.ssoIssuerUrl || '');
    setCfgSsoClientId(conn.config?.ssoClientId || '');
  };

  const handleToggleHistory = async (connId: string) => {
    if (historyConnId === connId) {
      setHistoryConnId(null);
      return;
    }
    setHistoryConnId(connId);
    setLoadingRuns(true);
    try {
      const runs = await fetchSyncRuns(connId);
      setSyncRuns(runs);
    } finally {
      setLoadingRuns(false);
    }
  };

  const handleSaveConfig = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!editingConn) return;
    setCfgSaving(true);
    try {
      const payload: Record<string, unknown> = { verifyNow: true };
      const k = editingConn.providerKey;
      if (k === 'github') {
        if (cfgGithubToken.trim()) payload.githubToken = cfgGithubToken.trim();
        if (cfgGithubAppId.trim()) payload.githubAppId = cfgGithubAppId.trim();
        if (cfgGithubInstallationId.trim()) payload.githubInstallationId = cfgGithubInstallationId.trim();
        if (cfgGithubPrivateKeyPem.trim()) payload.githubPrivateKeyPem = cfgGithubPrivateKeyPem.trim();
        if (cfgDefaultRepo.trim()) payload.defaultRepo = cfgDefaultRepo.trim();
      } else if (k === 'gitlab') {
        if (cfgGitlabUrl.trim()) payload.gitlabUrl = cfgGitlabUrl.trim();
        if (cfgGitlabToken.trim()) payload.gitlabToken = cfgGitlabToken.trim();
      } else if (k === 'bitbucket') {
        if (cfgBitbucketWorkspace.trim()) payload.bitbucketWorkspace = cfgBitbucketWorkspace.trim();
        if (cfgBitbucketAppPassword.trim()) payload.bitbucketAppPassword = cfgBitbucketAppPassword.trim();
      } else if (k === 'slack') {
        if (cfgWebhookUrl.trim()) payload.webhookUrl = cfgWebhookUrl.trim();
      } else if (k === 'teams') {
        if (cfgTeamsWebhookUrl.trim()) payload.teamsWebhookUrl = cfgTeamsWebhookUrl.trim();
      } else if (k === 'email_alerts') {
        if (cfgEmailProvider.trim()) payload.emailProvider = cfgEmailProvider.trim();
        if (cfgEmailApiKey.trim()) payload.emailApiKey = cfgEmailApiKey.trim();
        if (cfgEmailFrom.trim()) payload.emailFrom = cfgEmailFrom.trim();
      } else if (k === 'aws') {
        if (cfgAwsRoleArn.trim()) payload.awsRoleArn = cfgAwsRoleArn.trim();
        if (cfgAwsExternalId.trim()) payload.awsExternalId = cfgAwsExternalId.trim();
        if (cfgAwsAccessKeyId.trim()) payload.awsAccessKeyId = cfgAwsAccessKeyId.trim();
        if (cfgAwsSecretAccessKey.trim()) payload.awsSecretAccessKey = cfgAwsSecretAccessKey.trim();
        if (cfgAwsRegion.trim()) payload.awsRegion = cfgAwsRegion.trim();
      } else if (k === 'azure') {
        if (cfgAzureTenantId.trim()) payload.azureTenantId = cfgAzureTenantId.trim();
        if (cfgAzureSubId.trim()) payload.azureSubscriptionId = cfgAzureSubId.trim();
      } else if (k === 'gcp') {
        if (cfgGcpProjectId.trim()) payload.gcpProjectId = cfgGcpProjectId.trim();
      } else if (k === 'kubernetes') {
        if (cfgKubeClusterName.trim()) payload.kubeClusterName = cfgKubeClusterName.trim();
        if (cfgKubeApiUrl.trim()) payload.kubeApiUrl = cfgKubeApiUrl.trim();
        if (cfgKubeToken.trim()) payload.kubeToken = cfgKubeToken.trim();
      } else if (k === 'siem_splunk') {
        if (cfgSplunkHecUrl.trim()) payload.splunkHecUrl = cfgSplunkHecUrl.trim();
        if (cfgSplunkHecToken.trim()) payload.splunkHecToken = cfgSplunkHecToken.trim();
      } else if (k === 'siem_elastic') {
        if (cfgElasticUrl.trim()) payload.elasticEndpointUrl = cfgElasticUrl.trim();
        if (cfgElasticKey.trim()) payload.elasticApiKey = cfgElasticKey.trim();
      } else if (k === 'kms_vault') {
        if (cfgVaultAddress.trim()) payload.vaultAddress = cfgVaultAddress.trim();
        if (cfgVaultToken.trim()) payload.vaultToken = cfgVaultToken.trim();
        if (cfgKmsArn.trim()) payload.awsKmsKeyArn = cfgKmsArn.trim();
      } else if (k === 'sso_oidc') {
        if (cfgSsoIssuerUrl.trim()) payload.ssoIssuerUrl = cfgSsoIssuerUrl.trim();
        if (cfgSsoClientId.trim()) payload.ssoClientId = cfgSsoClientId.trim();
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

  const handleIntelQuery = async (e: React.FormEvent) => {
    e.preventDefault();
    const cveIds = intelCveInput
      .split(',')
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean);
    if (cveIds.length === 0) return;
    setIntelBusy(true);
    try {
      const res = await queryVulnerabilityIntel({ cveIds, forceRefresh: false });
      if (res) setIntelResult(res);
    } finally {
      setIntelBusy(false);
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

  const handleK8sAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!k8sManifestYaml.trim()) return;
    setK8sBusy(true);
    try {
      const res = await analyzeKubernetes({
        clusterName: k8sClusterName.trim() || 'k8s-cluster',
        manifestYaml: k8sManifestYaml,
      });
      if (res) setK8sResult(res);
    } finally {
      setK8sBusy(false);
    }
  };

  const sbomProjects = projects.filter((p) => p.sbomGenerated);
  const categories = ['All', ...Array.from(new Set(connectors.map((c) => c.category)))];
  const filteredConnectors = connectors.filter((c) => {
    const matchesCategory = categoryFilter === 'All' || c.category === categoryFilter;
    const q = searchQuery.trim().toLowerCase();
    const matchesSearch =
      !q ||
      c.name.toLowerCase().includes(q) ||
      c.providerKey.toLowerCase().includes(q) ||
      c.category.toLowerCase().includes(q);
    return matchesCategory && matchesSearch;
  });

  const healthyCount = connectors.filter(
    (c) => c.status === 'Connected' || c.lifecycleState === 'HEALTHY' || c.lifecycleState === 'CONNECTED'
  ).length;

  return (
    <div className="space-y-6">
      {/* Live Integrations Workbench */}
      {canRunTools && (
        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-5">
          <div>
            <h2 className="text-base font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Plug className="w-4 h-4 text-cyan-500" />
              <span>Live External Security &amp; Threat Intel Workbench</span>
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Run real-time external scans against GitHub repos, OSV/NVD/CISA KEV/EPSS feeds, public HTTPS/TLS endpoints, OCI registries, and Kubernetes workloads.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
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
                  Fetches repo tree, package.json, Terraform, Dockerfile &amp; source files for SBOM + SAST/CVE findings.
                </p>
                <div className="grid grid-cols-2 gap-2">
                  <input
                    type="text"
                    required
                    value={ghRepoInput}
                    onChange={(e) => setGhRepoInput(e.target.value)}
                    placeholder="owner/repo"
                    className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                  />
                  <input
                    type="text"
                    value={ghBranchInput}
                    onChange={(e) => setGhBranchInput(e.target.value)}
                    placeholder="Branch (opt)"
                    className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                  />
                </div>
                {ghLastResult && (
                  <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-[11px] font-mono text-emerald-600 dark:text-emerald-300">
                    {String(ghLastResult.repository)} • Findings: {String(ghLastResult.findingsDetected)}
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
                    <span>OSV.dev Live Package Feed</span>
                  </span>
                  <span className="text-[10px] font-mono text-emerald-500">api.osv.dev</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Query Google OSV advisories for any dependency or project CycloneDX SBOM.
                </p>
                <div className="space-y-2">
                  {sbomProjects.length > 0 && (
                    <select
                      value={osvProjectId}
                      onChange={(e) => setOsvProjectId(e.target.value)}
                      className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs"
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
                  <div className="p-2 rounded-lg bg-amber-500/10 border border-amber-500/30 text-[11px] font-mono text-amber-600 dark:text-amber-300">
                    Checked: {String(osvLastResult.queriedCount)} pkg(s) • Advisories: {String(osvLastResult.advisoriesCount)}
                  </div>
                )}
              </div>
              <button
                type="submit"
                disabled={osvBusy}
                className="w-full py-2 rounded-lg bg-amber-600 hover:bg-amber-500 disabled:opacity-50 text-white text-xs font-semibold transition flex items-center justify-center gap-1.5 whitespace-nowrap"
              >
                {osvBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <ShieldAlert className="w-3.5 h-3.5" />}
                <span>{osvBusy ? 'Querying...' : 'Query OSV Advisories'}</span>
              </button>
            </form>

            {/* 3. Multi-Source CVE Intel (NVD + CISA KEV + FIRST EPSS) */}
            <form
              onSubmit={handleIntelQuery}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-3"
            >
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                    <Activity className="w-4 h-4 text-rose-500" />
                    <span>NVD + CISA KEV + EPSS Hub</span>
                  </span>
                  <span className="text-[10px] font-mono text-rose-400">RISK INTEL</span>
                </div>
                <p className="text-[11px] text-slate-500">
                  Enrich CVE IDs with live KEV exploit status and EPSS probability to uplift Trustrail Risk Engine priorities.
                </p>
                <input
                  type="text"
                  required
                  value={intelCveInput}
                  onChange={(e) => setIntelCveInput(e.target.value)}
                  placeholder="CVE-2021-44228, CVE-2024-3094"
                  className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                />
                {intelResult && Array.isArray(intelResult.cveResults) && intelResult.cveResults.length > 0 && (
                  <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30 text-[11px] font-mono text-rose-500 dark:text-rose-300 space-y-0.5">
                    {(intelResult.cveResults as Array<{ cveId: string; kevListed: boolean; epssScore: number | null }>)
                      .slice(0, 2)
                      .map((r) => (
                        <div key={r.cveId}>
                          {r.cveId}: {r.kevListed ? 'KEV LISTED' : 'Non-KEV'} • EPSS{' '}
                          {r.epssScore !== null ? `${Math.round(r.epssScore * 100)}%` : 'n/a'}
                        </div>
                      ))}
                  </div>
                )}
              </div>
              <button
                type="submit"
                disabled={intelBusy}
                className="w-full py-2 rounded-lg bg-rose-600 hover:bg-rose-500 disabled:opacity-50 text-white text-xs font-semibold transition flex items-center justify-center gap-1.5 whitespace-nowrap"
              >
                {intelBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />}
                <span>{intelBusy ? 'Enriching...' : 'Enrich CVE Risk Intel'}</span>
              </button>
            </form>

            {/* 4. Live HTTP/TLS Header Probe */}
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
                  className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                />
                {probeLastResult && (
                  <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-[11px] font-mono text-emerald-600 dark:text-emerald-300">
                    HTTP {String(probeLastResult.httpStatus)} • Flagged:{' '}
                    {Array.isArray(probeLastResult.issuesDetected) ? probeLastResult.issuesDetected.length : 0}
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

            {/* 5. Live OCI Container Registry Inspector */}
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
                  placeholder="library/nginx:latest"
                  className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                />
                {ociLastResult && (
                  <div className="p-2 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-[11px] font-mono text-indigo-400 truncate">
                    Layers: {String((ociLastResult.manifest as { layersCount?: number })?.layersCount ?? 0)} •{' '}
                    {String((ociLastResult.manifest as { digest?: string })?.digest || 'n/a')}
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

            {/* 6. Kubernetes RBAC & Pod Security Analyzer */}
            <form
              onSubmit={handleK8sAnalyze}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-3"
            >
              <div className="space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                    <Boxes className="w-4 h-4 text-sky-500" />
                    <span>Kubernetes Posture Analyzer</span>
                  </span>
                  <span className="text-[10px] font-mono text-sky-400">RBAC + PSS</span>
                </div>
                <input
                  type="text"
                  value={k8sClusterName}
                  onChange={(e) => setK8sClusterName(e.target.value)}
                  placeholder="Cluster name"
                  className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono"
                />
                <textarea
                  rows={2}
                  value={k8sManifestYaml}
                  onChange={(e) => setK8sManifestYaml(e.target.value)}
                  placeholder="Paste Deployment / ClusterRole YAML..."
                  className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-[11px] font-mono"
                />
                {k8sResult && (
                  <div className="p-2 rounded-lg bg-sky-500/10 border border-sky-500/30 text-[11px] font-mono text-sky-500 dark:text-sky-300">
                    Risks: {String(k8sResult.findingsCount ?? 0)} ({String(k8sResult.newFindingsInserted ?? 0)} new)
                  </div>
                )}
              </div>
              <button
                type="submit"
                disabled={k8sBusy}
                className="w-full py-2 rounded-lg bg-sky-600 hover:bg-sky-500 disabled:opacity-50 text-white text-xs font-semibold transition flex items-center justify-center gap-1.5 whitespace-nowrap"
              >
                {k8sBusy ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Boxes className="w-3.5 h-3.5" />}
                <span>{k8sBusy ? 'Analyzing...' : 'Analyze K8s Manifests'}</span>
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Main Integration Hub Panel */}
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Plug className="w-5 h-5 text-cyan-500" />
              <span>Integration Fabric &amp; Connector Hub</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Manage 19 source-control, cloud, Kubernetes, threat-intel, SIEM, SSO, and notification connectors with AES-256-GCM credential envelopes and sync cursors.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2 self-start">
            <div className="inline-flex rounded-lg bg-slate-100 dark:bg-slate-800 p-1 border border-slate-200 dark:border-slate-700">
              <button
                type="button"
                onClick={() => setViewMode('hub')}
                className={`px-3 py-1 rounded-md text-xs font-semibold transition ${
                  viewMode === 'hub'
                    ? 'bg-cyan-600 text-white'
                    : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                Connectors ({connectors.length})
              </button>
              <button
                type="button"
                onClick={() => setViewMode('dependencies')}
                className={`px-3 py-1 rounded-md text-xs font-semibold transition flex items-center gap-1 ${
                  viewMode === 'dependencies'
                    ? 'bg-cyan-600 text-white'
                    : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                <Network className="w-3.5 h-3.5" />
                <span>Dependency Map</span>
              </button>
              <button
                type="button"
                onClick={() => setViewMode('siem_sso')}
                className={`px-3 py-1 rounded-md text-xs font-semibold transition flex items-center gap-1 ${
                  viewMode === 'siem_sso'
                    ? 'bg-cyan-600 text-white'
                    : 'text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white'
                }`}
              >
                <KeyRound className="w-3.5 h-3.5" />
                <span>SIEM &amp; SSO/SCIM</span>
              </button>
            </div>
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
              {healthyCount} / {connectors.length} Connected
            </span>
          </div>
        </div>

        {/* View 1: Connector Hub Grid */}
        {viewMode === 'hub' && (
          <>
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div className="flex flex-wrap gap-1.5">
                {categories.map((cat) => (
                  <button
                    key={cat}
                    type="button"
                    onClick={() => setCategoryFilter(cat)}
                    className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold transition border ${
                      categoryFilter === cat
                        ? 'bg-cyan-600 text-white border-cyan-500'
                        : 'bg-slate-50 dark:bg-slate-950 text-slate-600 dark:text-slate-400 border-slate-200 dark:border-slate-800 hover:border-cyan-500/40'
                    }`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
              <div className="relative w-full sm:w-64">
                <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Filter connectors..."
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredConnectors.map((conn) => {
                const isConnected = conn.status === 'Connected' || conn.lifecycleState === 'HEALTHY';
                const needsCreds =
                  conn.healthCheck === 'Credentials_Required' || conn.lifecycleState === 'NOT_CONFIGURED';
                const isConfigurable = CONFIGURABLE_PROVIDERS.has(conn.providerKey);
                const isEditing = editingConn?.id === conn.id;
                const showingHistory = historyConnId === conn.id;

                return (
                  <div
                    key={conn.id}
                    className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-center justify-between gap-2 mb-2.5">
                        <div className="flex items-center space-x-2 min-w-0">
                          <Plug className="w-4 h-4 text-cyan-500 shrink-0" />
                          <span className="text-sm font-bold text-slate-900 dark:text-white truncate">{conn.name}</span>
                        </div>
                        <div className="flex items-center gap-1.5 shrink-0">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                              isConnected
                                ? 'bg-emerald-500/15 text-emerald-500 border border-emerald-500/30'
                                : needsCreds
                                ? 'bg-amber-500/15 text-amber-500 border border-amber-500/30'
                                : 'bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400'
                            }`}
                          >
                            {conn.lifecycleState || conn.status}
                          </span>
                        </div>
                      </div>

                      <div className="text-[11px] text-slate-500 font-mono mb-2 flex flex-wrap items-center justify-between gap-2">
                        <span>
                          {conn.category} • {conn.authType} • {conn.dataDirection || 'bidirectional'}
                        </span>
                        {conn.config?.encrypted && (
                          <span className="inline-flex items-center gap-1 text-[10px] text-emerald-500">
                            <Lock className="w-3 h-3" />
                            AES-256-GCM v{conn.config.keyVersion ?? 1}
                          </span>
                        )}
                      </div>

                      <div className="grid grid-cols-3 gap-2 mb-2.5 text-[10px] font-mono">
                        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2 py-1.5">
                          <span className="text-slate-400">Assets: </span>
                          <span className="font-bold text-slate-900 dark:text-white">{conn.assetsDiscovered ?? 0}</span>
                        </div>
                        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2 py-1.5">
                          <span className="text-slate-400">Events: </span>
                          <span className="font-bold text-slate-900 dark:text-white">{conn.eventsImported ?? 0}</span>
                        </div>
                        <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2 py-1.5">
                          <span className="text-slate-400">Failures: </span>
                          <span className={`font-bold ${(conn.failureCount ?? 0) > 0 ? 'text-rose-500' : 'text-slate-900 dark:text-white'}`}>
                            {conn.failureCount ?? 0}
                          </span>
                        </div>
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
                              conn.config.githubTokenHint && `PAT ${conn.config.githubTokenHint}`,
                              conn.config.githubAppId && `App ${conn.config.githubAppId}`,
                              conn.config.defaultRepo && `Repo ${conn.config.defaultRepo}`,
                              conn.config.gitlabUrl && `${conn.config.gitlabUrl}`,
                              conn.config.gitlabTokenHint && `GL ${conn.config.gitlabTokenHint}`,
                              conn.config.bitbucketWorkspace && `BB ${conn.config.bitbucketWorkspace}`,
                              conn.config.webhookUrlHint && `Hook ${conn.config.webhookUrlHint}`,
                              conn.config.teamsWebhookUrlHint && `Teams ${conn.config.teamsWebhookUrlHint}`,
                              conn.config.emailFrom && `Email ${conn.config.emailFrom}`,
                              conn.config.awsRoleArn && `Role ${conn.config.awsRoleArn}`,
                              conn.config.awsAccessKeyIdHint && `Key ${conn.config.awsAccessKeyIdHint}`,
                              conn.config.azureTenantId && `Tenant ${conn.config.azureTenantId}`,
                              conn.config.gcpProjectId && `GCP ${conn.config.gcpProjectId}`,
                              conn.config.kubeClusterName && `K8s ${conn.config.kubeClusterName}`,
                              conn.config.splunkHecUrlHint && `Splunk ${conn.config.splunkHecUrlHint}`,
                              conn.config.elasticEndpointUrlHint && `Elastic ${conn.config.elasticEndpointUrlHint}`,
                              conn.config.vaultAddress && `Vault ${conn.config.vaultAddress}`,
                              conn.config.ssoIssuerUrl && `SSO ${conn.config.ssoIssuerUrl}`,
                            ]
                              .filter(Boolean)
                              .join(' • ')}
                          </span>
                        </div>
                      )}

                      {!isConnected && conn.configHint && (
                        <div className="text-[11px] text-amber-600 dark:text-amber-300 bg-amber-500/10 border border-amber-500/20 rounded-lg p-2.5 mb-3 flex items-start gap-2">
                          <AlertTriangle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                          <span>{conn.lastError || conn.configHint}</span>
                        </div>
                      )}

                      {/* Sync Run History Drawer */}
                      {showingHistory && (
                        <div className="mb-3 p-3 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 space-y-2">
                          <div className="text-[11px] font-bold text-slate-700 dark:text-slate-200 flex items-center justify-between">
                            <span>Recent Sync Runs</span>
                            {conn.syncCursor && (
                              <span className="text-[10px] font-mono text-cyan-500">Cursor: {conn.syncCursor}</span>
                            )}
                          </div>
                          {loadingRuns ? (
                            <div className="text-xs text-slate-500">Loading sync runs...</div>
                          ) : syncRuns.length === 0 ? (
                            <div className="text-[11px] text-slate-500">No sync runs recorded yet. Click Sync Now to run an initial sync.</div>
                          ) : (
                            <div className="space-y-1.5 max-h-36 overflow-y-auto">
                              {syncRuns.map((run) => (
                                <div
                                  key={run.id}
                                  className="text-[11px] font-mono p-2 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 flex items-center justify-between"
                                >
                                  <span>
                                    {run.mode} • {run.status} • {run.assetsDiscovered} assets / {run.eventsImported} events
                                  </span>
                                  <span className="text-slate-400">{run.startedAt.slice(0, 19).replace('T', ' ')}</span>
                                </div>
                              ))}
                            </div>
                          )}
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
                              <div className="grid grid-cols-2 gap-2">
                                <input
                                  type="text"
                                  value={cfgGithubAppId}
                                  onChange={(e) => setCfgGithubAppId(e.target.value)}
                                  placeholder="GitHub App ID (opt)"
                                  className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                                />
                                <input
                                  type="text"
                                  value={cfgGithubInstallationId}
                                  onChange={(e) => setCfgGithubInstallationId(e.target.value)}
                                  placeholder="Installation ID (opt)"
                                  className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                                />
                              </div>
                              <textarea
                                rows={2}
                                value={cfgGithubPrivateKeyPem}
                                onChange={(e) => setCfgGithubPrivateKeyPem(e.target.value)}
                                placeholder="GitHub App RS256 Private Key PEM (optional)"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-[11px] font-mono"
                              />
                              <input
                                type="text"
                                value={cfgDefaultRepo}
                                onChange={(e) => setCfgDefaultRepo(e.target.value)}
                                placeholder="Default repository (owner/repo)"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                            </>
                          )}

                          {conn.providerKey === 'gitlab' && (
                            <div className="space-y-2">
                              <input
                                type="url"
                                value={cfgGitlabUrl}
                                onChange={(e) => setCfgGitlabUrl(e.target.value)}
                                placeholder="https://gitlab.com"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                              <input
                                type="password"
                                required
                                value={cfgGitlabToken}
                                onChange={(e) => setCfgGitlabToken(e.target.value)}
                                placeholder="glpat-..."
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                            </div>
                          )}

                          {conn.providerKey === 'bitbucket' && (
                            <div className="space-y-2">
                              <input
                                type="text"
                                required
                                value={cfgBitbucketWorkspace}
                                onChange={(e) => setCfgBitbucketWorkspace(e.target.value)}
                                placeholder="Bitbucket Workspace"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                              <input
                                type="password"
                                required
                                value={cfgBitbucketAppPassword}
                                onChange={(e) => setCfgBitbucketAppPassword(e.target.value)}
                                placeholder="App Password / Token"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                            </div>
                          )}

                          {conn.providerKey === 'slack' && (
                            <input
                              type="url"
                              required
                              value={cfgWebhookUrl}
                              onChange={(e) => setCfgWebhookUrl(e.target.value)}
                              placeholder="https://hooks.slack.com/services/..."
                              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                            />
                          )}

                          {conn.providerKey === 'teams' && (
                            <input
                              type="url"
                              required
                              value={cfgTeamsWebhookUrl}
                              onChange={(e) => setCfgTeamsWebhookUrl(e.target.value)}
                              placeholder="https://outlook.office.com/webhook/..."
                              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                            />
                          )}

                          {conn.providerKey === 'email_alerts' && (
                            <div className="space-y-2">
                              <div className="grid grid-cols-2 gap-2">
                                <select
                                  value={cfgEmailProvider}
                                  onChange={(e) => setCfgEmailProvider(e.target.value)}
                                  className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                                >
                                  <option value="resend">Resend</option>
                                  <option value="postmark">Postmark</option>
                                  <option value="ses">AWS SES</option>
                                </select>
                                <input
                                  type="email"
                                  value={cfgEmailFrom}
                                  onChange={(e) => setCfgEmailFrom(e.target.value)}
                                  placeholder="security@acme.cloud"
                                  className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                                />
                              </div>
                              <input
                                type="password"
                                required
                                value={cfgEmailApiKey}
                                onChange={(e) => setCfgEmailApiKey(e.target.value)}
                                placeholder="Provider API Key"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                            </div>
                          )}

                          {conn.providerKey === 'aws' && (
                            <>
                              <input
                                type="text"
                                value={cfgAwsRoleArn}
                                onChange={(e) => setCfgAwsRoleArn(e.target.value)}
                                placeholder="arn:aws:iam::123456789012:role/TrustrailReadOnly"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                              <div className="grid grid-cols-2 gap-2">
                                <input
                                  type="text"
                                  value={cfgAwsAccessKeyId}
                                  onChange={(e) => setCfgAwsAccessKeyId(e.target.value)}
                                  placeholder="AKIA..."
                                  className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                                />
                                <input
                                  type="password"
                                  value={cfgAwsSecretAccessKey}
                                  onChange={(e) => setCfgAwsSecretAccessKey(e.target.value)}
                                  placeholder="Secret Access Key"
                                  className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                                />
                              </div>
                              <div className="grid grid-cols-2 gap-2">
                                <input
                                  type="text"
                                  value={cfgAwsRegion}
                                  onChange={(e) => setCfgAwsRegion(e.target.value)}
                                  placeholder="us-east-1"
                                  className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                                />
                                <input
                                  type="text"
                                  value={cfgAwsExternalId}
                                  onChange={(e) => setCfgAwsExternalId(e.target.value)}
                                  placeholder="External ID"
                                  className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                                />
                              </div>
                            </>
                          )}

                          {conn.providerKey === 'azure' && (
                            <div className="grid grid-cols-2 gap-2">
                              <input
                                type="text"
                                required
                                value={cfgAzureTenantId}
                                onChange={(e) => setCfgAzureTenantId(e.target.value)}
                                placeholder="Azure Tenant UUID"
                                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                              <input
                                type="text"
                                required
                                value={cfgAzureSubId}
                                onChange={(e) => setCfgAzureSubId(e.target.value)}
                                placeholder="Subscription ID"
                                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                            </div>
                          )}

                          {conn.providerKey === 'gcp' && (
                            <input
                              type="text"
                              required
                              value={cfgGcpProjectId}
                              onChange={(e) => setCfgGcpProjectId(e.target.value)}
                              placeholder="my-gcp-security-project"
                              className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                            />
                          )}

                          {conn.providerKey === 'kubernetes' && (
                            <div className="space-y-2">
                              <input
                                type="text"
                                value={cfgKubeClusterName}
                                onChange={(e) => setCfgKubeClusterName(e.target.value)}
                                placeholder="Cluster name (e.g. prod-eks)"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                              <input
                                type="url"
                                value={cfgKubeApiUrl}
                                onChange={(e) => setCfgKubeApiUrl(e.target.value)}
                                placeholder="https://k8s-api.example.com:6443"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                              <input
                                type="password"
                                value={cfgKubeToken}
                                onChange={(e) => setCfgKubeToken(e.target.value)}
                                placeholder="Read-only ServiceAccount Bearer Token"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                            </div>
                          )}

                          {conn.providerKey === 'siem_splunk' && (
                            <div className="space-y-2">
                              <input
                                type="url"
                                required
                                value={cfgSplunkHecUrl}
                                onChange={(e) => setCfgSplunkHecUrl(e.target.value)}
                                placeholder="https://splunk-hec.example.com:8088/services/collector"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                              <input
                                type="password"
                                required
                                value={cfgSplunkHecToken}
                                onChange={(e) => setCfgSplunkHecToken(e.target.value)}
                                placeholder="Splunk HEC Token"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                            </div>
                          )}

                          {conn.providerKey === 'siem_elastic' && (
                            <div className="space-y-2">
                              <input
                                type="url"
                                required
                                value={cfgElasticUrl}
                                onChange={(e) => setCfgElasticUrl(e.target.value)}
                                placeholder="https://elastic-siem.example.com:9200/_bulk"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                              <input
                                type="password"
                                required
                                value={cfgElasticKey}
                                onChange={(e) => setCfgElasticKey(e.target.value)}
                                placeholder="Elastic API Key / Sentinel Shared Key"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                            </div>
                          )}

                          {conn.providerKey === 'kms_vault' && (
                            <div className="space-y-2">
                              <input
                                type="url"
                                value={cfgVaultAddress}
                                onChange={(e) => setCfgVaultAddress(e.target.value)}
                                placeholder="https://vault.example.com:8200"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                              <input
                                type="password"
                                value={cfgVaultToken}
                                onChange={(e) => setCfgVaultToken(e.target.value)}
                                placeholder="Vault Token (optional)"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                              <input
                                type="text"
                                value={cfgKmsArn}
                                onChange={(e) => setCfgKmsArn(e.target.value)}
                                placeholder="AWS KMS Key ARN (optional)"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                            </div>
                          )}

                          {conn.providerKey === 'sso_oidc' && (
                            <div className="space-y-2">
                              <input
                                type="url"
                                required
                                value={cfgSsoIssuerUrl}
                                onChange={(e) => setCfgSsoIssuerUrl(e.target.value)}
                                placeholder="https://login.okta.com/oauth2/default"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                              />
                              <input
                                type="text"
                                required
                                value={cfgSsoClientId}
                                onChange={(e) => setCfgSsoClientId(e.target.value)}
                                placeholder="OIDC Client ID"
                                className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
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
                      <div className="flex flex-wrap items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => handleToggleHistory(conn.id)}
                          className="flex items-center space-x-1 px-2 py-1 rounded-lg text-[11px] font-semibold border bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-200 dark:border-slate-700"
                        >
                          <History className="w-3 h-3" />
                          <span>Runs</span>
                        </button>
                        {canRunTools && (
                          <button
                            type="button"
                            onClick={() => syncConnector(conn.id, 'incremental')}
                            className="flex items-center space-x-1 px-2.5 py-1 rounded-lg text-[11px] font-semibold border bg-emerald-600/15 hover:bg-emerald-600/25 text-emerald-500 border-emerald-500/30"
                          >
                            <RefreshCw className="w-3 h-3" />
                            <span>Sync Now</span>
                          </button>
                        )}
                        {isAdmin && isConfigurable && (
                          <button
                            type="button"
                            onClick={() => openConfigure(conn)}
                            className="flex items-center space-x-1 px-2.5 py-1 rounded-lg text-[11px] font-semibold transition border bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-200 border-slate-200 dark:border-slate-700"
                          >
                            <SlidersHorizontal className="w-3 h-3" />
                            <span>Configure</span>
                          </button>
                        )}
                        {isAdmin && (
                          <button
                            type="button"
                            onClick={() => testConnector(conn.id)}
                            className="flex items-center space-x-1 px-2.5 py-1 rounded-lg text-[11px] font-semibold transition border bg-cyan-600 hover:bg-cyan-500 text-white border-cyan-500"
                          >
                            <CheckCircle2 className="w-3 h-3" />
                            <span>Verify</span>
                          </button>
                        )}
                        {isAdmin && isConnected && (
                          <button
                            type="button"
                            onClick={() => disconnectConnector(conn.id)}
                            className="flex items-center space-x-1 px-2 py-1 rounded-lg text-[11px] font-semibold transition border bg-rose-500/15 hover:bg-rose-500/25 text-rose-500 border-rose-500/30"
                          >
                            <Power className="w-3 h-3" />
                            <span>Disconnect</span>
                          </button>
                        )}
                        {isAdmin && conn.config?.configured && (
                          <button
                            type="button"
                            onClick={() => deleteConnectorData(conn.id)}
                            title="Delete encrypted credentials & sync history"
                            className="flex items-center space-x-1 px-2 py-1 rounded-lg text-[11px] font-semibold transition border bg-rose-500/10 hover:bg-rose-500/20 text-rose-400 border-rose-500/30"
                          >
                            <Trash2 className="w-3 h-3" />
                            <span>Purge</span>
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </>
        )}

        {/* View 2: Integration Dependency Map */}
        {viewMode === 'dependencies' && (
          <div className="space-y-3">
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Architectural wiring between external providers, internal Event Bus topics, security engines, and deterministic fallback modes.
            </p>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {dependencyMap.map((spec) => (
                <div
                  key={spec.providerKey}
                  className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-2.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-bold text-slate-900 dark:text-white">{spec.displayName}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-500/15 text-cyan-500 border border-cyan-500/30">
                      {spec.category} • {spec.dataDirection}
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-600 dark:text-slate-300">
                    <strong>Connected Modules:</strong> {spec.connectedModules.join(', ')}
                  </div>
                  <div className="text-[11px] font-mono text-emerald-600 dark:text-emerald-400">
                    <strong>Emits:</strong> {spec.emitsEvents.length > 0 ? spec.emitsEvents.join(', ') : 'None (sink)'}
                  </div>
                  <div className="text-[11px] font-mono text-indigo-500 dark:text-indigo-300">
                    <strong>Consumes:</strong>{' '}
                    {spec.consumesEvents.length > 0 ? spec.consumesEvents.join(', ') : 'Inbound collector only'}
                  </div>
                  <div className="text-[11px] text-slate-500 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-2">
                    <strong>Fallback:</strong> {spec.fallbackMode}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* View 3: SIEM Export & Enterprise SSO / SCIM 2.0 */}
        {viewMode === 'siem_sso' && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* SIEM Exporter */}
            <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Send className="w-4 h-4 text-cyan-500" />
                  <span>SIEM Security Event Forwarder</span>
                </h3>
                <span className="text-[10px] font-mono text-slate-500">Splunk / Elastic / Sentinel</span>
              </div>
              <div className="flex items-center gap-2">
                <select
                  value={siemDest}
                  onChange={(e) => setSiemDest(e.target.value as 'splunk' | 'elastic' | 'sentinel' | 'webhook')}
                  className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono"
                >
                  <option value="splunk">Splunk HEC</option>
                  <option value="elastic">Elastic Security</option>
                  <option value="sentinel">Microsoft Sentinel</option>
                  <option value="webhook">Slack / Webhook</option>
                </select>
                {canRunTools && (
                  <button
                    type="button"
                    onClick={() =>
                      exportToSiem({
                        destination: siemDest,
                        resourceType: 'SecurityPostureDigest',
                        resourceId: `digest-${Date.now()}`,
                        eventData: { summary: 'Manual SIEM security posture export', timestamp: new Date().toISOString() },
                      })
                    }
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
                  >
                    Dispatch SIEM Event
                  </button>
                )}
              </div>
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {siemExports.length === 0 ? (
                  <p className="text-xs text-slate-500">No SIEM exports recorded yet.</p>
                ) : (
                  siemExports.map((exp) => (
                    <div
                      key={exp.id}
                      className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-2.5 text-xs font-mono flex items-center justify-between gap-2"
                    >
                      <div className="min-w-0">
                        <div className="font-bold text-slate-900 dark:text-white truncate">
                          {exp.destination.toUpperCase()} • {exp.resourceType}
                        </div>
                        <div className="text-[11px] text-slate-500 truncate">
                          corr={exp.correlationId} {exp.errorMessage ? `• ${exp.errorMessage}` : ''}
                        </div>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] shrink-0 ${
                          exp.status === 'Delivered'
                            ? 'bg-emerald-500/15 text-emerald-500'
                            : exp.status === 'Queued'
                            ? 'bg-amber-500/15 text-amber-500'
                            : 'bg-rose-500/15 text-rose-500'
                        }`}
                      >
                        {exp.status}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Enterprise SSO & SCIM 2.0 */}
            <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <KeyRound className="w-4 h-4 text-emerald-500" />
                  <span>Enterprise SSO (OIDC/SAML) &amp; SCIM 2.0</span>
                </h3>
                <span className="text-[10px] font-mono text-emerald-500">
                  {ssoConfig?.enabled ? `${ssoConfig.provider.toUpperCase()} ACTIVE` : 'CONFIGURABLE'}
                </span>
              </div>

              {isAdmin && (
                <form
                  onSubmit={async (e) => {
                    e.preventDefault();
                    await configureSso({
                      provider: ssoProvider,
                      issuerUrl: ssoIssuer.trim() || undefined,
                      clientId: ssoClientIdInput.trim() || undefined,
                      domainHint: ssoDomainHint.trim() || undefined,
                      enabled: true,
                    });
                  }}
                  className="space-y-2.5"
                >
                  <div className="grid grid-cols-2 gap-2">
                    <select
                      value={ssoProvider}
                      onChange={(e) => setSsoProvider(e.target.value as 'oidc' | 'saml' | 'okta' | 'entra')}
                      className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                    >
                      <option value="oidc">OIDC</option>
                      <option value="okta">Okta</option>
                      <option value="entra">Microsoft Entra ID</option>
                      <option value="saml">SAML 2.0</option>
                    </select>
                    <input
                      type="text"
                      value={ssoDomainHint}
                      onChange={(e) => setSsoDomainHint(e.target.value)}
                      placeholder="Domain hint (acme.cloud)"
                      className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                    />
                  </div>
                  <input
                    type="url"
                    value={ssoIssuer}
                    onChange={(e) => setSsoIssuer(e.target.value)}
                    placeholder="Issuer URL (https://dev-123.okta.com/oauth2/default)"
                    className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                  />
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={ssoClientIdInput}
                      onChange={(e) => setSsoClientIdInput(e.target.value)}
                      placeholder="Client ID"
                      className="flex-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                    />
                    <button
                      type="submit"
                      className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold"
                    >
                      Save SSO
                    </button>
                  </div>
                </form>
              )}

              <div className="pt-3 border-t border-slate-200 dark:border-slate-800 space-y-2.5">
                <div className="text-xs font-bold text-slate-900 dark:text-white">
                  SCIM 2.0 Directory Provisioning (`/api/v1/scim/v2/Users`)
                </div>
                {isAdmin && (
                  <div className="flex gap-2">
                    <input
                      type="text"
                      value={scimTokenName}
                      onChange={(e) => setScimTokenName(e.target.value)}
                      placeholder="SCIM Token Name"
                      className="flex-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs"
                    />
                    <button
                      type="button"
                      onClick={async () => {
                        const res = await issueScimToken(scimTokenName.trim() || 'SCIM Client');
                        if (res) setNewScimSecret(res.secret);
                      }}
                      className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold whitespace-nowrap"
                    >
                      Issue SCIM Token
                    </button>
                  </div>
                )}
                {newScimSecret && (
                  <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-[11px] font-mono text-emerald-500 break-all">
                    Copy SCIM Token once: {newScimSecret}
                  </div>
                )}
                <div className="space-y-1.5 max-h-36 overflow-y-auto">
                  {scimTokens.map((t) => (
                    <div
                      key={t.id}
                      className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono flex items-center justify-between"
                    >
                      <span>
                        {t.name} ({t.tokenPrefix}...) {t.revoked ? '• REVOKED' : ''}
                      </span>
                      {isAdmin && !t.revoked && (
                        <button
                          type="button"
                          onClick={() => revokeScimToken(t.id)}
                          className="text-rose-500 hover:underline text-[11px]"
                        >
                          Revoke
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
