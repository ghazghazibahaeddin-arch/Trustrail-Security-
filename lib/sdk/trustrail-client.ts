export interface TrustrailClientOptions {
  baseUrl: string;
  token?: string;
  timeoutMs?: number;
}

export class TrustrailApiError extends Error {
  status: number;
  code: string;
  details?: unknown;

  constructor(message: string, status: number, code: string, details?: unknown) {
    super(message);
    this.name = 'TrustrailApiError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export class TrustrailClient {
  private baseUrl: string;
  private token?: string;
  private timeoutMs: number;

  constructor(options: TrustrailClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/+$/, '');
    this.token = options.token;
    this.timeoutMs = options.timeoutMs ?? 15_000;
  }

  setToken(token: string) {
    this.token = token;
  }

  private async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...(init.headers as Record<string, string> | undefined),
      };
      if (this.token) {
        headers.Authorization = `Bearer ${this.token}`;
      }

      const res = await fetch(`${this.baseUrl}${path}`, {
        ...init,
        headers,
        signal: controller.signal,
      });

      const data = (await res.json()) as Record<string, unknown>;
      if (!res.ok) {
        throw new TrustrailApiError(
          String(data.error || `HTTP ${res.status}`),
          res.status,
          String(data.code || 'API_ERROR'),
          data.details
        );
      }
      return data as T;
    } finally {
      clearTimeout(timer);
    }
  }

  async health() {
    return this.request<Record<string, unknown>>('/api/health');
  }

  async login(email: string, password: string, orgId?: string) {
    const res = await this.request<{ token: string; user: Record<string, unknown>; organization: Record<string, unknown> }>(
      '/api/v1/auth/login',
      {
        method: 'POST',
        body: JSON.stringify({ email, password, orgId }),
      }
    );
    this.token = res.token;
    return res;
  }

  async listProjects() {
    return this.request<{ projects: Array<Record<string, unknown>> }>('/api/v1/projects');
  }

  async runScan(payload: {
    projectId?: string;
    projectName?: string;
    codeContent?: string;
    filePath?: string;
    packageJsonContent?: string;
    terraformContent?: string;
    dockerfileContent?: string;
  }) {
    return this.request<Record<string, unknown>>('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async listFindings(params?: { severity?: string; status?: string; q?: string }) {
    const qs = new URLSearchParams();
    if (params?.severity) qs.set('severity', params.severity);
    if (params?.status) qs.set('status', params.status);
    if (params?.q) qs.set('q', params.q);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return this.request<{ findings: Array<Record<string, unknown>>; total: number }>(`/api/v1/findings${suffix}`);
  }

  async resolveFinding(findingId: string, resolutionEvidence: string) {
    return this.request<Record<string, unknown>>(`/api/v1/findings/${encodeURIComponent(findingId)}`, {
      method: 'PATCH',
      body: JSON.stringify({ status: 'Resolved', resolutionEvidence }),
    });
  }

  async getGraph() {
    return this.request<{ nodes: unknown[]; edges: unknown[]; attackPaths: unknown[] }>('/api/v1/graph');
  }

  async evaluatePolicy(payload: Record<string, unknown>) {
    return this.request<{ decision: string; allowed: boolean; violatedRules: unknown[] }>('/api/v1/policies/evaluate', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async issueTrustPassport(title: string, scope: string[], expiresDays = 180) {
    return this.request<Record<string, unknown>>('/api/v1/trust-center', {
      method: 'POST',
      body: JSON.stringify({ title, scope, expiresDays }),
    });
  }

  async verifyAuditChain() {
    return this.request<{ chainVerified: boolean; totalEntries: number; logs: unknown[] }>('/api/v1/audit-logs');
  }

  async listApiKeys() {
    return this.request<{ apiKeys: Array<Record<string, unknown>> }>('/api/v1/api-keys');
  }

  async createApiKey(name: string, role: 'Owner' | 'Admin' | 'Developer' | 'Viewer' = 'Developer') {
    return this.request<{ apiKey: Record<string, unknown>; secret: string }>('/api/v1/api-keys', {
      method: 'POST',
      body: JSON.stringify({ name, role }),
    });
  }

  async revokeApiKey(id: string) {
    return this.request<{ id: string; revoked: boolean }>(`/api/v1/api-keys/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  async scanGithubRepo(repo: string, branch?: string) {
    return this.request<Record<string, unknown>>('/api/v1/integrations/github/scan-repo', {
      method: 'POST',
      body: JSON.stringify({ repo, branch }),
    });
  }

  async queryOsv(payload: {
    projectId?: string;
    packages?: Array<{ ecosystem: 'npm' | 'PyPI' | 'Go' | 'Maven'; name: string; version: string }>;
  }) {
    return this.request<Record<string, unknown>>('/api/v1/integrations/osv/query', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async probeHttpEndpoint(targetUrl: string, projectId?: string) {
    return this.request<Record<string, unknown>>('/api/v1/integrations/http-probe', {
      method: 'POST',
      body: JSON.stringify({ targetUrl, projectId }),
    });
  }

  async configureConnector(id: string, payload: Record<string, unknown>) {
    return this.request<Record<string, unknown>>(`/api/v1/connectors/${encodeURIComponent(id)}/configure`, {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async rotateApiKey(id: string) {
    return this.request<{ apiKey: Record<string, unknown>; secret: string; rotatedFromId: string }>(
      `/api/v1/api-keys/${encodeURIComponent(id)}/rotate`,
      { method: 'POST' }
    );
  }

  async getProjectSbom(projectId: string, format: 'cyclonedx' | 'spdx' = 'cyclonedx', validate = true) {
    return this.request<Record<string, unknown>>(
      `/api/v1/projects/${encodeURIComponent(projectId)}/sbom?format=${format}&validate=${validate}`
    );
  }

  async startRemediation(findingId: string, patchDiff?: string) {
    return this.request<{ run: Record<string, unknown> }>('/api/v1/remediation', {
      method: 'POST',
      body: JSON.stringify({ findingId, patchDiff }),
    });
  }

  async getCloudResources() {
    return this.request<{ resources: Array<Record<string, unknown>> }>('/api/v1/cloud/resources');
  }

  async getSystemMetrics() {
    return this.request<Record<string, unknown>>('/api/v1/system/metrics');
  }

  async getSecurityPosture() {
    return this.request<{ organization: Record<string, unknown> }>('/api/v1/organizations');
  }

  async listFabricEvents(params?: { status?: string; eventType?: string; limit?: number }) {
    const qs = new URLSearchParams();
    if (params?.status) qs.set('status', params.status);
    if (params?.eventType) qs.set('eventType', params.eventType);
    if (params?.limit) qs.set('limit', String(params.limit));
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    return this.request<{ events: Array<Record<string, unknown>>; statusCounts: Record<string, number> }>(
      `/api/v1/fabric/events${suffix}`
    );
  }

  async replayFabricEvent(eventId: string, simulateFailure = false) {
    return this.request<Record<string, unknown>>('/api/v1/fabric/events', {
      method: 'POST',
      body: JSON.stringify({ action: 'replay', eventId, simulateFailure }),
    });
  }

  async queryVulnerabilityIntel(payload: {
    cveIds?: string[];
    packages?: Array<{ ecosystem: 'npm' | 'PyPI' | 'Go' | 'Maven'; name: string; version: string }>;
    forceRefresh?: boolean;
  }) {
    return this.request<Record<string, unknown>>('/api/v1/intel/query', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async analyzeKubernetes(payload: { clusterName?: string; manifestYaml?: string }) {
    return this.request<Record<string, unknown>>('/api/v1/integrations/kubernetes/analyze', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async ingestRuntimeEvent(payload: {
    source: 'otel' | 'kubernetes_audit' | 'falco' | 'cloudtrail' | 'custom';
    severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
    eventType: string;
    actor: string;
    resource: string;
    summary: string;
    raw?: Record<string, unknown>;
  }) {
    return this.request<Record<string, unknown>>('/api/v1/events/ingest', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async syncConnector(id: string, mode: 'initial' | 'incremental' | 'manual' = 'manual') {
    return this.request<Record<string, unknown>>(`/api/v1/connectors/${encodeURIComponent(id)}/sync`, {
      method: 'POST',
      body: JSON.stringify({ mode }),
    });
  }

  async deleteConnector(id: string) {
    return this.request<Record<string, unknown>>(`/api/v1/connectors/${encodeURIComponent(id)}`, {
      method: 'DELETE',
    });
  }

  async listRunners() {
    return this.request<{ runners: Array<Record<string, unknown>>; jobs: Array<Record<string, unknown>>; ciSnippets: Record<string, string> }>(
      '/api/v1/runner'
    );
  }

  async createRunner(name: string, mode: 'scan' | 'cicd' | 'runtime_collector' = 'cicd', environment = 'production') {
    return this.request<{ runner: Record<string, unknown>; enrollmentToken: string }>('/api/v1/runner', {
      method: 'POST',
      body: JSON.stringify({ action: 'create_runner', name, mode, environment }),
    });
  }

  async exportSiem(payload: {
    destination: 'splunk' | 'elastic' | 'sentinel' | 'webhook';
    resourceType: string;
    resourceId: string;
    eventData: Record<string, unknown>;
  }) {
    return this.request<Record<string, unknown>>('/api/v1/siem/export', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  }

  async getSsoConfig() {
    return this.request<Record<string, unknown>>('/api/v1/sso');
  }
}

