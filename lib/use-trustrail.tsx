'use client';

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import {
  AuthUser,
  MembershipSummary,
  Organization,
  Project,
  SecurityFinding,
  GraphNode,
  GraphEdge,
  AttackPath,
  ChangeContract,
  PolicyItem,
  AIAgentAsset,
  Incident,
  CanaryItem,
  ComplianceControl,
  Connector,
  ApiKeyItem,
  TrustReceiptItem,
  TeamMember,
  AuditLogItem,
  RemediationRun,
  RecoveryBackup,
  CloudResource,
  BackgroundJob,
  SystemMetrics,
  EnforcementMode,
  Edition,
  Role,
  EMPTY_ORGANIZATION,
} from './trustrail-store';

export type NavTab =
  | 'overview'
  | 'graph'
  | 'attack-paths'
  | 'projects'
  | 'vulnerabilities'
  | 'supply-chain'
  | 'cicd'
  | 'cloud'
  | 'identity'
  | 'api'
  | 'ai-agents'
  | 'change-integrity'
  | 'policies'
  | 'remediation'
  | 'runtime'
  | 'incidents'
  | 'recovery'
  | 'deception'
  | 'compliance'
  | 'trust-center'
  | 'integrations'
  | 'team'
  | 'billing'
  | 'settings';

export interface ScanPayloadInput {
  projectId?: string;
  projectName?: string;
  codeContent?: string;
  filePath?: string;
  packageJsonContent?: string;
  packageLockContent?: string;
  requirementsTxtContent?: string;
  goModContent?: string;
  pomXmlContent?: string;
  githubWorkflowContent?: string;
  terraformContent?: string;
  dockerfileContent?: string;
}

export interface ApiError extends Error {
  code?: string;
  status?: number;
  details?: Record<string, unknown>;
}

interface ActionNotice {
  type: 'success' | 'error';
  message: string;
}

interface TrustrailContextType {
  isLoadingSession: boolean;
  isLoadingData: boolean;
  user: AuthUser | null;
  memberships: MembershipSummary[];
  activeTab: NavTab;
  setActiveTab: (tab: NavTab) => void;
  theme: 'dark' | 'light';
  toggleTheme: () => void;
  globalSearch: string;
  setGlobalSearch: (q: string) => void;
  notice: ActionNotice | null;
  clearNotice: () => void;

  org: Organization;
  projects: Project[];
  findings: SecurityFinding[];
  graphNodes: GraphNode[];
  graphEdges: GraphEdge[];
  attackPaths: AttackPath[];
  changeContracts: ChangeContract[];
  policies: PolicyItem[];
  aiAgents: AIAgentAsset[];
  incidents: Incident[];
  canaries: CanaryItem[];
  complianceControls: ComplianceControl[];
  connectors: Connector[];
  apiKeys: ApiKeyItem[];
  trustReceipts: TrustReceiptItem[];
  teamMembers: TeamMember[];
  auditLogs: AuditLogItem[];
  auditChainVerified: boolean;
  remediationRuns: RemediationRun[];
  recoveryBackups: RecoveryBackup[];
  cloudResources: CloudResource[];
  backgroundJobs: BackgroundJob[];
  systemMetrics: SystemMetrics | null;

  isScanning: boolean;
  scanProgress: string;

  // Auth Actions
  login: (email: string, password: string, orgId?: string, mfaCode?: string) => Promise<void>;
  register: (payload: {
    email: string;
    name: string;
    password: string;
    organizationName: string;
    edition: Edition;
  }) => Promise<{ emailVerificationRequired?: boolean; verificationTokenPreview?: string }>;
  logout: () => Promise<void>;
  refreshSessionToken: () => Promise<void>;
  updateProfile: (payload: { name?: string; currentPassword?: string; newPassword?: string }) => Promise<boolean>;
  setupMfa: () => Promise<{ secret: string; otpauthUri: string } | null>;
  verifyMfa: (code: string) => Promise<boolean>;
  disableMfa: () => Promise<boolean>;
  verifyEmail: (payload: { token?: string; resend?: boolean }) => Promise<{ verified?: boolean; verificationTokenPreview?: string } | null>;
  forgotPassword: (email: string) => Promise<{ message: string; resetTokenPreview?: string }>;
  resetPassword: (token: string, newPassword: string) => Promise<boolean>;
  switchOrganization: (orgId: string) => Promise<void>;
  refreshAll: () => Promise<void>;

  // Core Actions
  runScan: (input?: ScanPayloadInput) => Promise<Record<string, unknown> | null>;
  createProject: (payload: {
    name: string;
    repoUrl: string;
    branch: string;
    language: string;
    framework: string;
  }) => Promise<void>;
  resolveFinding: (findingId: string, resolutionEvidence?: string, status?: SecurityFinding['status']) => Promise<void>;
  startRemediation: (findingId: string, patchDiff?: string, verificationCommand?: string) => Promise<RemediationRun | null>;
  progressRemediation: (
    runId: string,
    action: 'run_verification' | 'rescan_and_resolve',
    patchedCodeSample?: string
  ) => Promise<RemediationRun | null>;
  mitigateAttackPath: (pathId: string) => Promise<void>;
  createChangeContract: (payload: {
    title: string;
    project: string;
    targetAsset: string;
    purpose: string;
    newStatePayload: Record<string, unknown>;
    riskLevel: 'High' | 'Medium' | 'Low';
  }) => Promise<void>;
  tamperChangeContract: (contractId: string, newStatePayload: Record<string, unknown>) => Promise<void>;
  approveChange: (contractId: string) => Promise<void>;
  revokeApproval: (contractId: string) => Promise<void>;
  executeChange: (contractId: string) => Promise<void>;
  createPolicy: (payload: {
    name: string;
    engine: PolicyItem['engine'];
    severity: PolicyItem['severity'];
    ruleCode: string;
  }) => Promise<void>;
  togglePolicy: (id: string, status: PolicyItem['status']) => Promise<void>;
  evaluatePolicy: (payload: Record<string, unknown>) => Promise<{ decision: string; allowed: boolean; violatedRules: Array<{ ruleName: string; reason: string; remediation: string }> } | null>;
  executeAgentTool: (agentId: string, toolName: string) => Promise<{ allowed: boolean; message: string }>;
  revokeAgent: (agentId: string, status: 'Active' | 'Quarantine' | 'Revoked') => Promise<void>;
  createIncident: (title: string, severity: 'SEV-1' | 'SEV-2' | 'SEV-3', affectedAsset: string) => Promise<void>;
  updateIncident: (id: string, payload: { status?: Incident['status']; appendAction?: string }) => Promise<void>;
  createBackupSnapshot: (targetName: string, backupType?: 'Full Snapshot' | 'Incremental WAL' | 'Config & Keys') => Promise<void>;
  verifyBackupRestore: (backupId: string) => Promise<void>;
  deployCanary: (type: 'Canary Token URL' | 'Honey API Key' | 'Decoy Database User' | 'Honeypot Endpoint', location: string) => Promise<void>;
  triggerCanary: (canaryId: string) => Promise<void>;
  updateComplianceControl: (id: string, status: ComplianceControl['status']) => Promise<void>;
  issueTrustPassport: (title: string, scope: string[], expiresDays?: number) => Promise<void>;
  revokeTrustPassport: (id: string) => Promise<void>;
  testConnector: (id: string) => Promise<void>;
  configureConnector: (
    id: string,
    payload: {
      githubToken?: string;
      defaultRepo?: string;
      webhookUrl?: string;
      awsRoleArn?: string;
      awsExternalId?: string;
      awsAccessKeyId?: string;
      awsSecretAccessKey?: string;
      awsRegion?: string;
      azureTenantId?: string;
      azureSubscriptionId?: string;
      gcpProjectId?: string;
      verifyNow?: boolean;
    }
  ) => Promise<boolean>;
  disconnectConnector: (id: string) => Promise<void>;
  rotateVaultSecrets: () => Promise<void>;
  evaluateCloudPosture: (payload: {
    provider: 'aws' | 'azure' | 'gcp';
    accountId: string;
    region: string;
    resources?: Array<{
      resourceType: string;
      resourceArn: string;
      exposure: 'Public' | 'Internal' | 'Private';
      publicAccessBlock?: boolean;
      encryptionEnabled?: boolean;
      openPorts?: number[];
      wildcardPermissions?: boolean;
    }>;
  }) => Promise<void>;
  inspectOciImage: (image: string, dockerfileContent?: string) => Promise<Record<string, unknown> | null>;
  fetchProjectSbom: (projectId: string, format: 'cyclonedx' | 'spdx') => Promise<Record<string, unknown> | null>;
  verifySlsaAttestation: (
    projectId: string,
    payload: { expectedDigestSha256: string; artifactContent?: string; hmacSignature?: string; signingSecret?: string }
  ) => Promise<Record<string, unknown> | null>;
  createApiKey: (
    name: string,
    role: Role,
    scopes?: string[],
    expiresInDays?: number
  ) => Promise<{ apiKey: ApiKeyItem; secret: string } | null>;
  rotateApiKey: (id: string) => Promise<{ apiKey: ApiKeyItem; secret: string } | null>;
  revokeApiKey: (id: string) => Promise<void>;
  scanGithubRepo: (repo: string, branch?: string) => Promise<Record<string, unknown> | null>;
  queryOsv: (payload: {
    projectId?: string;
    packages?: Array<{ ecosystem: 'npm' | 'PyPI' | 'Go' | 'Maven'; name: string; version: string }>;
  }) => Promise<Record<string, unknown> | null>;
  probeHttpEndpoint: (targetUrl: string, projectId?: string) => Promise<Record<string, unknown> | null>;
  dispatchTestWebhook: () => Promise<void>;
  enqueueBackgroundJob: (jobType: string, payload?: Record<string, unknown>, simulateFailure?: boolean) => Promise<void>;
  retryBackgroundJob: (jobId: string, simulateFailure?: boolean) => Promise<void>;
  inviteMember: (payload: { email: string; name: string; role: Role; title: string }) => Promise<void>;
  updateMemberRole: (membershipId: string, role: Role) => Promise<void>;
  updateMemberStatus: (membershipId: string, userStatus: 'Active' | 'Disabled') => Promise<void>;
  updateOrgSettings: (payload: {
    name?: string;
    edition?: Edition;
    dataRetentionDays?: number;
    threatSharingOptIn?: boolean;
    enforcementMode?: EnforcementMode;
  }) => Promise<void>;
}

const TrustrailContext = createContext<TrustrailContextType | undefined>(undefined);

async function apiFetch<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...init,
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(init?.headers || {}),
    },
  });
  const data = (await res.json()) as Record<string, unknown>;
  if (!res.ok) {
    const err = new Error(String(data.error || `Request failed (${res.status})`)) as ApiError;
    if (typeof data.code === 'string') err.code = data.code;
    err.status = res.status;
    err.details = data;
    throw err;
  }
  return data as T;
}

export function TrustrailProvider({ children }: { children: React.ReactNode }) {
  const [isLoadingSession, setIsLoadingSession] = useState(true);
  const [isLoadingData, setIsLoadingData] = useState(false);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [memberships, setMemberships] = useState<MembershipSummary[]>([]);
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [globalSearch, setGlobalSearch] = useState('');
  const [notice, setNotice] = useState<ActionNotice | null>(null);

  const [org, setOrg] = useState<Organization>(EMPTY_ORGANIZATION);
  const [projects, setProjects] = useState<Project[]>([]);
  const [findings, setFindings] = useState<SecurityFinding[]>([]);
  const [graphNodes, setGraphNodes] = useState<GraphNode[]>([]);
  const [graphEdges, setGraphEdges] = useState<GraphEdge[]>([]);
  const [attackPaths, setAttackPaths] = useState<AttackPath[]>([]);
  const [changeContracts, setChangeContracts] = useState<ChangeContract[]>([]);
  const [policies, setPolicies] = useState<PolicyItem[]>([]);
  const [aiAgents, setAiAgents] = useState<AIAgentAsset[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [canaries, setCanaries] = useState<CanaryItem[]>([]);
  const [complianceControls, setComplianceControls] = useState<ComplianceControl[]>([]);
  const [connectors, setConnectors] = useState<Connector[]>([]);
  const [apiKeys, setApiKeys] = useState<ApiKeyItem[]>([]);
  const [trustReceipts, setTrustReceipts] = useState<TrustReceiptItem[]>([]);
  const [teamMembers, setTeamMembers] = useState<TeamMember[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditLogItem[]>([]);
  const [auditChainVerified, setAuditChainVerified] = useState(true);
  const [remediationRuns, setRemediationRuns] = useState<RemediationRun[]>([]);
  const [recoveryBackups, setRecoveryBackups] = useState<RecoveryBackup[]>([]);
  const [cloudResources, setCloudResources] = useState<CloudResource[]>([]);
  const [backgroundJobs, setBackgroundJobs] = useState<BackgroundJob[]>([]);
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics | null>(null);

  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState('');

  const showNotice = useCallback((type: 'success' | 'error', message: string) => {
    setNotice({ type, message });
  }, []);

  const clearNotice = useCallback(() => setNotice(null), []);

  const toggleTheme = useCallback(() => {
    setTheme((prev) => {
      const next = prev === 'dark' ? 'light' : 'dark';
      if (typeof document !== 'undefined') {
        document.documentElement.classList.toggle('dark', next === 'dark');
      }
      return next;
    });
  }, []);

  const refreshAll = useCallback(async () => {
    setIsLoadingData(true);
    try {
      const [
        orgRes,
        projRes,
        findRes,
        graphRes,
        chgRes,
        polRes,
        agRes,
        incRes,
        canRes,
        compRes,
        connRes,
        trRes,
        teamRes,
        auditRes,
        keysRes,
        remRes,
        bkpRes,
        cloudRes,
        jobsRes,
        metricsRes,
      ] = await Promise.all([
        apiFetch<{ organization: Organization }>('/api/v1/organizations'),
        apiFetch<{ projects: Project[] }>('/api/v1/projects'),
        apiFetch<{ findings: SecurityFinding[] }>('/api/v1/findings'),
        apiFetch<{ nodes: GraphNode[]; edges: GraphEdge[]; attackPaths: AttackPath[] }>('/api/v1/graph'),
        apiFetch<{ changes: ChangeContract[] }>('/api/v1/changes'),
        apiFetch<{ policies: PolicyItem[] }>('/api/v1/policies'),
        apiFetch<{ aiAgents: AIAgentAsset[] }>('/api/v1/ai-agents'),
        apiFetch<{ incidents: Incident[] }>('/api/v1/incidents'),
        apiFetch<{ canaries: CanaryItem[] }>('/api/v1/deception'),
        apiFetch<{ controls: ComplianceControl[] }>('/api/v1/compliance'),
        apiFetch<{ connectors: Connector[] }>('/api/v1/connectors'),
        apiFetch<{ trustReceipts: TrustReceiptItem[] }>('/api/v1/trust-center'),
        apiFetch<{ members: TeamMember[] }>('/api/v1/team'),
        apiFetch<{ chainVerified: boolean; logs: AuditLogItem[] }>('/api/v1/audit-logs?limit=50'),
        apiFetch<{ apiKeys: ApiKeyItem[] }>('/api/v1/api-keys').catch(() => ({ apiKeys: [] })),
        apiFetch<{ runs: RemediationRun[] }>('/api/v1/remediation').catch(() => ({ runs: [] })),
        apiFetch<{ backups: RecoveryBackup[] }>('/api/v1/recovery/backups').catch(() => ({ backups: [] })),
        apiFetch<{ resources: CloudResource[] }>('/api/v1/cloud/resources').catch(() => ({ resources: [] })),
        apiFetch<{ jobs: BackgroundJob[] }>('/api/v1/jobs').catch(() => ({ jobs: [] })),
        apiFetch<SystemMetrics>('/api/v1/system/metrics').catch(() => null),
      ]);

      setOrg(orgRes.organization);
      setProjects(projRes.projects);
      setFindings(findRes.findings);
      setGraphNodes(graphRes.nodes);
      setGraphEdges(graphRes.edges);
      setAttackPaths(graphRes.attackPaths);
      setChangeContracts(chgRes.changes);
      setPolicies(polRes.policies);
      setAiAgents(agRes.aiAgents);
      setIncidents(incRes.incidents);
      setCanaries(canRes.canaries);
      setComplianceControls(compRes.controls);
      setConnectors(connRes.connectors);
      setApiKeys(keysRes.apiKeys);
      setTrustReceipts(trRes.trustReceipts);
      setTeamMembers(teamRes.members);
      setAuditLogs(auditRes.logs);
      setAuditChainVerified(auditRes.chainVerified);
      setRemediationRuns(remRes.runs);
      setRecoveryBackups(bkpRes.backups);
      setCloudResources(cloudRes.resources);
      setBackgroundJobs(jobsRes.jobs);
      setSystemMetrics(metricsRes);
    } catch (err) {
      showNotice('error', (err as Error).message);
    } finally {
      setIsLoadingData(false);
    }
  }, [showNotice]);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const sess = await apiFetch<{
          authenticated: boolean;
          user: AuthUser | null;
          organization: Organization | null;
          memberships: MembershipSummary[];
        }>('/api/v1/auth/session');
        if (!active) return;
        if (sess.authenticated && sess.user) {
          setUser(sess.user);
          setMemberships(sess.memberships);
          if (sess.organization) setOrg(sess.organization);
          await refreshAll();
        }
      } catch {
        // Ignore initial unauthenticated state
      } finally {
        if (active) setIsLoadingSession(false);
      }
    })();
    return () => {
      active = false;
    };
  }, [refreshAll]);

  const login = async (email: string, password: string, orgId?: string, mfaCode?: string) => {
    const res = await apiFetch<{
      user: AuthUser;
      organization: Organization;
      memberships: MembershipSummary[];
    }>('/api/v1/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, orgId, ...(mfaCode ? { mfaCode } : {}) }),
    });
    setUser(res.user);
    setOrg(res.organization);
    setMemberships(res.memberships);
    await refreshAll();
    showNotice('success', `Signed in to ${res.organization.name} as ${res.user.role}.`);
  };

  const register = async (payload: {
    email: string;
    name: string;
    password: string;
    organizationName: string;
    edition: Edition;
  }) => {
    const res = await apiFetch<{
      user: AuthUser;
      organization: Organization;
      memberships: MembershipSummary[];
      emailVerificationRequired?: boolean;
      verificationTokenPreview?: string;
    }>('/api/v1/auth/register', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    setUser(res.user);
    setOrg(res.organization);
    setMemberships(res.memberships);
    await refreshAll();
    showNotice('success', `Workspace "${res.organization.name}" created.`);
    return {
      emailVerificationRequired: res.emailVerificationRequired,
      verificationTokenPreview: res.verificationTokenPreview,
    };
  };

  const logout = async () => {
    await apiFetch('/api/v1/auth/logout', { method: 'POST' });
    setUser(null);
    setMemberships([]);
    setOrg(EMPTY_ORGANIZATION);
    setProjects([]);
    setFindings([]);
    setAttackPaths([]);
  };

  const refreshSessionToken = async () => {
    try {
      await apiFetch('/api/v1/auth/refresh', { method: 'POST' });
      showNotice('success', 'Session token rotated and previous JWT ID revoked.');
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const updateProfile = async (payload: { name?: string; currentPassword?: string; newPassword?: string }) => {
    try {
      const res = await apiFetch<{ profile: { name: string; passwordChanged?: boolean } }>('/api/v1/auth/profile', {
        method: 'PATCH',
        body: JSON.stringify(payload),
      });
      setUser((prev) => (prev ? { ...prev, name: res.profile.name } : prev));
      await refreshAll();
      showNotice('success', res.profile.passwordChanged ? 'Password rotated and profile updated.' : 'Profile updated.');
      return true;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return false;
    }
  };

  const setupMfa = async () => {
    try {
      const res = await apiFetch<{ secret: string; otpauthUri: string }>('/api/v1/auth/mfa/setup', {
        method: 'POST',
      });
      showNotice('success', 'Generated AES-256-GCM encrypted TOTP MFA secret. Verify a 6-digit code to activate.');
      return { secret: res.secret, otpauthUri: res.otpauthUri };
    } catch (err) {
      showNotice('error', (err as Error).message);
      return null;
    }
  };

  const verifyMfa = async (code: string) => {
    try {
      await apiFetch('/api/v1/auth/mfa/verify', {
        method: 'POST',
        body: JSON.stringify({ code }),
      });
      setUser((prev) => (prev ? { ...prev, mfaVerified: true } : prev));
      await refreshAll();
      showNotice('success', 'Two-factor authentication (TOTP) verified and enforced on login.');
      return true;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return false;
    }
  };

  const disableMfa = async () => {
    try {
      await apiFetch('/api/v1/auth/mfa/verify', { method: 'DELETE' });
      setUser((prev) => (prev ? { ...prev, mfaVerified: false } : prev));
      await refreshAll();
      showNotice('success', 'Two-factor authentication disabled.');
      return true;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return false;
    }
  };

  const verifyEmail = async (payload: { token?: string; resend?: boolean }) => {
    try {
      const res = await apiFetch<{ verified?: boolean; verificationTokenPreview?: string }>(
        '/api/v1/auth/verify-email',
        { method: 'POST', body: JSON.stringify(payload) }
      );
      if (res.verified) {
        setUser((prev) => (prev ? { ...prev, emailVerified: true } : prev));
        showNotice('success', 'Email address cryptographically verified.');
      } else {
        showNotice('success', 'Issued fresh email verification token.');
      }
      return res;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return null;
    }
  };

  const forgotPassword = async (email: string) => {
    return apiFetch<{ message: string; resetTokenPreview?: string }>('/api/v1/auth/forgot-password', {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  };

  const resetPassword = async (token: string, newPassword: string) => {
    await apiFetch('/api/v1/auth/reset-password', {
      method: 'POST',
      body: JSON.stringify({ token, newPassword }),
    });
    return true;
  };

  const switchOrganization = async (orgId: string) => {
    const res = await apiFetch<{ user: AuthUser; organization: Organization }>('/api/v1/auth/switch-org', {
      method: 'POST',
      body: JSON.stringify({ orgId }),
    });
    setUser(res.user);
    setOrg(res.organization);
    await refreshAll();
    showNotice('success', `Switched workspace to ${res.organization.name}.`);
  };

  const runScan = async (input?: ScanPayloadInput) => {
    setIsScanning(true);
    setScanProgress('Executing SAST, Secret, SCA/SBOM, IaC & CI Workflow scanners...');
    try {
      const res = await apiFetch<Record<string, unknown>>('/api/v1/scans', {
        method: 'POST',
        body: JSON.stringify(input || {}),
      });
      await refreshAll();
      const scanInfo = res.scan as { findingsDetected?: number; scannersRun?: string[] } | undefined;
      showNotice(
        'success',
        `Scan completed (${scanInfo?.scannersRun?.join(', ') || 'Unified Sweep'}): ${scanInfo?.findingsDetected ?? 0} findings analyzed.`
      );
      return res;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return null;
    } finally {
      setIsScanning(false);
      setScanProgress('');
    }
  };

  const createProject = async (payload: {
    name: string;
    repoUrl: string;
    branch: string;
    language: string;
    framework: string;
  }) => {
    try {
      await apiFetch('/api/v1/projects', { method: 'POST', body: JSON.stringify(payload) });
      await refreshAll();
      showNotice('success', `Project "${payload.name}" added and registered in Security Graph.`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const resolveFinding = async (
    findingId: string,
    resolutionEvidence = 'Verified fixed and re-scanned in Trustrail',
    status: SecurityFinding['status'] = 'Resolved'
  ) => {
    try {
      await apiFetch(`/api/v1/findings/${encodeURIComponent(findingId)}`, {
        method: 'PATCH',
        body: JSON.stringify({ status, resolutionEvidence }),
      });
      await refreshAll();
      showNotice('success', `Finding updated to ${status}. Graph and Attack Paths recalculated.`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const startRemediation = async (findingId: string, patchDiff?: string, verificationCommand?: string) => {
    try {
      const res = await apiFetch<{ run: RemediationRun }>('/api/v1/remediation', {
        method: 'POST',
        body: JSON.stringify({ findingId, patchDiff, verificationCommand }),
      });
      await refreshAll();
      showNotice('success', 'Remediation patch run started. Execute verification tests before resolution.');
      return res.run;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return null;
    }
  };

  const progressRemediation = async (
    runId: string,
    action: 'run_verification' | 'rescan_and_resolve',
    patchedCodeSample?: string
  ) => {
    try {
      const res = await apiFetch<{ run: RemediationRun; resolved?: boolean }>('/api/v1/remediation', {
        method: 'PATCH',
        body: JSON.stringify({ runId, action, patchedCodeSample }),
      });
      await refreshAll();
      showNotice(
        'success',
        res.resolved
          ? 'Re-scan passed cleanly and finding closed with verified evidence!'
          : 'Pre-resolution verification tests passed. Ready for final re-scan closure.'
      );
      return res.run;
    } catch (err) {
      await refreshAll();
      showNotice('error', (err as Error).message);
      return null;
    }
  };

  const mitigateAttackPath = async (pathId: string) => {
    try {
      await apiFetch('/api/v1/attack-paths', {
        method: 'POST',
        body: JSON.stringify({ pathId, resolutionEvidence: 'Mitigated contributing entry vulnerability via Attack Path Center' }),
      });
      await refreshAll();
      showNotice('success', 'Attack path severed and verified.');
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const createChangeContract = async (payload: {
    title: string;
    project: string;
    targetAsset: string;
    purpose: string;
    newStatePayload: Record<string, unknown>;
    riskLevel: 'High' | 'Medium' | 'Low';
  }) => {
    try {
      await apiFetch('/api/v1/changes', { method: 'POST', body: JSON.stringify(payload) });
      await refreshAll();
      showNotice('success', 'IntentLock Change Contract created and hashed.');
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const tamperChangeContract = async (contractId: string, newStatePayload: Record<string, unknown>) => {
    try {
      const res = await apiFetch<{ verification: { status: string; reason: string } }>(
        `/api/v1/changes/${encodeURIComponent(contractId)}`,
        {
          method: 'PATCH',
          body: JSON.stringify({ newStatePayload }),
        }
      );
      await refreshAll();
      showNotice('error', `IntentLock Alert: ${res.verification.reason}`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const approveChange = async (contractId: string) => {
    try {
      await apiFetch(`/api/v1/changes/${encodeURIComponent(contractId)}/approve`, {
        method: 'POST',
        body: JSON.stringify({ action: 'approve' }),
      });
      await refreshAll();
      showNotice('success', 'Change Contract cryptographically approved under IntentLock.');
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const revokeApproval = async (contractId: string) => {
    try {
      await apiFetch(`/api/v1/changes/${encodeURIComponent(contractId)}/approve`, {
        method: 'POST',
        body: JSON.stringify({ action: 'revoke', reason: 'Manual security revocation' }),
      });
      await refreshAll();
      showNotice('success', 'IntentLock approval revoked.');
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const executeChange = async (contractId: string) => {
    try {
      await apiFetch(`/api/v1/changes/${encodeURIComponent(contractId)}/execute`, { method: 'POST' });
      await refreshAll();
      showNotice('success', 'Verified Change Contract executed cleanly.');
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const createPolicy = async (payload: {
    name: string;
    engine: PolicyItem['engine'];
    severity: PolicyItem['severity'];
    ruleCode: string;
  }) => {
    try {
      await apiFetch('/api/v1/policies', { method: 'POST', body: JSON.stringify(payload) });
      await refreshAll();
      showNotice('success', `Policy "${payload.name}" added.`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const togglePolicy = async (id: string, status: PolicyItem['status']) => {
    try {
      await apiFetch('/api/v1/policies', { method: 'PATCH', body: JSON.stringify({ id, status }) });
      await refreshAll();
      showNotice('success', `Policy enforcement changed to ${status}.`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const evaluatePolicy = async (payload: Record<string, unknown>) => {
    try {
      return await apiFetch<{ decision: string; allowed: boolean; violatedRules: Array<{ ruleName: string; reason: string; remediation: string }> }>(
        '/api/v1/policies/evaluate',
        { method: 'POST', body: JSON.stringify(payload) }
      );
    } catch (err) {
      showNotice('error', (err as Error).message);
      return null;
    }
  };

  const executeAgentTool = async (agentId: string, toolName: string) => {
    try {
      const res = await apiFetch<{ allowed: boolean; actionsUsed: number; actionLimit: number }>(
        `/api/v1/ai-agents/${encodeURIComponent(agentId)}/execute`,
        { method: 'POST', body: JSON.stringify({ toolName }) }
      );
      await refreshAll();
      const msg = `Allowed "${toolName}" (${res.actionsUsed}/${res.actionLimit} actions used).`;
      showNotice('success', msg);
      return { allowed: true, message: msg };
    } catch (err) {
      await refreshAll();
      const msg = (err as Error).message;
      showNotice('error', msg);
      return { allowed: false, message: msg };
    }
  };

  const revokeAgent = async (agentId: string, status: 'Active' | 'Quarantine' | 'Revoked') => {
    try {
      await apiFetch(`/api/v1/ai-agents/${encodeURIComponent(agentId)}/revoke`, {
        method: 'POST',
        body: JSON.stringify({ status }),
      });
      await refreshAll();
      showNotice('success', `AI Agent state updated to ${status}.`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const createIncident = async (title: string, severity: 'SEV-1' | 'SEV-2' | 'SEV-3', affectedAsset: string) => {
    try {
      await apiFetch('/api/v1/incidents', {
        method: 'POST',
        body: JSON.stringify({ title, severity, affectedAsset }),
      });
      await refreshAll();
      showNotice('success', `Incident "${title}" opened and logged.`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const updateIncident = async (id: string, payload: { status?: Incident['status']; appendAction?: string }) => {
    try {
      await apiFetch(`/api/v1/incidents/${encodeURIComponent(id)}`, {
        method: 'PATCH',
        body: JSON.stringify(payload),
      });
      await refreshAll();
      showNotice('success', 'Incident playbook updated.');
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const createBackupSnapshot = async (
    targetName: string,
    backupType: 'Full Snapshot' | 'Incremental WAL' | 'Config & Keys' = 'Full Snapshot'
  ) => {
    try {
      const res = await apiFetch<{ backupId: string }>('/api/v1/recovery/backups', {
        method: 'POST',
        body: JSON.stringify({ action: 'create_snapshot', targetName, backupType }),
      });
      await refreshAll();
      showNotice('success', `Created SHA-256 checksummed recovery snapshot ${res.backupId}.`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const verifyBackupRestore = async (backupId: string) => {
    try {
      await apiFetch('/api/v1/recovery/backups', {
        method: 'POST',
        body: JSON.stringify({ action: 'verify_restore', backupId }),
      });
      await refreshAll();
      showNotice('success', `Backup ${backupId} passed SHA-256 checksum & SQLite integrity check.`);
    } catch (err) {
      await refreshAll();
      showNotice('error', (err as Error).message);
    }
  };

  const deployCanary = async (
    type: 'Canary Token URL' | 'Honey API Key' | 'Decoy Database User' | 'Honeypot Endpoint',
    location: string
  ) => {
    try {
      await apiFetch('/api/v1/deception', { method: 'POST', body: JSON.stringify({ type, location }) });
      await refreshAll();
      showNotice('success', `Deployed ${type} canary.`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const triggerCanary = async (canaryId: string) => {
    try {
      await apiFetch('/api/v1/deception', { method: 'POST', body: JSON.stringify({ canaryId }) });
      await refreshAll();
      showNotice('error', 'Canary tripwire triggered and logged in audit trail!');
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const updateComplianceControl = async (id: string, status: ComplianceControl['status']) => {
    try {
      await apiFetch('/api/v1/compliance', { method: 'PATCH', body: JSON.stringify({ id, status }) });
      await refreshAll();
      showNotice('success', `Control marked ${status}.`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const issueTrustPassport = async (title: string, scope: string[], expiresDays = 180) => {
    try {
      await apiFetch('/api/v1/trust-center', {
        method: 'POST',
        body: JSON.stringify({ title, scope, expiresDays }),
      });
      await refreshAll();
      showNotice('success', `Issued Trust Passport "${title}".`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const revokeTrustPassport = async (id: string) => {
    try {
      await apiFetch(`/api/v1/trust-center/${encodeURIComponent(id)}/revoke`, { method: 'POST' });
      await refreshAll();
      showNotice('success', 'Trust Passport visibility updated.');
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const testConnector = async (id: string) => {
    try {
      const res = await apiFetch<{ message?: string }>(`/api/v1/connectors/${encodeURIComponent(id)}/test`, {
        method: 'POST',
      });
      await refreshAll();
      showNotice('success', res.message || 'Connector verified.');
    } catch (err) {
      await refreshAll();
      showNotice('error', (err as Error).message);
    }
  };

  const configureConnector = async (
    id: string,
    payload: {
      githubToken?: string;
      defaultRepo?: string;
      webhookUrl?: string;
      awsRoleArn?: string;
      awsExternalId?: string;
      awsAccessKeyId?: string;
      awsSecretAccessKey?: string;
      awsRegion?: string;
      azureTenantId?: string;
      azureSubscriptionId?: string;
      gcpProjectId?: string;
      verifyNow?: boolean;
    }
  ) => {
    try {
      const res = await apiFetch<{ message?: string }>(`/api/v1/connectors/${encodeURIComponent(id)}/configure`, {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      await refreshAll();
      showNotice('success', res.message || 'Connector configuration encrypted and verified.');
      return true;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return false;
    }
  };

  const disconnectConnector = async (id: string) => {
    try {
      await apiFetch(`/api/v1/connectors/${encodeURIComponent(id)}/disconnect`, { method: 'POST' });
      await refreshAll();
      showNotice('success', 'Connector disconnected.');
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const rotateVaultSecrets = async () => {
    try {
      const res = await apiFetch<{ rotatedCount: number; activeKeyVersion: number }>(
        '/api/v1/connectors/rotate-secrets',
        { method: 'POST' }
      );
      await refreshAll();
      showNotice(
        'success',
        `Rotated ${res.rotatedCount} encrypted credential envelope(s) under Vault Key v${res.activeKeyVersion}.`
      );
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const evaluateCloudPosture = async (payload: {
    provider: 'aws' | 'azure' | 'gcp';
    accountId: string;
    region: string;
    resources?: Array<{
      resourceType: string;
      resourceArn: string;
      exposure: 'Public' | 'Internal' | 'Private';
      publicAccessBlock?: boolean;
      encryptionEnabled?: boolean;
      openPorts?: number[];
      wildcardPermissions?: boolean;
    }>;
  }) => {
    try {
      const res = await apiFetch<{ evaluatedCount: number; nonCompliantCount: number; newFindingsCount: number }>(
        '/api/v1/cloud/resources',
        { method: 'POST', body: JSON.stringify(payload) }
      );
      await refreshAll();
      showNotice(
        'success',
        `Evaluated ${res.evaluatedCount} ${payload.provider.toUpperCase()} resource(s): ${res.nonCompliantCount} drift issue(s), ${res.newFindingsCount} new findings.`
      );
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const inspectOciImage = async (image: string, dockerfileContent?: string) => {
    try {
      const res = await apiFetch<Record<string, unknown>>('/api/v1/integrations/oci/inspect', {
        method: 'POST',
        body: JSON.stringify({ image, ...(dockerfileContent ? { dockerfileContent } : {}) }),
      });
      await refreshAll();
      const detected = Array.isArray(res.findingsDetected) ? res.findingsDetected.length : 0;
      showNotice('success', `Inspected OCI manifest for ${image} (${detected} finding(s) analyzed).`);
      return res;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return null;
    }
  };

  const fetchProjectSbom = async (projectId: string, format: 'cyclonedx' | 'spdx') => {
    try {
      return await apiFetch<Record<string, unknown>>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/sbom?format=${format}&validate=true`
      );
    } catch (err) {
      showNotice('error', (err as Error).message);
      return null;
    }
  };

  const verifySlsaAttestation = async (
    projectId: string,
    payload: { expectedDigestSha256: string; artifactContent?: string; hmacSignature?: string; signingSecret?: string }
  ) => {
    try {
      const res = await apiFetch<Record<string, unknown>>(
        `/api/v1/projects/${encodeURIComponent(projectId)}/sbom`,
        { method: 'POST', body: JSON.stringify(payload) }
      );
      await refreshAll();
      showNotice('success', `Artifact attestation verified cleanly (${String(res.slsaLevel)}).`);
      return res;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return null;
    }
  };

  const createApiKey = async (name: string, role: Role, scopes?: string[], expiresInDays?: number) => {
    try {
      const res = await apiFetch<{ apiKey: ApiKeyItem; secret: string }>('/api/v1/api-keys', {
        method: 'POST',
        body: JSON.stringify({ name, role, ...(scopes ? { scopes } : {}), ...(expiresInDays ? { expiresInDays } : {}) }),
      });
      await refreshAll();
      showNotice('success', `Issued scoped API key "${name}" (${res.apiKey.keyPrefix}). Copy it now.`);
      return res;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return null;
    }
  };

  const rotateApiKey = async (id: string) => {
    try {
      const res = await apiFetch<{ apiKey: ApiKeyItem; secret: string }>(
        `/api/v1/api-keys/${encodeURIComponent(id)}/rotate`,
        { method: 'POST' }
      );
      await refreshAll();
      showNotice('success', `Rotated API key (${res.apiKey.keyPrefix}). Previous key revoked immediately.`);
      return res;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return null;
    }
  };

  const revokeApiKey = async (id: string) => {
    try {
      await apiFetch(`/api/v1/api-keys/${encodeURIComponent(id)}`, { method: 'DELETE' });
      await refreshAll();
      showNotice('success', 'API key revoked immediately.');
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const scanGithubRepo = async (repo: string, branch?: string) => {
    setIsScanning(true);
    setScanProgress(`Fetching & scanning live GitHub repository ${repo}...`);
    try {
      const res = await apiFetch<Record<string, unknown>>('/api/v1/integrations/github/scan-repo', {
        method: 'POST',
        body: JSON.stringify({ repo, branch, includeOsvCheck: true }),
      });
      await refreshAll();
      showNotice(
        'success',
        `Scanned ${String(res.repository)}@${String(res.branch)}: ${String(res.findingsDetected)} findings analyzed (${String(res.newFindingsInserted)} new).`
      );
      return res;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return null;
    } finally {
      setIsScanning(false);
      setScanProgress('');
    }
  };

  const queryOsv = async (payload: {
    projectId?: string;
    packages?: Array<{ ecosystem: 'npm' | 'PyPI' | 'Go' | 'Maven'; name: string; version: string }>;
  }) => {
    try {
      const res = await apiFetch<Record<string, unknown>>('/api/v1/integrations/osv/query', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      await refreshAll();
      showNotice(
        'success',
        `OSV.dev live query: checked ${String(res.queriedCount)} package(s), ${String(res.advisoriesCount)} advisories found (${String(res.newFindingsInserted)} new findings).`
      );
      return res;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return null;
    }
  };

  const probeHttpEndpoint = async (targetUrl: string, projectId?: string) => {
    try {
      const res = await apiFetch<Record<string, unknown>>('/api/v1/integrations/http-probe', {
        method: 'POST',
        body: JSON.stringify({ targetUrl, projectId }),
      });
      await refreshAll();
      const issues = Array.isArray(res.issuesDetected) ? res.issuesDetected.length : 0;
      showNotice(
        'success',
        `Probed ${String(res.targetUrl)} (HTTP ${String(res.httpStatus)}, ${String(res.latencyMs)}ms): ${issues} security/TLS check(s) flagged.`
      );
      return res;
    } catch (err) {
      showNotice('error', (err as Error).message);
      return null;
    }
  };

  const dispatchTestWebhook = async () => {
    try {
      const res = await apiFetch<{ httpStatus: number }>('/api/v1/webhooks/outbound/test', {
        method: 'POST',
        body: JSON.stringify({ summaryOnly: true }),
      });
      await refreshAll();
      showNotice('success', `Dispatched live security posture digest via webhook (HTTP ${res.httpStatus}).`);
    } catch (err) {
      await refreshAll();
      showNotice('error', (err as Error).message);
    }
  };

  const enqueueBackgroundJob = async (
    jobType: string,
    payload: Record<string, unknown> = {},
    simulateFailure = false
  ) => {
    try {
      await apiFetch('/api/v1/jobs', {
        method: 'POST',
        body: JSON.stringify({ action: 'enqueue', jobType, payload, executeImmediately: true, simulateFailure }),
      });
      await refreshAll();
      showNotice('success', `Processed background job "${jobType}".`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const retryBackgroundJob = async (jobId: string, simulateFailure = false) => {
    try {
      await apiFetch('/api/v1/jobs', {
        method: 'POST',
        body: JSON.stringify({ action: 'retry', jobId, simulateFailure }),
      });
      await refreshAll();
      showNotice('success', `Retried background job ${jobId}.`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const inviteMember = async (payload: { email: string; name: string; role: Role; title: string }) => {
    try {
      await apiFetch('/api/v1/team', { method: 'POST', body: JSON.stringify(payload) });
      await refreshAll();
      showNotice('success', `Invited ${payload.email} (${payload.role}).`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const updateMemberRole = async (membershipId: string, role: Role) => {
    try {
      await apiFetch('/api/v1/team', { method: 'PATCH', body: JSON.stringify({ membershipId, role }) });
      await refreshAll();
      showNotice('success', `Updated member role to ${role}.`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const updateMemberStatus = async (membershipId: string, userStatus: 'Active' | 'Disabled') => {
    try {
      await apiFetch('/api/v1/team', { method: 'PATCH', body: JSON.stringify({ membershipId, userStatus }) });
      await refreshAll();
      showNotice('success', `Updated account status to ${userStatus}.`);
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  const updateOrgSettings = async (payload: {
    name?: string;
    edition?: Edition;
    dataRetentionDays?: number;
    threatSharingOptIn?: boolean;
    enforcementMode?: EnforcementMode;
  }) => {
    try {
      await apiFetch('/api/v1/organizations', { method: 'PATCH', body: JSON.stringify(payload) });
      await refreshAll();
      showNotice('success', 'Organization governance settings saved.');
    } catch (err) {
      showNotice('error', (err as Error).message);
    }
  };

  return (
    <TrustrailContext.Provider
      value={{
        isLoadingSession,
        isLoadingData,
        user,
        memberships,
        activeTab,
        setActiveTab,
        theme,
        toggleTheme,
        globalSearch,
        setGlobalSearch,
        notice,
        clearNotice,
        org,
        projects,
        findings,
        graphNodes,
        graphEdges,
        attackPaths,
        changeContracts,
        policies,
        aiAgents,
        incidents,
        canaries,
        complianceControls,
        connectors,
        apiKeys,
        trustReceipts,
        teamMembers,
        auditLogs,
        auditChainVerified,
        remediationRuns,
        recoveryBackups,
        cloudResources,
        backgroundJobs,
        systemMetrics,
        isScanning,
        scanProgress,
        login,
        register,
        logout,
        refreshSessionToken,
        updateProfile,
        setupMfa,
        verifyMfa,
        disableMfa,
        verifyEmail,
        forgotPassword,
        resetPassword,
        switchOrganization,
        refreshAll,
        runScan,
        createProject,
        resolveFinding,
        startRemediation,
        progressRemediation,
        mitigateAttackPath,
        createChangeContract,
        tamperChangeContract,
        approveChange,
        revokeApproval,
        executeChange,
        createPolicy,
        togglePolicy,
        evaluatePolicy,
        executeAgentTool,
        revokeAgent,
        createIncident,
        updateIncident,
        createBackupSnapshot,
        verifyBackupRestore,
        deployCanary,
        triggerCanary,
        updateComplianceControl,
        issueTrustPassport,
        revokeTrustPassport,
        testConnector,
        configureConnector,
        disconnectConnector,
        rotateVaultSecrets,
        evaluateCloudPosture,
        inspectOciImage,
        fetchProjectSbom,
        verifySlsaAttestation,
        createApiKey,
        rotateApiKey,
        revokeApiKey,
        scanGithubRepo,
        queryOsv,
        probeHttpEndpoint,
        dispatchTestWebhook,
        enqueueBackgroundJob,
        retryBackgroundJob,
        inviteMember,
        updateMemberRole,
        updateMemberStatus,
        updateOrgSettings,
      }}
    >
      {children}
    </TrustrailContext.Provider>
  );
}

export function useTrustrail() {
  const context = useContext(TrustrailContext);
  if (!context) {
    throw new Error('useTrustrail must be used within a TrustrailProvider');
  }
  return context;
}
