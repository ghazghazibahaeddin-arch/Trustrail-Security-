export type Edition = 'developer' | 'smb' | 'enterprise';
export type Role = 'Owner' | 'Admin' | 'Developer' | 'Viewer';

export type EnforcementMode = 'Observe' | 'Recommend' | 'Enforce';

export interface AuthUser {
  id: string;
  email: string;
  name: string;
  role: Role;
  orgId: string;
  emailVerified?: boolean;
  mfaVerified?: boolean;
}

export interface MembershipSummary {
  orgId: string;
  orgName: string;
  slug: string;
  edition: Edition;
  role: Role;
  title: string;
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  edition: Edition;
  tierName: string;
  dataRetentionDays?: number;
  threatSharingOptIn?: boolean;
  enforcementMode?: EnforcementMode;
  riskScore: number;
  securityRating: 'A+' | 'A' | 'B+' | 'B' | 'C' | 'D' | 'F';
  assetsCount: number;
  openFindingsCount: number;
  criticalPathsCount: number;
  activeIncidentsCount: number;
  compliancePercentage: number;
}

export interface CycloneDxSbom {
  bomFormat: 'CycloneDX';
  specVersion: string;
  serialNumber?: string;
  components: Array<{ type: string; name: string; version: string; purl: string }>;
}

export interface Project {
  id: string;
  name: string;
  repoUrl: string;
  branch: string;
  language: string;
  framework: string;
  owner: string;
  status: 'protected' | 'warning' | 'critical' | 'scanning';
  lastScanned: string;
  findingsCount: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  connectedAwsAccount?: string;
  sbomGenerated: boolean;
  sbom?: CycloneDxSbom | null;
  slsaLevel: 'SLSA 1' | 'SLSA 2' | 'SLSA 3' | 'None';
}

export interface SecurityFinding {
  id: string;
  fingerprint: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: 'SAST' | 'SCA' | 'SECRET' | 'IAC' | 'CLOUD' | 'CONTAINER' | 'API' | 'SUPPLY_CHAIN';
  scanner: string;
  assetId?: string;
  assetName: string;
  projectId: string;
  filePath?: string;
  line?: number;
  cve?: string;
  cvss: number;
  exploitability: 'High' | 'Medium' | 'Low' | 'Proof-of-Concept';
  status: 'Open' | 'In_Remediation' | 'Under_Review' | 'Resolved' | 'False_Positive';
  discoveredAt: string;
  verifiedAt?: string;
  evidence: string;
  suggestedFix: string;
  resolutionEvidence?: string;
  aiPatchReady: boolean;
  assignedOwner: string;
  riskScore?: number;
  priorityTier?: 'P0-IMMEDIATE' | 'P1-URGENT' | 'P2-ELEVATED' | 'P3-SCHEDULED';
  riskReasons?: string[];
}

export interface GraphNode {
  id: string;
  orgId: string;
  projectId?: string | null;
  name: string;
  assetType: string;
  owner: string;
  internetExposed: boolean;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  openFindingsCount: number;
}

export interface GraphEdge {
  id: string;
  orgId: string;
  sourceAssetId: string;
  targetAssetId: string;
  relation: string;
  evidence: string;
  confidence?: number;
  collectedAt?: string;
  verifiedAt?: string;
}

export interface AttackPathStep {
  order: number;
  title: string;
  assetType: string;
  assetId: string;
  assetName: string;
  description: string;
}

export interface AttackPath {
  id: string;
  title: string;
  riskScore: number;
  severity: 'CRITICAL' | 'HIGH';
  likelihood: 'High' | 'Medium';
  impact: string;
  targetAsset: string;
  steps: AttackPathStep[];
  contributingFindingIds: string[];
  mitigation: string;
  status: 'Active' | 'Mitigated';
}

export interface ChangeContract {
  id: string;
  title: string;
  actor: string;
  project: string;
  targetAsset: string;
  previousStateHash: string;
  newStatePayload: Record<string, unknown>;
  newStateHash: string;
  approvedHash?: string;
  purpose: string;
  riskLevel: 'High' | 'Medium' | 'Low';
  intentLockStatus: 'Locked' | 'Modified_Revalidation_Required' | 'Approved' | 'Executed' | 'Rejected';
  intentLockReason?: string;
  approvedBy?: string;
  createdAt: string;
  evidenceSummary: string;
}

export interface PolicyItem {
  id: string;
  name: string;
  engine: 'OPA Rego' | 'Cloud Guard' | 'IntentLock' | 'SCA Guard' | 'Agent Guard';
  severity: 'Critical' | 'High' | 'Medium';
  status: 'Enforced' | 'Audit_Only' | 'Disabled';
  ruleCode: string;
  createdAt: string;
}

export interface AIAgentAsset {
  id: string;
  name: string;
  type: 'LLM Agent' | 'MCP Server' | 'Autonomous Worker';
  ownerTeam: string;
  permissions: string[];
  allowlistedTools: string[];
  status: 'Active' | 'Quarantine' | 'Revoked';
  riskLevel: 'High' | 'Medium' | 'Low';
  actionsUsed: number;
  actionLimit: number;
  lastAction: string;
  canaryTriggered: boolean;
}

export interface Incident {
  id: string;
  title: string;
  severity: 'SEV-1' | 'SEV-2' | 'SEV-3';
  status: 'Open' | 'Contained' | 'Recovered' | 'Closed';
  affectedAsset: string;
  owner: string;
  openedAt: string;
  closedAt?: string;
  summary: string;
  playbookName: string;
  actionsTaken: string[];
}

export interface CanaryItem {
  id: string;
  type: string;
  location: string;
  tokenHint: string;
  status: string;
  alertsCount: number;
  lastTriggeredAt?: string | null;
}

export interface ComplianceControl {
  id: string;
  framework: string;
  code: string;
  title: string;
  status: 'Verified' | 'Needs_Evidence' | 'Non_Compliant';
  evidenceCount: number;
  lastVerified: string;
  owner: string;
}

export interface MaskedConnectorConfig {
  configured: boolean;
  encrypted: boolean;
  keyVersion?: number;
  githubTokenHint?: string;
  defaultRepo?: string;
  webhookUrlHint?: string;
  awsRoleArn?: string;
  awsExternalIdHint?: string;
  awsAccessKeyIdHint?: string;
  awsRegion?: string;
  azureTenantId?: string;
  azureSubscriptionId?: string;
  gcpProjectId?: string;
}

export interface Connector {
  id: string;
  providerKey: string;
  name: string;
  category: string;
  status: string;
  availabilityState?: string;
  lastSync: string;
  authType: string;
  permissions: string[];
  healthCheck: string;
  configHint: string;
  config?: MaskedConnectorConfig;
}

export interface ApiKeyItem {
  id: string;
  name: string;
  keyPrefix: string;
  role: Role;
  scopes: string[];
  expiresAt: string | null;
  rotatedFromId?: string | null;
  lastUsedAt: string | null;
  createdAt: string;
  revoked: boolean;
  createdByEmail: string;
}

export interface RemediationRun {
  id: string;
  orgId: string;
  findingId: string;
  status: 'Patch_Generated' | 'Tests_Passed' | 'Rescan_Verified' | 'Failed';
  patchDiff: string;
  verificationCommand: string;
  verificationPassed: boolean;
  rescanClean: boolean;
  createdBy: string;
  createdAt: string;
  verifiedAt?: string | null;
}

export interface RecoveryBackup {
  id: string;
  orgId: string;
  targetName: string;
  backupType: string;
  checksumSha256: string;
  sizeBytes: number;
  restoreTestedAt?: string | null;
  restoreStatus: 'Untested' | 'Verified' | 'Failed';
  createdAt: string;
}

export interface CloudResource {
  id: string;
  orgId: string;
  provider: 'aws' | 'azure' | 'gcp';
  accountId: string;
  resourceType: string;
  resourceArn: string;
  region: string;
  exposure: string;
  compliant: boolean;
  details: Record<string, unknown>;
  collectedAt: string;
}

export interface NotificationDelivery {
  id: string;
  orgId: string;
  channel: string;
  eventType: string;
  status: string;
  httpStatus?: number | null;
  summary: string;
  createdAt: string;
}

export interface BackgroundJob {
  id: string;
  orgId: string;
  jobType: string;
  status: 'Queued' | 'Running' | 'Completed' | 'Dead_Letter';
  attempts: number;
  maxAttempts: number;
  lastError?: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface SystemMetrics {
  generatedAt: string;
  vaultKeyVersion: number;
  enforcementMode: EnforcementMode;
  auditChain: { valid: boolean; totalEntries: number; brokenAtId?: number };
  findingsSummary: Array<{ severity: string; status: string; count: number }>;
  remediationSummary: Array<{ status: string; count: number }>;
  jobsSummary: Array<{ status: string; count: number }>;
  recentNotifications: NotificationDelivery[];
}

export interface TrustReceiptItem {
  id: string;
  title: string;
  issuedAt: string;
  expiresAt: string;
  scope: string[];
  signature: string;
  revoked: boolean;
  accessCount: number;
}

export interface TeamMember {
  membershipId: string;
  userId: string;
  name: string;
  email: string;
  role: Role;
  title: string;
  status: string;
  userStatus?: string;
  mfaEnabled: boolean;
  mfaVerified?: boolean;
}

export interface AuditLogItem {
  id: number;
  orgId: string;
  actorEmail: string;
  action: string;
  resourceType: string;
  resourceId: string;
  details: string;
  prevHash: string;
  entryHash: string;
  createdAt: string;
}

export const EMPTY_ORGANIZATION: Organization = {
  id: '',
  name: 'Loading...',
  slug: '',
  edition: 'developer',
  tierName: '',
  riskScore: 0,
  securityRating: 'A',
  assetsCount: 0,
  openFindingsCount: 0,
  criticalPathsCount: 0,
  activeIncidentsCount: 0,
  compliancePercentage: 100,
};
