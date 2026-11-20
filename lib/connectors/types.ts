export type ConnectorLifecycleState =
  | 'AVAILABLE'
  | 'NOT_CONFIGURED'
  | 'CONFIGURING'
  | 'AUTHENTICATING'
  | 'AUTHENTICATED'
  | 'CONNECTED'
  | 'INITIAL_SYNC'
  | 'SYNCHRONIZING'
  | 'HEALTHY'
  | 'DEGRADED'
  | 'ERROR'
  | 'REAUTH_REQUIRED'
  | 'DISCONNECTED';

export interface ConnectorSyncResult {
  runId: string;
  connectorId: string;
  providerKey: string;
  mode: 'initial' | 'incremental' | 'webhook' | 'manual';
  status: 'Completed' | 'Partial' | 'Failed';
  assetsDiscovered: number;
  eventsImported: number;
  failuresCount: number;
  cursor: string | null;
  errorMessage?: string | null;
  lifecycleState: ConnectorLifecycleState;
  startedAt: string;
  completedAt: string;
}

export interface ConnectorHealthReport {
  connectorId: string;
  providerKey: string;
  status: string;
  availabilityState: string;
  lifecycleState: ConnectorLifecycleState;
  healthCheck: string;
  lastSync: string;
  assetsDiscovered: number;
  eventsImported: number;
  failureCount: number;
  lastError?: string | null;
  credentialExpiresAt?: string | null;
  missingPermissions: string[];
  ownerEmail?: string | null;
  dataDirection: 'inbound' | 'outbound' | 'bidirectional';
}

export interface TrustrailConnector {
  readonly provider: string;
  readonly connectorId: string;
  readonly orgId: string;
  readonly authenticationMethod: string;
  readonly requiredScopes: string[];

  validateCredentials(): { valid: boolean; missing: string[]; reason?: string };
  connect(): Promise<{ connected: boolean; lifecycleState: ConnectorLifecycleState; message: string }>;
  testConnection(): Promise<{ ok: boolean; lifecycleState: ConnectorLifecycleState; message: string; details?: Record<string, unknown> }>;
  discoverAssets(): Promise<{ assetsDiscovered: number; details?: Record<string, unknown> }>;
  initialSync(): Promise<ConnectorSyncResult>;
  incrementalSync(cursor?: string | null): Promise<ConnectorSyncResult>;
  processWebhook?(payload: Record<string, unknown>, headers: Record<string, string>): Promise<{ accepted: boolean; eventsImported: number }>;
  executeSupportedAction?(action: string, params: Record<string, unknown>): Promise<Record<string, unknown>>;
  getHealth(): ConnectorHealthReport;
  refreshCredentials?(): Promise<{ refreshed: boolean; expiresAt?: string }>;
  disconnect(): { disconnected: boolean; lifecycleState: ConnectorLifecycleState };
  revoke(): { revoked: boolean; lifecycleState: ConnectorLifecycleState };
  deleteConnectionData(purgeSyncedFindings?: boolean): { deletedAssets: number; deletedSyncRuns: number; clearedCredentials: boolean };
}
