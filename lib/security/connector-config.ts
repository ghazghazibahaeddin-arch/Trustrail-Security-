import { decryptSecretPayload, encryptSecretPayload, isEncryptedEnvelope } from '@/lib/security/vault';

export interface ConnectorConfigData {
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

export function maskSecretValue(val?: string, prefixKeep = 4): string | undefined {
  if (!val || !val.trim()) return undefined;
  const trimmed = val.trim();
  if (trimmed.length <= prefixKeep + 4) {
    return `${trimmed.slice(0, 2)}****${trimmed.slice(-2)}`;
  }
  return `${trimmed.slice(0, prefixKeep)}****${trimmed.slice(-4)}`;
}

export function maskWebhookUrl(rawUrl?: string): string | undefined {
  if (!rawUrl || !rawUrl.trim()) return undefined;
  try {
    const u = new URL(rawUrl.trim());
    const tail = u.pathname.length > 6 ? `...${u.pathname.slice(-4)}` : '/***';
    return `${u.protocol}//${u.host}${tail}`;
  } catch {
    return 'https://****';
  }
}

export function encryptConnectorConfig(
  config: ConnectorConfigData,
  scope?: { orgId?: string; connectorId?: string }
): string {
  const clean: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(config)) {
    if (typeof v === 'string' && v.trim().length > 0) {
      clean[k] = v.trim();
    }
  }
  const aad = scope?.orgId && scope?.connectorId ? `${scope.orgId}:${scope.connectorId}` : undefined;
  return encryptSecretPayload(clean, { aad });
}

export function parseConnectorConfig(
  configJson?: string | null,
  scope?: { orgId?: string; connectorId?: string }
): ConnectorConfigData {
  if (!configJson) return {};
  try {
    const aad = scope?.orgId && scope?.connectorId ? `${scope.orgId}:${scope.connectorId}` : undefined;
    const { data } = decryptSecretPayload<Record<string, unknown>>(configJson, { aad });
    if (!data) return {};
    return {
      githubToken: typeof data.githubToken === 'string' ? data.githubToken : undefined,
      defaultRepo: typeof data.defaultRepo === 'string' ? data.defaultRepo : undefined,
      webhookUrl: typeof data.webhookUrl === 'string' ? data.webhookUrl : undefined,
      awsRoleArn: typeof data.awsRoleArn === 'string' ? data.awsRoleArn : undefined,
      awsExternalId: typeof data.awsExternalId === 'string' ? data.awsExternalId : undefined,
      awsAccessKeyId: typeof data.awsAccessKeyId === 'string' ? data.awsAccessKeyId : undefined,
      awsSecretAccessKey: typeof data.awsSecretAccessKey === 'string' ? data.awsSecretAccessKey : undefined,
      awsRegion: typeof data.awsRegion === 'string' ? data.awsRegion : undefined,
      azureTenantId: typeof data.azureTenantId === 'string' ? data.azureTenantId : undefined,
      azureSubscriptionId: typeof data.azureSubscriptionId === 'string' ? data.azureSubscriptionId : undefined,
      gcpProjectId: typeof data.gcpProjectId === 'string' ? data.gcpProjectId : undefined,
    };
  } catch {
    return {};
  }
}

export function maskConnectorConfig(
  configJson?: string | null,
  scope?: { orgId?: string; connectorId?: string }
): MaskedConnectorConfig {
  const aad = scope?.orgId && scope?.connectorId ? `${scope.orgId}:${scope.connectorId}` : undefined;
  let keyVersion: number | undefined;
  const encrypted = isEncryptedEnvelope(configJson);
  try {
    if (configJson) {
      const dec = decryptSecretPayload<Record<string, unknown>>(configJson, { aad });
      if (dec.keyVersion !== null) keyVersion = dec.keyVersion;
    }
  } catch {
    // ignore decryption errors in mask view
  }

  const cfg = parseConnectorConfig(configJson, scope);
  const githubTokenHint = maskSecretValue(cfg.githubToken, 4);
  const webhookUrlHint = maskWebhookUrl(cfg.webhookUrl);
  const awsExternalIdHint = maskSecretValue(cfg.awsExternalId, 2);
  const awsAccessKeyIdHint = maskSecretValue(cfg.awsAccessKeyId, 4);

  return {
    configured: Boolean(
      cfg.githubToken ||
        cfg.defaultRepo ||
        cfg.webhookUrl ||
        cfg.awsRoleArn ||
        cfg.awsExternalId ||
        cfg.awsAccessKeyId ||
        cfg.azureTenantId ||
        cfg.gcpProjectId
    ),
    encrypted,
    ...(keyVersion !== undefined ? { keyVersion } : {}),
    ...(githubTokenHint ? { githubTokenHint } : {}),
    ...(cfg.defaultRepo ? { defaultRepo: cfg.defaultRepo } : {}),
    ...(webhookUrlHint ? { webhookUrlHint } : {}),
    ...(cfg.awsRoleArn ? { awsRoleArn: cfg.awsRoleArn } : {}),
    ...(awsExternalIdHint ? { awsExternalIdHint } : {}),
    ...(awsAccessKeyIdHint ? { awsAccessKeyIdHint } : {}),
    ...(cfg.awsRegion ? { awsRegion: cfg.awsRegion } : {}),
    ...(cfg.azureTenantId ? { azureTenantId: cfg.azureTenantId } : {}),
    ...(cfg.azureSubscriptionId ? { azureSubscriptionId: cfg.azureSubscriptionId } : {}),
    ...(cfg.gcpProjectId ? { gcpProjectId: cfg.gcpProjectId } : {}),
  };
}
