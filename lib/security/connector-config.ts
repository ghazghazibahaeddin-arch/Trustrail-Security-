import { decryptSecretPayload, encryptSecretPayload, isEncryptedEnvelope } from '@/lib/security/vault';

export interface ConnectorConfigData {
  githubToken?: string;
  githubAppId?: string;
  githubInstallationId?: string;
  githubPrivateKeyPem?: string;
  defaultRepo?: string;
  gitlabUrl?: string;
  gitlabToken?: string;
  bitbucketWorkspace?: string;
  bitbucketUsername?: string;
  bitbucketAppPassword?: string;
  webhookUrl?: string;
  teamsWebhookUrl?: string;
  emailProvider?: string;
  emailApiKey?: string;
  emailFrom?: string;
  emailRecipients?: string;
  awsRoleArn?: string;
  awsExternalId?: string;
  awsAccessKeyId?: string;
  awsSecretAccessKey?: string;
  awsRegion?: string;
  azureTenantId?: string;
  azureSubscriptionId?: string;
  gcpProjectId?: string;
  kubeApiUrl?: string;
  kubeToken?: string;
  kubeClusterName?: string;
  splunkHecUrl?: string;
  splunkHecToken?: string;
  elasticEndpointUrl?: string;
  elasticApiKey?: string;
  vaultAddress?: string;
  vaultToken?: string;
  awsKmsKeyArn?: string;
  ssoIssuerUrl?: string;
  ssoClientId?: string;
}

export interface MaskedConnectorConfig {
  configured: boolean;
  encrypted: boolean;
  keyVersion?: number;
  githubTokenHint?: string;
  githubAppId?: string;
  githubInstallationId?: string;
  githubPrivateKeyConfigured?: boolean;
  defaultRepo?: string;
  gitlabUrl?: string;
  gitlabTokenHint?: string;
  bitbucketWorkspace?: string;
  bitbucketAppPasswordHint?: string;
  webhookUrlHint?: string;
  teamsWebhookUrlHint?: string;
  emailProvider?: string;
  emailFrom?: string;
  emailApiKeyHint?: string;
  awsRoleArn?: string;
  awsExternalIdHint?: string;
  awsAccessKeyIdHint?: string;
  awsRegion?: string;
  azureTenantId?: string;
  azureSubscriptionId?: string;
  gcpProjectId?: string;
  kubeClusterName?: string;
  kubeApiUrlHint?: string;
  kubeTokenHint?: string;
  splunkHecUrlHint?: string;
  splunkHecTokenHint?: string;
  elasticEndpointUrlHint?: string;
  elasticApiKeyHint?: string;
  vaultAddress?: string;
  vaultTokenHint?: string;
  awsKmsKeyArn?: string;
  ssoIssuerUrl?: string;
  ssoClientId?: string;
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
    const str = (k: keyof ConnectorConfigData) => (typeof data[k] === 'string' ? (data[k] as string) : undefined);
    return {
      githubToken: str('githubToken'),
      githubAppId: str('githubAppId'),
      githubInstallationId: str('githubInstallationId'),
      githubPrivateKeyPem: str('githubPrivateKeyPem'),
      defaultRepo: str('defaultRepo'),
      gitlabUrl: str('gitlabUrl'),
      gitlabToken: str('gitlabToken'),
      bitbucketWorkspace: str('bitbucketWorkspace'),
      bitbucketUsername: str('bitbucketUsername'),
      bitbucketAppPassword: str('bitbucketAppPassword'),
      webhookUrl: str('webhookUrl'),
      teamsWebhookUrl: str('teamsWebhookUrl'),
      emailProvider: str('emailProvider'),
      emailApiKey: str('emailApiKey'),
      emailFrom: str('emailFrom'),
      emailRecipients: str('emailRecipients'),
      awsRoleArn: str('awsRoleArn'),
      awsExternalId: str('awsExternalId'),
      awsAccessKeyId: str('awsAccessKeyId'),
      awsSecretAccessKey: str('awsSecretAccessKey'),
      awsRegion: str('awsRegion'),
      azureTenantId: str('azureTenantId'),
      azureSubscriptionId: str('azureSubscriptionId'),
      gcpProjectId: str('gcpProjectId'),
      kubeApiUrl: str('kubeApiUrl'),
      kubeToken: str('kubeToken'),
      kubeClusterName: str('kubeClusterName'),
      splunkHecUrl: str('splunkHecUrl'),
      splunkHecToken: str('splunkHecToken'),
      elasticEndpointUrl: str('elasticEndpointUrl'),
      elasticApiKey: str('elasticApiKey'),
      vaultAddress: str('vaultAddress'),
      vaultToken: str('vaultToken'),
      awsKmsKeyArn: str('awsKmsKeyArn'),
      ssoIssuerUrl: str('ssoIssuerUrl'),
      ssoClientId: str('ssoClientId'),
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
  const gitlabTokenHint = maskSecretValue(cfg.gitlabToken, 4);
  const bitbucketAppPasswordHint = maskSecretValue(cfg.bitbucketAppPassword, 3);
  const webhookUrlHint = maskWebhookUrl(cfg.webhookUrl);
  const teamsWebhookUrlHint = maskWebhookUrl(cfg.teamsWebhookUrl);
  const emailApiKeyHint = maskSecretValue(cfg.emailApiKey, 3);
  const awsExternalIdHint = maskSecretValue(cfg.awsExternalId, 2);
  const awsAccessKeyIdHint = maskSecretValue(cfg.awsAccessKeyId, 4);
  const kubeApiUrlHint = maskWebhookUrl(cfg.kubeApiUrl);
  const kubeTokenHint = maskSecretValue(cfg.kubeToken, 4);
  const splunkHecUrlHint = maskWebhookUrl(cfg.splunkHecUrl);
  const splunkHecTokenHint = maskSecretValue(cfg.splunkHecToken, 4);
  const elasticEndpointUrlHint = maskWebhookUrl(cfg.elasticEndpointUrl);
  const elasticApiKeyHint = maskSecretValue(cfg.elasticApiKey, 4);
  const vaultTokenHint = maskSecretValue(cfg.vaultToken, 3);

  return {
    configured: Boolean(
      cfg.githubToken ||
        cfg.githubAppId ||
        cfg.defaultRepo ||
        cfg.gitlabToken ||
        cfg.bitbucketAppPassword ||
        cfg.webhookUrl ||
        cfg.teamsWebhookUrl ||
        cfg.emailApiKey ||
        cfg.awsRoleArn ||
        cfg.awsExternalId ||
        cfg.awsAccessKeyId ||
        cfg.azureTenantId ||
        cfg.gcpProjectId ||
        cfg.kubeApiUrl ||
        cfg.splunkHecUrl ||
        cfg.elasticEndpointUrl ||
        cfg.vaultAddress ||
        cfg.awsKmsKeyArn ||
        cfg.ssoIssuerUrl
    ),
    encrypted,
    ...(keyVersion !== undefined ? { keyVersion } : {}),
    ...(githubTokenHint ? { githubTokenHint } : {}),
    ...(cfg.githubAppId ? { githubAppId: cfg.githubAppId } : {}),
    ...(cfg.githubInstallationId ? { githubInstallationId: cfg.githubInstallationId } : {}),
    ...(cfg.githubPrivateKeyPem ? { githubPrivateKeyConfigured: true } : {}),
    ...(cfg.defaultRepo ? { defaultRepo: cfg.defaultRepo } : {}),
    ...(cfg.gitlabUrl ? { gitlabUrl: cfg.gitlabUrl } : {}),
    ...(gitlabTokenHint ? { gitlabTokenHint } : {}),
    ...(cfg.bitbucketWorkspace ? { bitbucketWorkspace: cfg.bitbucketWorkspace } : {}),
    ...(bitbucketAppPasswordHint ? { bitbucketAppPasswordHint } : {}),
    ...(webhookUrlHint ? { webhookUrlHint } : {}),
    ...(teamsWebhookUrlHint ? { teamsWebhookUrlHint } : {}),
    ...(cfg.emailProvider ? { emailProvider: cfg.emailProvider } : {}),
    ...(cfg.emailFrom ? { emailFrom: cfg.emailFrom } : {}),
    ...(emailApiKeyHint ? { emailApiKeyHint } : {}),
    ...(cfg.awsRoleArn ? { awsRoleArn: cfg.awsRoleArn } : {}),
    ...(awsExternalIdHint ? { awsExternalIdHint } : {}),
    ...(awsAccessKeyIdHint ? { awsAccessKeyIdHint } : {}),
    ...(cfg.awsRegion ? { awsRegion: cfg.awsRegion } : {}),
    ...(cfg.azureTenantId ? { azureTenantId: cfg.azureTenantId } : {}),
    ...(cfg.azureSubscriptionId ? { azureSubscriptionId: cfg.azureSubscriptionId } : {}),
    ...(cfg.gcpProjectId ? { gcpProjectId: cfg.gcpProjectId } : {}),
    ...(cfg.kubeClusterName ? { kubeClusterName: cfg.kubeClusterName } : {}),
    ...(kubeApiUrlHint ? { kubeApiUrlHint } : {}),
    ...(kubeTokenHint ? { kubeTokenHint } : {}),
    ...(splunkHecUrlHint ? { splunkHecUrlHint } : {}),
    ...(splunkHecTokenHint ? { splunkHecTokenHint } : {}),
    ...(elasticEndpointUrlHint ? { elasticEndpointUrlHint } : {}),
    ...(elasticApiKeyHint ? { elasticApiKeyHint } : {}),
    ...(cfg.vaultAddress ? { vaultAddress: cfg.vaultAddress } : {}),
    ...(vaultTokenHint ? { vaultTokenHint } : {}),
    ...(cfg.awsKmsKeyArn ? { awsKmsKeyArn: cfg.awsKmsKeyArn } : {}),
    ...(cfg.ssoIssuerUrl ? { ssoIssuerUrl: cfg.ssoIssuerUrl } : {}),
    ...(cfg.ssoClientId ? { ssoClientId: cfg.ssoClientId } : {}),
  };
}
