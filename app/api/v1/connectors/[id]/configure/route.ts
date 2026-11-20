import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import {
  encryptConnectorConfig,
  maskConnectorConfig,
  parseConnectorConfig,
} from '@/lib/security/connector-config';
import { assertSafeExternalUrl } from '@/lib/security/ssrf';
import { publishEvent } from '@/lib/fabric/event-bus';

const ConfigureSchema = z.object({
  githubToken: z.string().max(400).optional(),
  githubAppId: z.string().max(40).optional(),
  githubInstallationId: z.string().max(40).optional(),
  githubPrivateKeyPem: z.string().max(8000).optional(),
  defaultRepo: z.string().max(200).optional(),
  gitlabUrl: z.string().max(300).optional(),
  gitlabToken: z.string().max(400).optional(),
  bitbucketWorkspace: z.string().max(120).optional(),
  bitbucketUsername: z.string().max(120).optional(),
  bitbucketAppPassword: z.string().max(400).optional(),
  webhookUrl: z.string().max(500).optional(),
  teamsWebhookUrl: z.string().max(500).optional(),
  emailProvider: z.string().max(40).optional(),
  emailApiKey: z.string().max(400).optional(),
  emailFrom: z.string().max(200).optional(),
  emailRecipients: z.string().max(500).optional(),
  awsRoleArn: z.string().max(200).optional(),
  awsExternalId: z.string().max(200).optional(),
  awsAccessKeyId: z.string().max(200).optional(),
  awsSecretAccessKey: z.string().max(400).optional(),
  awsRegion: z.string().max(40).optional(),
  azureTenantId: z.string().max(100).optional(),
  azureSubscriptionId: z.string().max(100).optional(),
  gcpProjectId: z.string().max(100).optional(),
  kubeApiUrl: z.string().max(400).optional(),
  kubeToken: z.string().max(2000).optional(),
  kubeClusterName: z.string().max(120).optional(),
  splunkHecUrl: z.string().max(400).optional(),
  splunkHecToken: z.string().max(400).optional(),
  elasticEndpointUrl: z.string().max(400).optional(),
  elasticApiKey: z.string().max(400).optional(),
  vaultAddress: z.string().max(300).optional(),
  vaultToken: z.string().max(400).optional(),
  awsKmsKeyArn: z.string().max(240).optional(),
  ssoIssuerUrl: z.string().max(300).optional(),
  ssoClientId: z.string().max(200).optional(),
  ownerEmail: z.string().max(200).optional(),
  credentialExpiresAt: z.string().max(60).optional(),
  verifyNow: z.boolean().default(true),
});

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Admin');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = ConfigureSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid connector configuration payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const row = db
    .prepare('SELECT id, provider_key, name, config_json FROM connectors WHERE id = ? AND org_id = ?')
    .get(id, authResult.auth.orgId) as
    | { id: string; provider_key: string; name: string; config_json: string | null }
    | undefined;

  if (!row) return jsonError('Connector not found.', 404, 'NOT_FOUND');

  const vaultScope = { orgId: authResult.auth.orgId, connectorId: id };
  const existing = parseConnectorConfig(row.config_json, vaultScope);
  const nextConfig = { ...existing };

  const assignStr = (key: keyof typeof nextConfig, val: string | undefined) => {
    if (val !== undefined) {
      nextConfig[key] = val.trim() || undefined;
    }
  };

  assignStr('githubToken', parsed.data.githubToken);
  assignStr('githubAppId', parsed.data.githubAppId);
  assignStr('githubInstallationId', parsed.data.githubInstallationId);
  assignStr('githubPrivateKeyPem', parsed.data.githubPrivateKeyPem);
  assignStr('defaultRepo', parsed.data.defaultRepo);
  assignStr('gitlabToken', parsed.data.gitlabToken);
  assignStr('bitbucketWorkspace', parsed.data.bitbucketWorkspace);
  assignStr('bitbucketUsername', parsed.data.bitbucketUsername);
  assignStr('bitbucketAppPassword', parsed.data.bitbucketAppPassword);
  assignStr('emailProvider', parsed.data.emailProvider);
  assignStr('emailApiKey', parsed.data.emailApiKey);
  assignStr('emailFrom', parsed.data.emailFrom);
  assignStr('emailRecipients', parsed.data.emailRecipients);
  assignStr('awsRoleArn', parsed.data.awsRoleArn);
  assignStr('awsExternalId', parsed.data.awsExternalId);
  assignStr('awsAccessKeyId', parsed.data.awsAccessKeyId);
  assignStr('awsSecretAccessKey', parsed.data.awsSecretAccessKey);
  assignStr('awsRegion', parsed.data.awsRegion);
  assignStr('azureTenantId', parsed.data.azureTenantId);
  assignStr('azureSubscriptionId', parsed.data.azureSubscriptionId);
  assignStr('gcpProjectId', parsed.data.gcpProjectId);
  assignStr('kubeToken', parsed.data.kubeToken);
  assignStr('kubeClusterName', parsed.data.kubeClusterName);
  assignStr('splunkHecToken', parsed.data.splunkHecToken);
  assignStr('elasticApiKey', parsed.data.elasticApiKey);
  assignStr('vaultToken', parsed.data.vaultToken);
  assignStr('awsKmsKeyArn', parsed.data.awsKmsKeyArn);
  assignStr('ssoClientId', parsed.data.ssoClientId);

  const urlFields: Array<['webhookUrl' | 'teamsWebhookUrl' | 'gitlabUrl' | 'kubeApiUrl' | 'splunkHecUrl' | 'elasticEndpointUrl' | 'vaultAddress' | 'ssoIssuerUrl', string | undefined]> = [
    ['webhookUrl', parsed.data.webhookUrl],
    ['teamsWebhookUrl', parsed.data.teamsWebhookUrl],
    ['gitlabUrl', parsed.data.gitlabUrl],
    ['kubeApiUrl', parsed.data.kubeApiUrl],
    ['splunkHecUrl', parsed.data.splunkHecUrl],
    ['elasticEndpointUrl', parsed.data.elasticEndpointUrl],
    ['vaultAddress', parsed.data.vaultAddress],
    ['ssoIssuerUrl', parsed.data.ssoIssuerUrl],
  ];

  for (const [key, rawUrl] of urlFields) {
    if (rawUrl !== undefined) {
      const trimmed = rawUrl.trim();
      if (trimmed) {
        try {
          await assertSafeExternalUrl(trimmed, { requireHttps: true });
        } catch (err) {
          return jsonError(`Invalid ${key}: ${(err as Error).message}`, 400, 'INVALID_URL');
        }
        nextConfig[key] = trimmed;
      } else {
        nextConfig[key] = undefined;
      }
    }
  }

  const encryptedEnvelope = encryptConnectorConfig(nextConfig, vaultScope);
  const now = new Date().toISOString();
  let status = 'Disconnected';
  let availabilityState = 'NOT_CONFIGURED';
  let lifecycleState = 'CONFIGURING';
  let healthCheck = 'Credentials_Required';
  let message = `Saved AES-256-GCM encrypted configuration for ${row.name}.`;

  if (row.provider_key === 'github') {
    const token = nextConfig.githubToken || process.env.GITHUB_TOKEN;
    if (token && parsed.data.verifyNow) {
      try {
        const ghRes = await fetch('https://api.github.com/rate_limit', {
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'application/vnd.github+json',
            'User-Agent': 'Trustrail-Security-Cloud',
          },
          signal: AbortSignal.timeout(8000),
        });
        if (!ghRes.ok) {
          return jsonError(
            `GitHub rejected token with HTTP ${ghRes.status}. Configuration was not activated.`,
            400,
            'GITHUB_AUTH_FAILED'
          );
        }
        status = 'Connected';
        availabilityState = 'CONNECTED';
        lifecycleState = 'HEALTHY';
        healthCheck = 'Healthy';
        message = 'GitHub PAT verified cleanly against api.github.com and encrypted into org vault.';
      } catch (err) {
        return jsonError(`Unable to verify GitHub PAT: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
      }
    } else if (token || (nextConfig.githubAppId && nextConfig.githubInstallationId && nextConfig.githubPrivateKeyPem)) {
      status = 'Connected';
      availabilityState = 'CONFIGURED';
      lifecycleState = 'AUTHENTICATED';
      healthCheck = 'Healthy';
      message = nextConfig.githubAppId
        ? 'GitHub App credentials encrypted into org vault. Click Verify / Test to exchange installation token.'
        : 'GitHub credentials encrypted into org vault.';
    }
  } else if (row.provider_key === 'slack') {
    const hook = nextConfig.webhookUrl || process.env.SLACK_WEBHOOK_URL;
    if (hook && parsed.data.verifyNow) {
      try {
        const hookRes = await fetch(hook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            text: '[Trustrail Security Cloud] Webhook channel configured and verified.',
            content: '[Trustrail Security Cloud] Webhook channel configured and verified.',
            event: 'trustrail.webhook_configured',
            timestamp: now,
          }),
          signal: AbortSignal.timeout(8000),
        });
        if (!hookRes.ok) {
          return jsonError(
            `Webhook endpoint returned HTTP ${hookRes.status}. Check URL before saving.`,
            400,
            'WEBHOOK_DELIVERY_FAILED'
          );
        }
        status = 'Connected';
        availabilityState = 'CONNECTED';
        lifecycleState = 'HEALTHY';
        healthCheck = 'Healthy';
        message = `Webhook URL verified (HTTP ${hookRes.status}) and encrypted into org vault.`;
      } catch (err) {
        return jsonError(`Webhook verification error: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
      }
    } else if (hook) {
      status = 'Connected';
      availabilityState = 'CONFIGURED';
      lifecycleState = 'CONNECTED';
      healthCheck = 'Healthy';
    }
  } else if (row.provider_key === 'teams') {
    if (nextConfig.teamsWebhookUrl) {
      status = 'Disconnected';
      availabilityState = 'CONFIGURED';
      lifecycleState = 'CONFIGURING';
      healthCheck = 'Configured_Ready_To_Test';
      message = 'Saved encrypted Microsoft Teams webhook URL. Click Verify / Test to dispatch a test card.';
    }
  } else if (row.provider_key === 'gitlab') {
    if (nextConfig.gitlabToken) {
      status = 'Disconnected';
      availabilityState = 'CONFIGURED';
      lifecycleState = 'CONFIGURING';
      healthCheck = 'Configured_Ready_To_Test';
      message = 'Saved encrypted GitLab credentials. Click Verify / Test to validate against GitLab API v4.';
    }
  } else if (row.provider_key === 'bitbucket') {
    if (nextConfig.bitbucketWorkspace && nextConfig.bitbucketAppPassword) {
      status = 'Disconnected';
      availabilityState = 'CONFIGURED';
      lifecycleState = 'CONFIGURING';
      healthCheck = 'Configured_Ready_To_Test';
      message = 'Saved encrypted Bitbucket workspace credentials.';
    }
  } else if (row.provider_key === 'aws') {
    if (nextConfig.awsRoleArn && !/^arn:aws[a-z-]*:iam::\d{12}:role\/.+$/.test(nextConfig.awsRoleArn)) {
      return jsonError(
        'Invalid AWS IAM Role ARN format (expected arn:aws:iam::123456789012:role/...).',
        400,
        'VALIDATION_ERROR'
      );
    }
    const hasAwsKeys = Boolean(
      (nextConfig.awsAccessKeyId && nextConfig.awsSecretAccessKey) ||
        (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY)
    );
    if (hasAwsKeys) {
      status = 'Disconnected';
      availabilityState = 'CONFIGURED';
      lifecycleState = 'CONFIGURING';
      healthCheck = 'Configured_Ready_To_Test';
      message = 'Saved encrypted AWS credentials. Click Verify / Test to run live AWS STS GetCallerIdentity.';
    } else if (nextConfig.awsRoleArn) {
      status = 'Disconnected';
      availabilityState = 'CONFIGURED';
      lifecycleState = 'CONFIGURING';
      healthCheck = 'Credentials_Required';
      message = 'Saved AWS IAM Role ARN & External ID encrypted in vault.';
    }
  } else if (row.provider_key === 'azure') {
    if (nextConfig.azureTenantId && !/^[0-9a-f-]{36}$/i.test(nextConfig.azureTenantId)) {
      return jsonError('Invalid Azure Tenant ID UUID format.', 400, 'VALIDATION_ERROR');
    }
    if (nextConfig.azureTenantId && nextConfig.azureSubscriptionId) {
      status = 'Disconnected';
      availabilityState = 'CONFIGURED';
      lifecycleState = 'CONFIGURING';
      healthCheck = 'Configured_Ready_To_Test';
      message = 'Saved Azure Tenant & Subscription metadata encrypted in vault.';
    }
  } else if (row.provider_key === 'gcp') {
    if (nextConfig.gcpProjectId && !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(nextConfig.gcpProjectId)) {
      return jsonError('Invalid GCP Project ID format.', 400, 'VALIDATION_ERROR');
    }
    if (nextConfig.gcpProjectId) {
      status = 'Disconnected';
      availabilityState = 'CONFIGURED';
      lifecycleState = 'CONFIGURING';
      healthCheck = 'Configured_Ready_To_Test';
      message = 'Saved GCP Project ID encrypted in vault.';
    }
  } else if (row.provider_key === 'kubernetes') {
    status = 'Connected';
    availabilityState = nextConfig.kubeApiUrl ? 'CONFIGURED' : 'AVAILABLE';
    lifecycleState = nextConfig.kubeApiUrl ? 'CONNECTED' : 'AVAILABLE';
    healthCheck = 'Healthy';
    message = nextConfig.kubeApiUrl
      ? 'Saved Kubernetes API server endpoint & bearer token encrypted in vault.'
      : 'Kubernetes posture engine ready for manifest/snapshot inspection.';
  } else if (row.provider_key === 'siem_splunk' || row.provider_key === 'siem_elastic' || row.provider_key === 'email_alerts') {
    status = 'Disconnected';
    availabilityState = 'CONFIGURED';
    lifecycleState = 'CONFIGURING';
    healthCheck = 'Configured_Ready_To_Test';
    message = `Saved encrypted ${row.name} configuration in vault.`;
  } else {
    status = 'Connected';
    availabilityState = 'AVAILABLE';
    lifecycleState = 'HEALTHY';
    healthCheck = 'Healthy';
  }

  db.prepare(
    `UPDATE connectors
     SET config_json = ?, status = ?, availability_state = ?, lifecycle_state = ?, health_check = ?,
         last_sync = ?, owner_email = COALESCE(?, owner_email),
         credential_expires_at = COALESCE(?, credential_expires_at), last_error = NULL
     WHERE id = ? AND org_id = ?`
  ).run(
    encryptedEnvelope,
    status,
    availabilityState,
    lifecycleState,
    healthCheck,
    status === 'Connected' ? now : 'Never',
    parsed.data.ownerEmail?.trim() || authResult.auth.email,
    parsed.data.credentialExpiresAt || null,
    id,
    authResult.auth.orgId
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'CONNECTOR_CONFIGURED',
    resourceType: 'Connector',
    resourceId: id,
    details: `Updated AES-256-GCM encrypted configuration for ${row.name} (status=${status}, lifecycle=${lifecycleState}).`,
  });

  if (status === 'Connected') {
    publishEvent(db, {
      orgId: authResult.auth.orgId,
      eventType: 'integration.connected',
      actorId: authResult.auth.email,
      sourceConnector: row.provider_key,
      sourceResourceId: id,
      payload: { lifecycleState, availabilityState },
    });
  }

  return jsonOk({
    id,
    status,
    availabilityState,
    lifecycleState,
    healthCheck,
    lastSync: status === 'Connected' ? now : 'Never',
    message,
    config: maskConnectorConfig(encryptedEnvelope, vaultScope),
  });
}
