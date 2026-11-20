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

const ConfigureSchema = z.object({
  githubToken: z.string().max(400).optional(),
  defaultRepo: z.string().max(200).optional(),
  webhookUrl: z.string().max(500).optional(),
  awsRoleArn: z.string().max(200).optional(),
  awsExternalId: z.string().max(200).optional(),
  awsAccessKeyId: z.string().max(200).optional(),
  awsSecretAccessKey: z.string().max(400).optional(),
  awsRegion: z.string().max(40).optional(),
  azureTenantId: z.string().max(100).optional(),
  azureSubscriptionId: z.string().max(100).optional(),
  gcpProjectId: z.string().max(100).optional(),
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

  if (parsed.data.githubToken !== undefined) {
    nextConfig.githubToken = parsed.data.githubToken.trim() || undefined;
  }
  if (parsed.data.defaultRepo !== undefined) {
    nextConfig.defaultRepo = parsed.data.defaultRepo.trim() || undefined;
  }
  if (parsed.data.webhookUrl !== undefined) {
    const trimmedHook = parsed.data.webhookUrl.trim();
    if (trimmedHook) {
      try {
        await assertSafeExternalUrl(trimmedHook, { requireHttps: true });
      } catch (err) {
        return jsonError((err as Error).message, 400, 'INVALID_WEBHOOK_URL');
      }
      nextConfig.webhookUrl = trimmedHook;
    } else {
      nextConfig.webhookUrl = undefined;
    }
  }
  if (parsed.data.awsRoleArn !== undefined) {
    nextConfig.awsRoleArn = parsed.data.awsRoleArn.trim() || undefined;
  }
  if (parsed.data.awsExternalId !== undefined) {
    nextConfig.awsExternalId = parsed.data.awsExternalId.trim() || undefined;
  }
  if (parsed.data.awsAccessKeyId !== undefined) {
    nextConfig.awsAccessKeyId = parsed.data.awsAccessKeyId.trim() || undefined;
  }
  if (parsed.data.awsSecretAccessKey !== undefined) {
    nextConfig.awsSecretAccessKey = parsed.data.awsSecretAccessKey.trim() || undefined;
  }
  if (parsed.data.awsRegion !== undefined) {
    nextConfig.awsRegion = parsed.data.awsRegion.trim() || undefined;
  }
  if (parsed.data.azureTenantId !== undefined) {
    nextConfig.azureTenantId = parsed.data.azureTenantId.trim() || undefined;
  }
  if (parsed.data.azureSubscriptionId !== undefined) {
    nextConfig.azureSubscriptionId = parsed.data.azureSubscriptionId.trim() || undefined;
  }
  if (parsed.data.gcpProjectId !== undefined) {
    nextConfig.gcpProjectId = parsed.data.gcpProjectId.trim() || undefined;
  }

  const encryptedEnvelope = encryptConnectorConfig(nextConfig, vaultScope);
  const now = new Date().toISOString();
  let status = 'Disconnected';
  let availabilityState = 'NOT_CONFIGURED';
  let healthCheck = 'Credentials_Required';
  let message = `Saved AES-256-GCM encrypted configuration for ${row.name}.`;

  // Live verify when credentials provided
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
        healthCheck = 'Healthy';
        message = 'GitHub PAT verified cleanly against api.github.com and encrypted into org vault.';
      } catch (err) {
        return jsonError(`Unable to verify GitHub PAT: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
      }
    } else if (token) {
      status = 'Connected';
      availabilityState = 'CONFIGURED';
      healthCheck = 'Healthy';
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
        healthCheck = 'Healthy';
        message = `Webhook URL verified (HTTP ${hookRes.status}) and encrypted into org vault.`;
      } catch (err) {
        return jsonError(`Webhook verification error: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
      }
    } else if (hook) {
      status = 'Connected';
      availabilityState = 'CONFIGURED';
      healthCheck = 'Healthy';
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
      healthCheck = 'Configured_Ready_To_Test';
      message = 'Saved encrypted AWS credentials. Click Test Connection to run live AWS STS GetCallerIdentity.';
    } else if (nextConfig.awsRoleArn) {
      status = 'Disconnected';
      availabilityState = 'CONFIGURED';
      healthCheck = 'Credentials_Required';
      message = 'Saved AWS IAM Role ARN & External ID encrypted in vault. Add AWS Access Key or server IAM role to run STS verification.';
    }
  } else if (row.provider_key === 'azure') {
    if (nextConfig.azureTenantId && !/^[0-9a-f-]{36}$/i.test(nextConfig.azureTenantId)) {
      return jsonError('Invalid Azure Tenant ID UUID format.', 400, 'VALIDATION_ERROR');
    }
    if (nextConfig.azureTenantId && nextConfig.azureSubscriptionId) {
      status = 'Disconnected';
      availabilityState = 'CONFIGURED';
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
      healthCheck = 'Configured_Ready_To_Test';
      message = 'Saved GCP Project ID encrypted in vault.';
    }
  } else {
    status = 'Connected';
    availabilityState = 'AVAILABLE';
    healthCheck = 'Healthy';
  }

  db.prepare(
    `UPDATE connectors
     SET config_json = ?, status = ?, availability_state = ?, health_check = ?, last_sync = ?
     WHERE id = ? AND org_id = ?`
  ).run(
    encryptedEnvelope,
    status,
    availabilityState,
    healthCheck,
    status === 'Connected' ? now : 'Never',
    id,
    authResult.auth.orgId
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'CONNECTOR_CONFIGURED',
    resourceType: 'Connector',
    resourceId: id,
    details: `Updated AES-256-GCM encrypted configuration for ${row.name} (status=${status}, state=${availabilityState}).`,
  });

  return jsonOk({
    id,
    status,
    availabilityState,
    healthCheck,
    lastSync: status === 'Connected' ? now : 'Never',
    message,
    config: maskConnectorConfig(encryptedEnvelope, vaultScope),
  });
}

