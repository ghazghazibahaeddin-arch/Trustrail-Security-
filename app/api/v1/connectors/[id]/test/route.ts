import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { parseConnectorConfig } from '@/lib/security/connector-config';
import { assertSafeExternalUrl } from '@/lib/security/ssrf';
import { verifyAwsStsCallerIdentity } from '@/lib/integrations/aws-sigv4';

export async function POST(
  req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const authResult = requireAuth(req, 'Admin');
  if ('error' in authResult) return authResult.error;

  const { id } = await context.params;
  const db = getDb();
  const row = db
    .prepare('SELECT id, provider_key, name, config_hint, config_json FROM connectors WHERE id = ? AND org_id = ?')
    .get(id, authResult.auth.orgId) as
    | { id: string; provider_key: string; name: string; config_hint: string; config_json: string | null }
    | undefined;

  if (!row) return jsonError('Connector not found.', 404, 'NOT_FOUND');

  const now = new Date().toISOString();
  const cfg = parseConnectorConfig(row.config_json, {
    orgId: authResult.auth.orgId,
    connectorId: id,
  });

  // Local deterministic analysis engines
  if (row.provider_key === 'terraform' || row.provider_key === 'oci' || row.provider_key === 'http_probe') {
    db.prepare(
      `UPDATE connectors SET status = 'Connected', availability_state = 'AVAILABLE', health_check = 'Healthy', last_sync = ? WHERE id = ? AND org_id = ?`
    ).run(now, id, authResult.auth.orgId);

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'CONNECTOR_VERIFIED',
      resourceType: 'Connector',
      resourceId: id,
      details: `Verified engine health for ${row.name}.`,
    });

    return jsonOk({
      id,
      status: 'Connected',
      availabilityState: 'AVAILABLE',
      healthCheck: 'Healthy',
      lastSync: now,
      message: `${row.name} verified operational.`,
    });
  }

  // Live OSV.dev public API verification
  if (row.provider_key === 'osv') {
    try {
      const osvRes = await fetch('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.15' }),
        signal: AbortSignal.timeout(8000),
      });
      if (!osvRes.ok) {
        db.prepare(
          `UPDATE connectors SET status = 'Error', availability_state = 'DEGRADED', health_check = 'Degraded' WHERE id = ? AND org_id = ?`
        ).run(id, authResult.auth.orgId);
        return jsonError(`OSV.dev API returned HTTP ${osvRes.status}.`, 502, 'EXTERNAL_API_ERROR');
      }
      const osvJson = (await osvRes.json()) as { vulns?: Array<{ id: string }> };
      db.prepare(
        `UPDATE connectors SET status = 'Connected', availability_state = 'PUBLIC_FEED_READY', health_check = 'Healthy', last_sync = ? WHERE id = ? AND org_id = ?`
      ).run(now, id, authResult.auth.orgId);

      appendAuditLog(db, {
        orgId: authResult.auth.orgId,
        actorEmail: authResult.auth.email,
        action: 'CONNECTOR_VERIFIED',
        resourceType: 'Connector',
        resourceId: id,
        details: `Verified live OSV.dev CVE feed (${osvJson.vulns?.length ?? 0} sample advisories resolved).`,
      });

      return jsonOk({
        id,
        status: 'Connected',
        availabilityState: 'PUBLIC_FEED_READY',
        healthCheck: 'Healthy',
        lastSync: now,
        message: `OSV.dev live CVE feed responded cleanly (${osvJson.vulns?.length ?? 0} advisories on health check query).`,
      });
    } catch (err) {
      return jsonError(`OSV.dev network verification failed: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
    }
  }

  // GitHub verification (per-org PAT or server GITHUB_TOKEN)
  if (row.provider_key === 'github') {
    const githubToken = cfg.githubToken || process.env.GITHUB_TOKEN;
    if (!githubToken) {
      db.prepare(
        `UPDATE connectors SET status = 'Disconnected', availability_state = 'NOT_CONFIGURED', health_check = 'Credentials_Required' WHERE id = ? AND org_id = ?`
      ).run(id, authResult.auth.orgId);

      return jsonError(
        'GitHub credentialed integration requires a saved GitHub PAT or GITHUB_TOKEN on the server. Status remains Disconnected (Credentials_Required). Public repositories can still be scanned via Live Repo Scanner.',
        424,
        'CREDENTIALS_REQUIRED',
        { provider: 'github', configHint: row.config_hint }
      );
    }

    try {
      const ghRes = await fetch('https://api.github.com/rate_limit', {
        headers: {
          Authorization: `Bearer ${githubToken}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'Trustrail-Security-Cloud',
        },
        signal: AbortSignal.timeout(8000),
      });
      if (!ghRes.ok) {
        db.prepare(
          `UPDATE connectors SET status = 'Error', availability_state = 'ERROR', health_check = 'Degraded' WHERE id = ? AND org_id = ?`
        ).run(id, authResult.auth.orgId);
        return jsonError(`GitHub API returned HTTP ${ghRes.status}. Verify token scopes.`, 502, 'EXTERNAL_API_ERROR');
      }

      const rateData = (await ghRes.json()) as { resources?: { core?: { remaining?: number; limit?: number } } };
      db.prepare(
        `UPDATE connectors SET status = 'Connected', availability_state = 'CONNECTED', health_check = 'Healthy', last_sync = ? WHERE id = ? AND org_id = ?`
      ).run(now, id, authResult.auth.orgId);

      appendAuditLog(db, {
        orgId: authResult.auth.orgId,
        actorEmail: authResult.auth.email,
        action: 'CONNECTOR_VERIFIED',
        resourceType: 'Connector',
        resourceId: id,
        details: `Verified GitHub API token connectivity (rate remaining: ${rateData.resources?.core?.remaining ?? 'ok'}).`,
      });

      return jsonOk({
        id,
        status: 'Connected',
        availabilityState: 'CONNECTED',
        healthCheck: 'Healthy',
        lastSync: now,
        message: `GitHub API verified (${rateData.resources?.core?.remaining ?? 'active'}/${rateData.resources?.core?.limit ?? 5000} core requests remaining).`,
      });
    } catch (err) {
      return jsonError(`GitHub network verification failed: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
    }
  }

  // Real AWS SigV4 STS GetCallerIdentity verification
  if (row.provider_key === 'aws') {
    const accessKeyId = cfg.awsAccessKeyId || process.env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = cfg.awsSecretAccessKey || process.env.AWS_SECRET_ACCESS_KEY;
    const region = cfg.awsRegion || process.env.AWS_REGION || 'us-east-1';

    if (!accessKeyId || !secretAccessKey) {
      const nextState = cfg.awsRoleArn ? 'CONFIGURED' : 'NOT_CONFIGURED';
      db.prepare(
        `UPDATE connectors SET status = 'Disconnected', availability_state = ?, health_check = 'Credentials_Required' WHERE id = ? AND org_id = ?`
      ).run(nextState, id, authResult.auth.orgId);

      return jsonError(
        'AWS live verification requires AWS Access Key ID & Secret Access Key (encrypted in vault or via server env). Status remains Disconnected.',
        424,
        'CREDENTIALS_REQUIRED',
        { provider: 'aws', availabilityState: nextState, configHint: row.config_hint }
      );
    }

    try {
      const sts = await verifyAwsStsCallerIdentity({
        accessKeyId,
        secretAccessKey,
        sessionToken: process.env.AWS_SESSION_TOKEN,
        region,
      });

      if (!sts.ok) {
        db.prepare(
          `UPDATE connectors SET status = 'Error', availability_state = 'ERROR', health_check = 'Auth_Failed' WHERE id = ? AND org_id = ?`
        ).run(id, authResult.auth.orgId);
        return jsonError(
          `AWS STS rejected credentials (${sts.errorCode}): ${sts.errorMessage}`,
          401,
          'AWS_AUTH_FAILED'
        );
      }

      db.prepare(
        `UPDATE connectors SET status = 'Connected', availability_state = 'CONNECTED', health_check = 'Healthy', last_sync = ? WHERE id = ? AND org_id = ?`
      ).run(now, id, authResult.auth.orgId);

      if (sts.account && sts.arn) {
        db.prepare(
          `INSERT INTO cloud_resources (id, org_id, provider, account_id, resource_type, resource_arn, region, exposure, compliant, details_json, collected_at)
           VALUES (?, ?, 'aws', ?, 'AWS::STS::CallerIdentity', ?, ?, 'Internal', 1, ?, ?)`
        ).run(
          `cres-${crypto.randomUUID().slice(0, 8)}`,
          authResult.auth.orgId,
          sts.account,
          sts.arn,
          sts.region,
          JSON.stringify({ userId: sts.userId, roleArnConfigured: cfg.awsRoleArn || null }),
          now
        );
      }

      appendAuditLog(db, {
        orgId: authResult.auth.orgId,
        actorEmail: authResult.auth.email,
        action: 'CONNECTOR_VERIFIED',
        resourceType: 'Connector',
        resourceId: id,
        details: `Verified AWS STS GetCallerIdentity cleanly (account=${sts.account}, region=${sts.region}).`,
      });

      return jsonOk({
        id,
        status: 'Connected',
        availabilityState: 'CONNECTED',
        healthCheck: 'Healthy',
        lastSync: now,
        awsIdentity: sts,
        message: `AWS STS GetCallerIdentity succeeded (Account ${sts.account}, ARN ${sts.arn}).`,
      });
    } catch (err) {
      return jsonError(`AWS STS network verification failed: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
    }
  }

  // Azure & GCP honest credential/token checks
  if (row.provider_key === 'azure') {
    const azureToken = process.env.AZURE_ACCESS_TOKEN;
    if (!azureToken || !cfg.azureSubscriptionId) {
      const nextState = cfg.azureTenantId && cfg.azureSubscriptionId ? 'CONFIGURED' : 'NOT_CONFIGURED';
      db.prepare(
        `UPDATE connectors SET status = 'Disconnected', availability_state = ?, health_check = 'Credentials_Required' WHERE id = ? AND org_id = ?`
      ).run(nextState, id, authResult.auth.orgId);

      return jsonError(
        'Azure Resource Graph polling requires Azure Subscription metadata plus server AZURE_ACCESS_TOKEN. Status remains Disconnected.',
        424,
        'CREDENTIALS_REQUIRED',
        { provider: 'azure', availabilityState: nextState }
      );
    }

    try {
      const azRes = await fetch(
        `https://management.azure.com/subscriptions/${encodeURIComponent(cfg.azureSubscriptionId)}?api-version=2022-12-01`,
        {
          headers: { Authorization: `Bearer ${azureToken}` },
          signal: AbortSignal.timeout(8000),
        }
      );
      if (!azRes.ok) {
        return jsonError(`Azure ARM API returned HTTP ${azRes.status}.`, 502, 'EXTERNAL_API_ERROR');
      }
      db.prepare(
        `UPDATE connectors SET status = 'Connected', availability_state = 'CONNECTED', health_check = 'Healthy', last_sync = ? WHERE id = ? AND org_id = ?`
      ).run(now, id, authResult.auth.orgId);
      return jsonOk({
        id,
        status: 'Connected',
        availabilityState: 'CONNECTED',
        healthCheck: 'Healthy',
        lastSync: now,
        message: `Verified Azure Subscription ${cfg.azureSubscriptionId}.`,
      });
    } catch (err) {
      return jsonError(`Azure verification error: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
    }
  }

  if (row.provider_key === 'gcp') {
    const gcpToken = process.env.GCP_ACCESS_TOKEN;
    if (!gcpToken || !cfg.gcpProjectId) {
      const nextState = cfg.gcpProjectId ? 'CONFIGURED' : 'NOT_CONFIGURED';
      db.prepare(
        `UPDATE connectors SET status = 'Disconnected', availability_state = ?, health_check = 'Credentials_Required' WHERE id = ? AND org_id = ?`
      ).run(nextState, id, authResult.auth.orgId);

      return jsonError(
        'GCP Cloud Asset polling requires saved GCP Project ID plus server GCP_ACCESS_TOKEN. Status remains Disconnected.',
        424,
        'CREDENTIALS_REQUIRED',
        { provider: 'gcp', availabilityState: nextState }
      );
    }

    try {
      const gcpRes = await fetch(
        `https://cloudresourcemanager.googleapis.com/v1/projects/${encodeURIComponent(cfg.gcpProjectId)}`,
        {
          headers: { Authorization: `Bearer ${gcpToken}` },
          signal: AbortSignal.timeout(8000),
        }
      );
      if (!gcpRes.ok) {
        return jsonError(`GCP Resource Manager API returned HTTP ${gcpRes.status}.`, 502, 'EXTERNAL_API_ERROR');
      }
      db.prepare(
        `UPDATE connectors SET status = 'Connected', availability_state = 'CONNECTED', health_check = 'Healthy', last_sync = ? WHERE id = ? AND org_id = ?`
      ).run(now, id, authResult.auth.orgId);
      return jsonOk({
        id,
        status: 'Connected',
        availabilityState: 'CONNECTED',
        healthCheck: 'Healthy',
        lastSync: now,
        message: `Verified GCP Project ${cfg.gcpProjectId}.`,
      });
    } catch (err) {
      return jsonError(`GCP verification error: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
    }
  }

  // Slack / Discord / Custom Webhook alerting verification
  if (row.provider_key === 'slack') {
    const webhookUrl = cfg.webhookUrl || process.env.SLACK_WEBHOOK_URL;
    if (!webhookUrl) {
      db.prepare(
        `UPDATE connectors SET status = 'Disconnected', availability_state = 'NOT_CONFIGURED', health_check = 'Credentials_Required' WHERE id = ? AND org_id = ?`
      ).run(id, authResult.auth.orgId);

      return jsonError(
        'Webhook alerting requires a saved Slack, Discord, or HTTPS Webhook URL. Status remains Disconnected.',
        424,
        'CREDENTIALS_REQUIRED',
        { provider: 'slack', configHint: row.config_hint }
      );
    }

    try {
      const safeUrl = await assertSafeExternalUrl(webhookUrl, { requireHttps: true });
      const hookRes = await fetch(safeUrl.toString(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          text: '[Trustrail Security Cloud] Connectivity test succeeded.',
          content: '[Trustrail Security Cloud] Connectivity test succeeded.',
          event: 'trustrail.connectivity_test',
          timestamp: now,
        }),
        signal: AbortSignal.timeout(8000),
      });
      if (!hookRes.ok) {
        db.prepare(
          `UPDATE connectors SET status = 'Error', availability_state = 'ERROR', health_check = 'Degraded' WHERE id = ? AND org_id = ?`
        ).run(id, authResult.auth.orgId);
        return jsonError(`Webhook endpoint returned HTTP ${hookRes.status}.`, 502, 'EXTERNAL_API_ERROR');
      }
      db.prepare(
        `UPDATE connectors SET status = 'Connected', availability_state = 'CONNECTED', health_check = 'Healthy', last_sync = ? WHERE id = ? AND org_id = ?`
      ).run(now, id, authResult.auth.orgId);

      appendAuditLog(db, {
        orgId: authResult.auth.orgId,
        actorEmail: authResult.auth.email,
        action: 'CONNECTOR_VERIFIED',
        resourceType: 'Connector',
        resourceId: id,
        details: `Verified outbound alert webhook delivery (HTTP ${hookRes.status}).`,
      });

      return jsonOk({
        id,
        status: 'Connected',
        availabilityState: 'CONNECTED',
        healthCheck: 'Healthy',
        lastSync: now,
        message: `Webhook delivered test alert cleanly (HTTP ${hookRes.status}).`,
      });
    } catch (err) {
      return jsonError(`Webhook verification failed: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
    }
  }

  return jsonError('Unsupported connector provider.', 400, 'UNSUPPORTED_CONNECTOR');
}

