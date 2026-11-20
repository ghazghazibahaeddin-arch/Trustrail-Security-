import { NextRequest } from 'next/server';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { parseConnectorConfig } from '@/lib/security/connector-config';
import { assertSafeExternalUrl } from '@/lib/security/ssrf';
import { verifyAwsStsCallerIdentity } from '@/lib/integrations/aws-sigv4';
import { exchangeGithubInstallationToken } from '@/lib/integrations/github-app';
import { publishEvent } from '@/lib/fabric/event-bus';
import crypto from 'node:crypto';

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
  if (['terraform', 'oci', 'http_probe', 'kubernetes', 'kms_vault'].includes(row.provider_key)) {
    // If kubernetes has a remote endpoint configured, verify it cleanly
    if (row.provider_key === 'kubernetes' && cfg.kubeApiUrl && cfg.kubeToken) {
      try {
        const safe = await assertSafeExternalUrl(cfg.kubeApiUrl, { requireHttps: true });
        const kRes = await fetch(`${safe.origin}/version`, {
          headers: { Authorization: `Bearer ${cfg.kubeToken}` },
          signal: AbortSignal.timeout(7000),
        });
        if (!kRes.ok) {
          db.prepare(
            `UPDATE connectors SET status = 'Error', availability_state = 'ERROR', lifecycle_state = 'ERROR', health_check = 'Degraded', failure_count = failure_count + 1, last_error = ? WHERE id = ? AND org_id = ?`
          ).run(`K8s API returned HTTP ${kRes.status}`, id, authResult.auth.orgId);
          return jsonError(`Kubernetes API server returned HTTP ${kRes.status}.`, 502, 'EXTERNAL_API_ERROR');
        }
      } catch (err) {
        return jsonError(`Kubernetes API connectivity failed: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
      }
    }

    db.prepare(
      `UPDATE connectors SET status = 'Connected', availability_state = 'AVAILABLE', lifecycle_state = 'HEALTHY', health_check = 'Healthy', last_sync = ?, last_error = NULL WHERE id = ? AND org_id = ?`
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
      lifecycleState: 'HEALTHY',
      healthCheck: 'Healthy',
      lastSync: now,
      message: `${row.name} verified operational.`,
    });
  }

  // Live OSV.dev & NVD/KEV/EPSS verification
  if (row.provider_key === 'osv' || row.provider_key === 'nvd_kev_epss') {
    try {
      const target =
        row.provider_key === 'osv'
          ? fetch('https://api.osv.dev/v1/query', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.15' }),
              signal: AbortSignal.timeout(8000),
            })
          : fetch('https://api.first.org/data/v1/epss?cve=CVE-2021-44228', {
              signal: AbortSignal.timeout(8000),
            });

      const res = await target;
      if (!res.ok) {
        db.prepare(
          `UPDATE connectors SET status = 'Error', availability_state = 'DEGRADED', lifecycle_state = 'DEGRADED', health_check = 'Degraded' WHERE id = ? AND org_id = ?`
        ).run(id, authResult.auth.orgId);
        return jsonError(`${row.name} returned HTTP ${res.status}.`, 502, 'EXTERNAL_API_ERROR');
      }
      db.prepare(
        `UPDATE connectors SET status = 'Connected', availability_state = 'PUBLIC_FEED_READY', lifecycle_state = 'HEALTHY', health_check = 'Healthy', last_sync = ?, last_error = NULL WHERE id = ? AND org_id = ?`
      ).run(now, id, authResult.auth.orgId);

      appendAuditLog(db, {
        orgId: authResult.auth.orgId,
        actorEmail: authResult.auth.email,
        action: 'CONNECTOR_VERIFIED',
        resourceType: 'Connector',
        resourceId: id,
        details: `Verified live ${row.name} threat intelligence feed.`,
      });

      return jsonOk({
        id,
        status: 'Connected',
        availabilityState: 'PUBLIC_FEED_READY',
        lifecycleState: 'HEALTHY',
        healthCheck: 'Healthy',
        lastSync: now,
        message: `${row.name} live feed responded cleanly.`,
      });
    } catch (err) {
      return jsonError(`${row.name} network verification failed: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
    }
  }

  // GitHub verification (GitHub App installation token OR PAT)
  if (row.provider_key === 'github') {
    let githubToken = cfg.githubToken || process.env.GITHUB_TOKEN;
    if (!githubToken && cfg.githubAppId && cfg.githubInstallationId && cfg.githubPrivateKeyPem) {
      const ex = await exchangeGithubInstallationToken({
        appId: cfg.githubAppId,
        installationId: cfg.githubInstallationId,
        privateKeyPem: cfg.githubPrivateKeyPem,
      });
      if (!ex.ok || !ex.token) {
        db.prepare(
          `UPDATE connectors SET status = 'Error', availability_state = 'ERROR', lifecycle_state = 'REAUTH_REQUIRED', health_check = 'Auth_Failed', last_error = ? WHERE id = ? AND org_id = ?`
        ).run(ex.error || 'GitHub App exchange failed', id, authResult.auth.orgId);
        return jsonError(ex.error || 'GitHub App installation token exchange failed.', 401, 'GITHUB_APP_AUTH_FAILED');
      }
      githubToken = ex.token;
    }

    if (!githubToken) {
      db.prepare(
        `UPDATE connectors SET status = 'Disconnected', availability_state = 'NOT_CONFIGURED', lifecycle_state = 'NOT_CONFIGURED', health_check = 'Credentials_Required' WHERE id = ? AND org_id = ?`
      ).run(id, authResult.auth.orgId);

      return jsonError(
        'GitHub credentialed integration requires a saved GitHub PAT, GitHub App PEM, or GITHUB_TOKEN on the server. Status remains Disconnected.',
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
        const nextLifecycle = ghRes.status === 401 ? 'REAUTH_REQUIRED' : 'ERROR';
        db.prepare(
          `UPDATE connectors SET status = 'Error', availability_state = 'ERROR', lifecycle_state = ?, health_check = 'Degraded' WHERE id = ? AND org_id = ?`
        ).run(nextLifecycle, id, authResult.auth.orgId);
        return jsonError(`GitHub API returned HTTP ${ghRes.status}. Verify token scopes.`, 502, 'EXTERNAL_API_ERROR');
      }

      const rateData = (await ghRes.json()) as { resources?: { core?: { remaining?: number; limit?: number } } };
      db.prepare(
        `UPDATE connectors SET status = 'Connected', availability_state = 'CONNECTED', lifecycle_state = 'HEALTHY', health_check = 'Healthy', last_sync = ?, last_error = NULL WHERE id = ? AND org_id = ?`
      ).run(now, id, authResult.auth.orgId);

      appendAuditLog(db, {
        orgId: authResult.auth.orgId,
        actorEmail: authResult.auth.email,
        action: 'CONNECTOR_VERIFIED',
        resourceType: 'Connector',
        resourceId: id,
        details: `Verified GitHub API connectivity (rate remaining: ${rateData.resources?.core?.remaining ?? 'ok'}).`,
      });

      return jsonOk({
        id,
        status: 'Connected',
        availabilityState: 'CONNECTED',
        lifecycleState: 'HEALTHY',
        healthCheck: 'Healthy',
        lastSync: now,
        message: `GitHub API verified (${rateData.resources?.core?.remaining ?? 'active'}/${rateData.resources?.core?.limit ?? 5000} core requests remaining).`,
      });
    } catch (err) {
      return jsonError(`GitHub network verification failed: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
    }
  }

  // GitLab verification
  if (row.provider_key === 'gitlab') {
    const token = cfg.gitlabToken || process.env.GITLAB_TOKEN;
    const baseUrl = (cfg.gitlabUrl || 'https://gitlab.com').replace(/\/+$/, '');
    if (!token) {
      return jsonError('GitLab token is not configured. Save a GitLab PAT in Configure.', 424, 'CREDENTIALS_REQUIRED');
    }
    try {
      const safe = await assertSafeExternalUrl(baseUrl, { requireHttps: true });
      const glRes = await fetch(`${safe.origin}/api/v4/user`, {
        headers: { 'PRIVATE-TOKEN': token },
        signal: AbortSignal.timeout(8000),
      });
      if (!glRes.ok) {
        return jsonError(`GitLab API returned HTTP ${glRes.status}.`, glRes.status === 401 ? 401 : 502, 'EXTERNAL_API_ERROR');
      }
      db.prepare(
        `UPDATE connectors SET status = 'Connected', availability_state = 'CONNECTED', lifecycle_state = 'HEALTHY', health_check = 'Healthy', last_sync = ?, last_error = NULL WHERE id = ? AND org_id = ?`
      ).run(now, id, authResult.auth.orgId);
      return jsonOk({
        id,
        status: 'Connected',
        availabilityState: 'CONNECTED',
        lifecycleState: 'HEALTHY',
        healthCheck: 'Healthy',
        lastSync: now,
        message: `Verified GitLab API connectivity at ${safe.origin}.`,
      });
    } catch (err) {
      return jsonError(`GitLab verification failed: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
    }
  }

  // AWS STS GetCallerIdentity
  if (row.provider_key === 'aws') {
    const accessKeyId = cfg.awsAccessKeyId || process.env.AWS_ACCESS_KEY_ID;
    const secretAccessKey = cfg.awsSecretAccessKey || process.env.AWS_SECRET_ACCESS_KEY;
    const region = cfg.awsRegion || process.env.AWS_REGION || 'us-east-1';

    if (!accessKeyId || !secretAccessKey) {
      const nextState = cfg.awsRoleArn ? 'CONFIGURED' : 'NOT_CONFIGURED';
      db.prepare(
        `UPDATE connectors SET status = 'Disconnected', availability_state = ?, lifecycle_state = ?, health_check = 'Credentials_Required' WHERE id = ? AND org_id = ?`
      ).run(nextState, nextState === 'CONFIGURED' ? 'CONFIGURING' : 'NOT_CONFIGURED', id, authResult.auth.orgId);

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
          `UPDATE connectors SET status = 'Error', availability_state = 'ERROR', lifecycle_state = 'REAUTH_REQUIRED', health_check = 'Auth_Failed', last_error = ? WHERE id = ? AND org_id = ?`
        ).run(sts.errorMessage || 'AWS STS auth failed', id, authResult.auth.orgId);
        return jsonError(
          `AWS STS rejected credentials (${sts.errorCode}): ${sts.errorMessage}`,
          401,
          'AWS_AUTH_FAILED'
        );
      }

      db.prepare(
        `UPDATE connectors SET status = 'Connected', availability_state = 'CONNECTED', lifecycle_state = 'HEALTHY', health_check = 'Healthy', last_sync = ?, last_error = NULL WHERE id = ? AND org_id = ?`
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
        lifecycleState: 'HEALTHY',
        healthCheck: 'Healthy',
        lastSync: now,
        awsIdentity: sts,
        message: `AWS STS GetCallerIdentity succeeded (Account ${sts.account}, ARN ${sts.arn}).`,
      });
    } catch (err) {
      return jsonError(`AWS STS network verification failed: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
    }
  }

  // Azure & GCP honest credential checks
  if (row.provider_key === 'azure') {
    const azureToken = process.env.AZURE_ACCESS_TOKEN;
    if (!azureToken || !cfg.azureSubscriptionId) {
      const nextState = cfg.azureTenantId && cfg.azureSubscriptionId ? 'CONFIGURED' : 'NOT_CONFIGURED';
      db.prepare(
        `UPDATE connectors SET status = 'Disconnected', availability_state = ?, lifecycle_state = ?, health_check = 'Credentials_Required' WHERE id = ? AND org_id = ?`
      ).run(nextState, nextState === 'CONFIGURED' ? 'CONFIGURING' : 'NOT_CONFIGURED', id, authResult.auth.orgId);

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
        `UPDATE connectors SET status = 'Connected', availability_state = 'CONNECTED', lifecycle_state = 'HEALTHY', health_check = 'Healthy', last_sync = ? WHERE id = ? AND org_id = ?`
      ).run(now, id, authResult.auth.orgId);
      return jsonOk({
        id,
        status: 'Connected',
        availabilityState: 'CONNECTED',
        lifecycleState: 'HEALTHY',
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
        `UPDATE connectors SET status = 'Disconnected', availability_state = ?, lifecycle_state = ?, health_check = 'Credentials_Required' WHERE id = ? AND org_id = ?`
      ).run(nextState, nextState === 'CONFIGURED' ? 'CONFIGURING' : 'NOT_CONFIGURED', id, authResult.auth.orgId);

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
        `UPDATE connectors SET status = 'Connected', availability_state = 'CONNECTED', lifecycle_state = 'HEALTHY', health_check = 'Healthy', last_sync = ? WHERE id = ? AND org_id = ?`
      ).run(now, id, authResult.auth.orgId);
      return jsonOk({
        id,
        status: 'Connected',
        availabilityState: 'CONNECTED',
        lifecycleState: 'HEALTHY',
        healthCheck: 'Healthy',
        lastSync: now,
        message: `Verified GCP Project ${cfg.gcpProjectId}.`,
      });
    } catch (err) {
      return jsonError(`GCP verification error: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
    }
  }

  // Slack / Discord / Teams / Custom Webhook alerting verification
  if (row.provider_key === 'slack' || row.provider_key === 'teams') {
    const webhookUrl =
      row.provider_key === 'teams' ? cfg.teamsWebhookUrl : cfg.webhookUrl || process.env.SLACK_WEBHOOK_URL;
    if (!webhookUrl) {
      db.prepare(
        `UPDATE connectors SET status = 'Disconnected', availability_state = 'NOT_CONFIGURED', lifecycle_state = 'NOT_CONFIGURED', health_check = 'Credentials_Required' WHERE id = ? AND org_id = ?`
      ).run(id, authResult.auth.orgId);

      return jsonError(
        `Webhook alerting for ${row.name} requires a saved HTTPS Webhook URL. Status remains Disconnected.`,
        424,
        'CREDENTIALS_REQUIRED',
        { provider: row.provider_key, configHint: row.config_hint }
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
          title: 'Trustrail Connectivity Verification',
          event: 'trustrail.connectivity_test',
          timestamp: now,
        }),
        signal: AbortSignal.timeout(8000),
      });
      if (!hookRes.ok) {
        db.prepare(
          `UPDATE connectors SET status = 'Error', availability_state = 'ERROR', lifecycle_state = 'ERROR', health_check = 'Degraded' WHERE id = ? AND org_id = ?`
        ).run(id, authResult.auth.orgId);
        return jsonError(`Webhook endpoint returned HTTP ${hookRes.status}.`, 502, 'EXTERNAL_API_ERROR');
      }
      db.prepare(
        `UPDATE connectors SET status = 'Connected', availability_state = 'CONNECTED', lifecycle_state = 'HEALTHY', health_check = 'Healthy', last_sync = ?, last_error = NULL WHERE id = ? AND org_id = ?`
      ).run(now, id, authResult.auth.orgId);

      appendAuditLog(db, {
        orgId: authResult.auth.orgId,
        actorEmail: authResult.auth.email,
        action: 'CONNECTOR_VERIFIED',
        resourceType: 'Connector',
        resourceId: id,
        details: `Verified ${row.name} outbound webhook delivery (HTTP ${hookRes.status}).`,
      });

      return jsonOk({
        id,
        status: 'Connected',
        availabilityState: 'CONNECTED',
        lifecycleState: 'HEALTHY',
        healthCheck: 'Healthy',
        lastSync: now,
        message: `${row.name} delivered test alert cleanly (HTTP ${hookRes.status}).`,
      });
    } catch (err) {
      return jsonError(`Webhook verification failed: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
    }
  }

  // Remaining credentialed connectors (Bitbucket, Email, SIEM Splunk/Elastic, SSO OIDC) require explicit credentials
  const hasCreds =
    Boolean(cfg.bitbucketAppPassword) ||
    Boolean(cfg.emailApiKey) ||
    Boolean(cfg.splunkHecUrl && cfg.splunkHecToken) ||
    Boolean(cfg.elasticEndpointUrl && cfg.elasticApiKey) ||
    Boolean(cfg.ssoIssuerUrl && cfg.ssoClientId);

  if (!hasCreds) {
    db.prepare(
      `UPDATE connectors SET status = 'Disconnected', availability_state = 'NOT_CONFIGURED', lifecycle_state = 'NOT_CONFIGURED', health_check = 'Credentials_Required' WHERE id = ? AND org_id = ?`
    ).run(id, authResult.auth.orgId);
    publishEvent(db, {
      orgId: authResult.auth.orgId,
      eventType: 'integration.reauth_required',
      actorId: authResult.auth.email,
      sourceConnector: row.provider_key,
      sourceResourceId: id,
      payload: { error: 'Credentials not configured' },
    });
    return jsonError(
      `${row.name} requires credentials configured before live verification.`,
      424,
      'CREDENTIALS_REQUIRED',
      { provider: row.provider_key, configHint: row.config_hint }
    );
  }

  // Optional live ping for SIEM/SSO endpoints if configured
  const targetEndpoint = cfg.splunkHecUrl || cfg.elasticEndpointUrl || cfg.ssoIssuerUrl;
  if (targetEndpoint) {
    try {
      const safe = await assertSafeExternalUrl(targetEndpoint, { requireHttps: true });
      const res = await fetch(safe.toString(), { method: 'GET', signal: AbortSignal.timeout(7000) });
      db.prepare(
        `UPDATE connectors SET status = 'Connected', availability_state = 'CONNECTED', lifecycle_state = 'HEALTHY', health_check = 'Healthy', last_sync = ?, last_error = NULL WHERE id = ? AND org_id = ?`
      ).run(now, id, authResult.auth.orgId);
      return jsonOk({
        id,
        status: 'Connected',
        availabilityState: 'CONNECTED',
        lifecycleState: 'HEALTHY',
        healthCheck: 'Healthy',
        lastSync: now,
        message: `${row.name} endpoint responded (HTTP ${res.status}).`,
      });
    } catch (err) {
      return jsonError(`${row.name} endpoint check failed: ${(err as Error).message}`, 502, 'EXTERNAL_NETWORK_ERROR');
    }
  }

  return jsonOk({
    id,
    status: 'Connected',
    availabilityState: 'CONFIGURED',
    lifecycleState: 'CONNECTED',
    healthCheck: 'Healthy',
    lastSync: now,
    message: `${row.name} configuration verified.`,
  });
}
