import crypto from 'node:crypto';
import type { DatabaseSync } from 'node:sqlite';
import { appendAuditLog } from '@/lib/db';
import { maskConnectorConfig, parseConnectorConfig } from '@/lib/security/connector-config';
import { publishEvent } from '@/lib/fabric/event-bus';
import type { ConnectorLifecycleState, ConnectorSyncResult } from '@/lib/connectors/types';
import { queryMultiSourceVulnerabilityIntel } from '@/lib/integrations/intel-aggregator';

export function listSyncRunsForConnector(db: DatabaseSync, orgId: string, connectorId: string, limit = 15) {
  return db
    .prepare(
      `SELECT id, connector_id as connectorId, mode, status, assets_discovered as assetsDiscovered,
              events_imported as eventsImported, failures_count as failuresCount, cursor,
              error_message as errorMessage, started_at as startedAt, completed_at as completedAt
       FROM connector_sync_runs
       WHERE org_id = ? AND connector_id = ?
       ORDER BY started_at DESC LIMIT ?`
    )
    .all(orgId, connectorId, limit);
}

export async function runConnectorSync(
  db: DatabaseSync,
  orgId: string,
  connectorId: string,
  actorEmail: string,
  mode: 'initial' | 'incremental' | 'manual' = 'incremental'
): Promise<ConnectorSyncResult> {
  const row = db
    .prepare(
      `SELECT id, provider_key, name, status, availability_state, lifecycle_state, sync_cursor, config_json, assets_discovered, events_imported
       FROM connectors WHERE id = ? AND org_id = ?`
    )
    .get(connectorId, orgId) as
    | {
        id: string;
        provider_key: string;
        name: string;
        status: string;
        availability_state: string;
        lifecycle_state: string;
        sync_cursor: string | null;
        config_json: string | null;
        assets_discovered: number;
        events_imported: number;
      }
    | undefined;

  if (!row) {
    throw new Error('Connector not found.');
  }

  const runId = `sync-${crypto.randomUUID().slice(0, 8)}`;
  const startedAt = new Date().toISOString();
  const initialLifecycle: ConnectorLifecycleState = mode === 'initial' ? 'INITIAL_SYNC' : 'SYNCHRONIZING';

  db.prepare(
    `INSERT INTO connector_sync_runs (id, org_id, connector_id, mode, status, assets_discovered, events_imported, failures_count, cursor, started_at)
     VALUES (?, ?, ?, ?, 'Running', 0, 0, 0, ?, ?)`
  ).run(runId, orgId, connectorId, mode, row.sync_cursor, startedAt);

  db.prepare(`UPDATE connectors SET lifecycle_state = ? WHERE id = ? AND org_id = ?`).run(
    initialLifecycle,
    connectorId,
    orgId
  );

  const cfg = parseConnectorConfig(row.config_json, { orgId, connectorId });
  let assetsDiscovered = 0;
  let eventsImported = 0;
  let failuresCount = 0;
  let errorMessage: string | null = null;
  let nextCursor = row.sync_cursor || `cursor-${Date.now()}`;
  let finalLifecycle: ConnectorLifecycleState = 'HEALTHY';

  try {
    if (row.provider_key === 'github') {
      const token = cfg.githubToken || process.env.GITHUB_TOKEN;
      if (!token && !cfg.defaultRepo) {
        throw new Error('GitHub sync requires a configured GitHub PAT/App token or default repository.');
      }
      const headers: Record<string, string> = {
        Accept: 'application/vnd.github+json',
        'User-Agent': 'Trustrail-Security-Cloud',
      };
      if (token) headers.Authorization = `Bearer ${token}`;

      if (token) {
        const reposRes = await fetch('https://api.github.com/user/repos?per_page=10&sort=updated', {
          headers,
          signal: AbortSignal.timeout(8000),
        });
        if (!reposRes.ok) {
          throw new Error(`GitHub repo sync returned HTTP ${reposRes.status}`);
        }
        const repos = (await reposRes.json()) as Array<{ full_name: string }>;
        assetsDiscovered = repos.length;
        eventsImported = repos.length;
        nextCursor = `gh-${new Date().toISOString()}`;
      } else if (cfg.defaultRepo) {
        const rRes = await fetch(`https://api.github.com/repos/${cfg.defaultRepo}`, {
          headers,
          signal: AbortSignal.timeout(8000),
        });
        if (!rRes.ok) throw new Error(`GitHub repo lookup returned HTTP ${rRes.status}`);
        assetsDiscovered = 1;
        eventsImported = 1;
        nextCursor = `gh-public-${new Date().toISOString()}`;
      }
    } else if (row.provider_key === 'gitlab') {
      const baseUrl = (cfg.gitlabUrl || 'https://gitlab.com').replace(/\/+$/, '');
      if (!cfg.gitlabToken) throw new Error('GitLab access token is not configured.');
      const glRes = await fetch(`${baseUrl}/api/v4/projects?membership=true&per_page=10`, {
        headers: { 'PRIVATE-TOKEN': cfg.gitlabToken },
        signal: AbortSignal.timeout(8000),
      });
      if (!glRes.ok) throw new Error(`GitLab API returned HTTP ${glRes.status}`);
      const projects = (await glRes.json()) as Array<{ path_with_namespace: string }>;
      assetsDiscovered = projects.length;
      eventsImported = projects.length;
      nextCursor = `gl-${new Date().toISOString()}`;
    } else if (row.provider_key === 'nvd_kev_epss' || row.provider_key === 'osv') {
      const openCves = (
        db
          .prepare(`SELECT DISTINCT cve FROM findings WHERE org_id = ? AND cve IS NOT NULL LIMIT 5`)
          .all(orgId) as Array<{ cve: string }>
      ).map((r) => r.cve);

      const intel = await queryMultiSourceVulnerabilityIntel(db, {
        cveIds: openCves.length > 0 ? openCves : ['CVE-2021-23337'],
      });
      assetsDiscovered = intel.cveResults.length;
      eventsImported = intel.cveResults.reduce((sum, item) => sum + item.sources.length, 0);
      nextCursor = `intel-${new Date().toISOString()}`;
    } else if (row.provider_key === 'terraform' || row.provider_key === 'oci' || row.provider_key === 'kubernetes' || row.provider_key === 'http_probe' || row.provider_key === 'kms_vault') {
      const countRow = db
        .prepare('SELECT COUNT(*) as cnt FROM assets WHERE org_id = ?')
        .get(orgId) as { cnt: number };
      assetsDiscovered = countRow?.cnt || 0;
      eventsImported = 1;
      nextCursor = `local-${new Date().toISOString()}`;
    } else {
      throw new Error(`Live incremental sync for "${row.name}" requires active provider credentials.`);
    }

    const completedAt = new Date().toISOString();
    db.prepare(
      `UPDATE connector_sync_runs
       SET status = 'Completed', assets_discovered = ?, events_imported = ?, failures_count = 0, cursor = ?, completed_at = ?
       WHERE id = ?`
    ).run(assetsDiscovered, eventsImported, nextCursor, completedAt, runId);

    db.prepare(
      `UPDATE connectors
       SET status = 'Connected',
           lifecycle_state = 'HEALTHY',
           health_check = 'Healthy',
           last_sync = ?,
           sync_cursor = ?,
           assets_discovered = assets_discovered + ?,
           events_imported = events_imported + ?,
           last_error = NULL
       WHERE id = ? AND org_id = ?`
    ).run(completedAt, nextCursor, assetsDiscovered, eventsImported, connectorId, orgId);

    publishEvent(db, {
      orgId,
      eventType: 'integration.connected',
      actorId: actorEmail,
      sourceConnector: row.provider_key,
      sourceResourceId: connectorId,
      payload: { mode, runId, assetsDiscovered, eventsImported, cursor: nextCursor },
      idempotencyKey: `sync-ok-${runId}`,
    });

    appendAuditLog(db, {
      orgId,
      actorEmail,
      action: 'CONNECTOR_SYNC_COMPLETED',
      resourceType: 'Connector',
      resourceId: connectorId,
      details: `Synced ${row.name} (${mode}): ${assetsDiscovered} assets, ${eventsImported} events.`,
    });

    return {
      runId,
      connectorId,
      providerKey: row.provider_key,
      mode,
      status: 'Completed',
      assetsDiscovered,
      eventsImported,
      failuresCount: 0,
      cursor: nextCursor,
      errorMessage: null,
      lifecycleState: finalLifecycle,
      startedAt,
      completedAt,
    };
  } catch (err) {
    failuresCount = 1;
    errorMessage = (err as Error).message;
    const isAuthErr = /401|403|token|credentials|not configured/i.test(errorMessage);
    finalLifecycle = isAuthErr ? 'REAUTH_REQUIRED' : 'ERROR';
    const completedAt = new Date().toISOString();

    db.prepare(
      `UPDATE connector_sync_runs
       SET status = 'Failed', failures_count = 1, error_message = ?, completed_at = ?
       WHERE id = ?`
    ).run(errorMessage, completedAt, runId);

    db.prepare(
      `UPDATE connectors
       SET status = ?, lifecycle_state = ?, health_check = ?, failure_count = failure_count + 1, last_error = ?
       WHERE id = ? AND org_id = ?`
    ).run(
      isAuthErr ? 'Disconnected' : 'Error',
      finalLifecycle,
      isAuthErr ? 'Credentials_Required' : 'Degraded',
      errorMessage,
      connectorId,
      orgId
    );

    publishEvent(db, {
      orgId,
      eventType: isAuthErr ? 'integration.reauth_required' : 'integration.failed',
      actorId: actorEmail,
      sourceConnector: row.provider_key,
      sourceResourceId: connectorId,
      payload: { runId, mode, error: errorMessage },
      idempotencyKey: `sync-fail-${runId}`,
    });

    return {
      runId,
      connectorId,
      providerKey: row.provider_key,
      mode,
      status: 'Failed',
      assetsDiscovered: 0,
      eventsImported: 0,
      failuresCount,
      cursor: row.sync_cursor,
      errorMessage,
      lifecycleState: finalLifecycle,
      startedAt,
      completedAt,
    };
  }
}

export function deleteConnectorData(
  db: DatabaseSync,
  orgId: string,
  connectorId: string,
  actorEmail: string,
  purgeConfig = true
) {
  const row = db
    .prepare('SELECT id, name, provider_key FROM connectors WHERE id = ? AND org_id = ?')
    .get(connectorId, orgId) as { id: string; name: string; provider_key: string } | undefined;

  if (!row) throw new Error('Connector not found.');

  const delRuns = db
    .prepare('DELETE FROM connector_sync_runs WHERE connector_id = ? AND org_id = ?')
    .run(connectorId, orgId);

  let deletedCloud = 0;
  if (['aws', 'azure', 'gcp'].includes(row.provider_key)) {
    const res = db
      .prepare('DELETE FROM cloud_resources WHERE org_id = ? AND provider = ?')
      .run(orgId, row.provider_key);
    deletedCloud = Number(res.changes || 0);
  }

  db.prepare(
    `UPDATE connectors
     SET status = 'Disconnected',
         availability_state = 'NOT_CONFIGURED',
         lifecycle_state = 'DISCONNECTED',
         health_check = 'Offline',
         sync_cursor = NULL,
         assets_discovered = 0,
         events_imported = 0,
         last_error = NULL,
         config_json = CASE WHEN ? = 1 THEN NULL ELSE config_json END
     WHERE id = ? AND org_id = ?`
  ).run(purgeConfig ? 1 : 0, connectorId, orgId);

  appendAuditLog(db, {
    orgId,
    actorEmail,
    action: 'CONNECTOR_DATA_DELETED',
    resourceType: 'Connector',
    resourceId: connectorId,
    details: `Disconnected and purged synced state for ${row.name} (syncRuns=${Number(delRuns.changes || 0)}, cloudResources=${deletedCloud}, purgeConfig=${purgeConfig}).`,
  });

  return {
    connectorId,
    deletedSyncRuns: Number(delRuns.changes || 0),
    deletedCloudResources: deletedCloud,
    clearedCredentials: purgeConfig,
  };
}

export function formatConnectorRow(r: Record<string, unknown>, orgId: string) {
  const { configJson, permissionsJson, missingPermissionsJson, ...safeRow } = r;
  let permissions: string[] = [];
  let missingPermissions: string[] = [];
  try {
    permissions = JSON.parse(String(permissionsJson || '[]')) as string[];
  } catch {
    permissions = [];
  }
  try {
    missingPermissions = JSON.parse(String(missingPermissionsJson || '[]')) as string[];
  } catch {
    missingPermissions = [];
  }

  return {
    ...safeRow,
    permissions,
    missingPermissions,
    config: maskConnectorConfig(typeof configJson === 'string' ? configJson : null, {
      orgId,
      connectorId: String(r.id),
    }),
  };
}
