import { NextRequest } from 'next/server';
import { getDb, ensureBuiltInConnectors } from '@/lib/db';
import { jsonOk, requireAuth } from '@/lib/api-response';
import { formatConnectorRow } from '@/lib/connectors/hub';
import { INTEGRATION_DEPENDENCY_MAP } from '@/lib/fabric/dependency-map';

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  ensureBuiltInConnectors(db, authResult.auth.orgId);

  const rows = db
    .prepare(
      `SELECT id, provider_key as providerKey, name, category, auth_type as authType,
              permissions_json as permissionsJson, missing_permissions_json as missingPermissionsJson,
              status, availability_state as availabilityState, lifecycle_state as lifecycleState,
              health_check as healthCheck, last_sync as lastSync, config_hint as configHint,
              config_json as configJson, sync_cursor as syncCursor,
              assets_discovered as assetsDiscovered, events_imported as eventsImported,
              failure_count as failureCount, last_error as lastError,
              credential_expires_at as credentialExpiresAt, owner_email as ownerEmail,
              data_direction as dataDirection
       FROM connectors WHERE org_id = ? ORDER BY id ASC`
    )
    .all(authResult.auth.orgId) as Array<Record<string, unknown>>;

  return jsonOk({
    connectors: rows.map((r) => formatConnectorRow(r, authResult.auth.orgId)),
    dependencyMap: INTEGRATION_DEPENDENCY_MAP,
  });
}
