import { NextRequest } from 'next/server';
import { getDb, ensureBuiltInConnectors } from '@/lib/db';
import { jsonOk, requireAuth } from '@/lib/api-response';
import { maskConnectorConfig } from '@/lib/security/connector-config';

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  ensureBuiltInConnectors(db, authResult.auth.orgId);

  const rows = db
    .prepare(
      `SELECT id, provider_key as providerKey, name, category, auth_type as authType,
              permissions_json as permissionsJson, status, availability_state as availabilityState,
              health_check as healthCheck, last_sync as lastSync, config_hint as configHint,
              config_json as configJson
       FROM connectors WHERE org_id = ?`
    )
    .all(authResult.auth.orgId) as Array<Record<string, unknown>>;

  return jsonOk({
    connectors: rows.map((r) => {
      const { configJson, ...safeRow } = r;
      return {
        ...safeRow,
        permissions: JSON.parse(String(r.permissionsJson || '[]')) as string[],
        config: maskConnectorConfig(typeof configJson === 'string' ? configJson : null, {
          orgId: authResult.auth.orgId,
          connectorId: String(r.id),
        }),
      };
    }),
  });
}

