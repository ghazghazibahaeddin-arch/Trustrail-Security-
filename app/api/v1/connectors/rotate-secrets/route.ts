import { NextRequest } from 'next/server';
import { getDb, withDbTransaction, appendAuditLog } from '@/lib/db';
import { getActiveVaultKeyVersion, rotateSecretEnvelope } from '@/lib/security/vault';
import { jsonOk, requireAuth } from '@/lib/api-response';

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Admin');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const rows = db
    .prepare('SELECT id, config_json FROM connectors WHERE org_id = ? AND config_json IS NOT NULL')
    .all(authResult.auth.orgId) as Array<{ id: string; config_json: string }>;

  const targetVersion = getActiveVaultKeyVersion();
  let rotatedCount = 0;
  withDbTransaction(db, () => {
    for (const row of rows) {
      try {
        const result = rotateSecretEnvelope(row.config_json, targetVersion, {
          aad: `${authResult.auth.orgId}:${row.id}`,
        });
        if (result.rotatedEnvelope && result.rotatedEnvelope !== row.config_json) {
          db.prepare('UPDATE connectors SET config_json = ? WHERE id = ? AND org_id = ?').run(
            result.rotatedEnvelope,
            row.id,
            authResult.auth.orgId
          );
          rotatedCount += 1;
        }
      } catch {
        // Skip unrotatable/empty payloads safely
      }
    }

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'VAULT_SECRETS_ROTATED',
      resourceType: 'Vault',
      resourceId: authResult.auth.orgId,
      details: `Re-encrypted ${rotatedCount} connector credential envelopes under vault key version v${targetVersion}.`,
    });
  });

  return jsonOk({
    rotatedCount,
    activeKeyVersion: targetVersion,
  });
}
