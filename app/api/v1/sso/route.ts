import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { sha256 } from '@/lib/security/crypto';

const SsoActionSchema = z.discriminatedUnion('action', [
  z.object({
    action: z.literal('configure_sso'),
    provider: z.enum(['oidc', 'saml', 'okta', 'entra']).default('oidc'),
    issuerUrl: z.string().url().optional(),
    clientId: z.string().min(2).max(160).optional(),
    metadataXmlOrUrl: z.string().max(20_000).optional(),
    domainHint: z.string().max(120).optional(),
    roleMapping: z.record(z.string(), z.enum(['Owner', 'Admin', 'Developer', 'Viewer'])).optional(),
    enabled: z.boolean().default(true),
  }),
  z.object({
    action: z.literal('issue_scim_token'),
    name: z.string().min(2).max(100),
  }),
  z.object({
    action: z.literal('revoke_scim_token'),
    tokenId: z.string().min(1),
  }),
]);

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer', 'read');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const ssoRow = db
    .prepare(
      `SELECT id, org_id as orgId, provider, issuer_url as issuerUrl, client_id as clientId,
              domain_hint as domainHint, role_mapping_json as roleMappingJson, enabled, updated_at as updatedAt
       FROM sso_configs WHERE org_id = ?`
    )
    .get(authResult.auth.orgId) as Record<string, unknown> | undefined;

  const scimTokens = db
    .prepare(
      `SELECT id, name, token_prefix as tokenPrefix, revoked, last_used_at as lastUsedAt, created_at as createdAt
       FROM scim_tokens WHERE org_id = ? ORDER BY created_at DESC`
    )
    .all(authResult.auth.orgId) as Array<Record<string, unknown>>;

  return jsonOk({
    ssoConfig: ssoRow
      ? {
          id: ssoRow.id,
          orgId: ssoRow.orgId,
          provider: ssoRow.provider,
          issuerUrl: ssoRow.issuerUrl,
          clientId: ssoRow.clientId,
          domainHint: ssoRow.domainHint,
          roleMapping: (() => {
            try {
              return JSON.parse(String(ssoRow.roleMappingJson || '{}')) as Record<string, string>;
            } catch {
              return {};
            }
          })(),
          enabled: Boolean(ssoRow.enabled),
          updatedAt: ssoRow.updatedAt,
        }
      : null,
    scimTokens: scimTokens.map((t) => ({ ...t, revoked: Boolean(t.revoked) })),
  });
}

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Admin', 'admin');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = SsoActionSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid SSO/SCIM request payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const now = new Date().toISOString();

  if (parsed.data.action === 'configure_sso') {
    const existing = db
      .prepare('SELECT id FROM sso_configs WHERE org_id = ?')
      .get(authResult.auth.orgId) as { id: string } | undefined;

    const id = existing?.id || `sso-${crypto.randomUUID().slice(0, 8)}`;
    const roleMappingJson = JSON.stringify(parsed.data.roleMapping || { admins: 'Admin', developers: 'Developer', viewers: 'Viewer' });

    if (existing) {
      db.prepare(
        `UPDATE sso_configs
         SET provider = ?, issuer_url = COALESCE(?, issuer_url), client_id = COALESCE(?, client_id),
             metadata_xml_or_url = COALESCE(?, metadata_xml_or_url), domain_hint = COALESCE(?, domain_hint),
             role_mapping_json = ?, enabled = ?, updated_at = ?
         WHERE org_id = ?`
      ).run(
        parsed.data.provider,
        parsed.data.issuerUrl || null,
        parsed.data.clientId || null,
        parsed.data.metadataXmlOrUrl || null,
        parsed.data.domainHint || null,
        roleMappingJson,
        parsed.data.enabled ? 1 : 0,
        now,
        authResult.auth.orgId
      );
    } else {
      db.prepare(
        `INSERT INTO sso_configs (id, org_id, provider, issuer_url, client_id, metadata_xml_or_url, domain_hint, role_mapping_json, enabled, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        id,
        authResult.auth.orgId,
        parsed.data.provider,
        parsed.data.issuerUrl || null,
        parsed.data.clientId || null,
        parsed.data.metadataXmlOrUrl || null,
        parsed.data.domainHint || null,
        roleMappingJson,
        parsed.data.enabled ? 1 : 0,
        now
      );
    }

    db.prepare(
      `UPDATE connectors
       SET status = ?, health_check = ?, availability_state = ?, lifecycle_state = ?, last_sync = ?
       WHERE org_id = ? AND provider_key = 'sso_oidc'`
    ).run(
      parsed.data.enabled ? 'Connected' : 'Disconnected',
      parsed.data.enabled ? 'Healthy' : 'Disabled',
      parsed.data.enabled ? 'READY' : 'NOT_CONFIGURED',
      parsed.data.enabled ? 'HEALTHY' : 'DISCONNECTED',
      now,
      authResult.auth.orgId
    );

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'SSO_CONFIG_UPDATED',
      resourceType: 'SsoConfig',
      resourceId: id,
      details: `Updated ${parsed.data.provider.toUpperCase()} SSO configuration (enabled=${parsed.data.enabled}).`,
    });

    return jsonOk({
      ssoConfig: {
        id,
        orgId: authResult.auth.orgId,
        provider: parsed.data.provider,
        issuerUrl: parsed.data.issuerUrl || null,
        clientId: parsed.data.clientId || null,
        domainHint: parsed.data.domainHint || null,
        roleMapping: JSON.parse(roleMappingJson) as Record<string, string>,
        enabled: parsed.data.enabled,
        updatedAt: now,
      },
    });
  }

  if (parsed.data.action === 'issue_scim_token') {
    const id = `scim-${crypto.randomUUID().slice(0, 8)}`;
    const rawToken = `tr_scim_${crypto.randomBytes(24).toString('hex')}`;
    const prefix = rawToken.slice(0, 15);
    db.prepare(
      `INSERT INTO scim_tokens (id, org_id, name, token_prefix, token_hash, revoked, created_at)
       VALUES (?, ?, ?, ?, ?, 0, ?)`
    ).run(id, authResult.auth.orgId, parsed.data.name.trim(), prefix, sha256(rawToken), now);

    appendAuditLog(db, {
      orgId: authResult.auth.orgId,
      actorEmail: authResult.auth.email,
      action: 'SCIM_TOKEN_ISSUED',
      resourceType: 'ScimToken',
      resourceId: id,
      details: `Issued SCIM 2.0 provisioning token "${parsed.data.name}" (${prefix}...).`,
    });

    return jsonOk(
      {
        scimToken: { id, name: parsed.data.name.trim(), tokenPrefix: prefix, revoked: false, createdAt: now },
        secret: rawToken,
      },
      201
    );
  }

  // revoke_scim_token
  const existingTok = db
    .prepare(`SELECT id FROM scim_tokens WHERE id = ? AND org_id = ?`)
    .get(parsed.data.tokenId, authResult.auth.orgId);
  if (!existingTok) {
    return jsonError('SCIM token not found.', 404, 'SCIM_TOKEN_NOT_FOUND');
  }
  db.prepare(`UPDATE scim_tokens SET revoked = 1 WHERE id = ? AND org_id = ?`).run(
    parsed.data.tokenId,
    authResult.auth.orgId
  );

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'SCIM_TOKEN_REVOKED',
    resourceType: 'ScimToken',
    resourceId: parsed.data.tokenId,
    details: `Revoked SCIM 2.0 provisioning token ${parsed.data.tokenId}.`,
  });

  return jsonOk({ id: parsed.data.tokenId, revoked: true });
}
