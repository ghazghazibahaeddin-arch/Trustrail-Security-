import crypto from 'node:crypto';
import { NextRequest } from 'next/server';
import { z } from 'zod';
import { getDb, appendAuditLog } from '@/lib/db';
import { jsonError, jsonOk, requireAuth } from '@/lib/api-response';
import { scanTerraformAndIaC } from '@/lib/engines/scanner-engine';
import { computeOrganizationSnapshot } from '@/lib/domain-mappers';
import { publishEvent } from '@/lib/fabric/event-bus';

const IngestCloudPostureSchema = z.object({
  provider: z.enum(['aws', 'azure', 'gcp']).default('aws'),
  accountId: z.string().min(3).max(80),
  region: z.string().min(2).max(40).default('us-east-1'),
  resources: z
    .array(
      z.object({
        resourceType: z.string().min(2).max(100),
        resourceArn: z.string().min(3).max(240),
        exposure: z.enum(['Public', 'Internal', 'Private']).default('Internal'),
        publicAccessBlock: z.boolean().optional(),
        encryptionEnabled: z.boolean().optional(),
        openPorts: z.array(z.number().int()).optional(),
        wildcardPermissions: z.boolean().optional(),
      })
    )
    .optional(),
  terraformPlanJson: z.string().max(250_000).optional(),
});

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer', 'read');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  const rows = db
    .prepare(
      `SELECT id, org_id as orgId, provider, account_id as accountId, resource_type as resourceType,
              resource_arn as resourceArn, region, exposure, compliant, details_json as detailsJson,
              collected_at as collectedAt
       FROM cloud_resources WHERE org_id = ? ORDER BY collected_at DESC`
    )
    .all(authResult.auth.orgId) as Array<Record<string, unknown>>;

  return jsonOk({
    resources: rows.map((r) => {
      const { detailsJson, ...rest } = r;
      let details: Record<string, unknown> = {};
      try {
        details = JSON.parse(String(detailsJson || '{}')) as Record<string, unknown>;
      } catch {
        details = {};
      }
      return {
        ...rest,
        compliant: Boolean(r.compliant),
        details,
      };
    }),
  });
}

export async function POST(req: NextRequest) {
  const authResult = requireAuth(req, 'Developer', 'scan');
  if ('error' in authResult) return authResult.error;

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return jsonError('Invalid JSON payload.', 400, 'INVALID_JSON');
  }

  const parsed = IngestCloudPostureSchema.safeParse(body);
  if (!parsed.success) {
    return jsonError('Invalid cloud posture payload.', 400, 'VALIDATION_ERROR', parsed.error.flatten());
  }

  const db = getDb();
  const now = new Date().toISOString();
  let evaluatedCount = 0;
  let nonCompliantCount = 0;
  let newFindingsCount = 0;

  if (parsed.data.resources) {
    for (const res of parsed.data.resources) {
      evaluatedCount += 1;
      const issues: string[] = [];
      if (res.exposure === 'Public' && res.publicAccessBlock === false) {
        issues.push('Public storage or network endpoint lacks Public Access Block.');
      }
      if (res.encryptionEnabled === false) {
        issues.push('At-rest KMS/AES-256 encryption is disabled.');
      }
      if (res.openPorts && (res.openPorts.includes(22) || res.openPorts.includes(3389)) && res.exposure === 'Public') {
        issues.push('Management port (22/3389) exposed publicly.');
      }
      if (res.wildcardPermissions) {
        issues.push('Over-privileged wildcard IAM permissions detected.');
      }

      const compliant = issues.length === 0;
      if (!compliant) nonCompliantCount += 1;

      db.prepare(
        `INSERT INTO cloud_resources (id, org_id, provider, account_id, resource_type, resource_arn, region, exposure, compliant, details_json, collected_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).run(
        `cres-${crypto.randomUUID().slice(0, 8)}`,
        authResult.auth.orgId,
        parsed.data.provider,
        parsed.data.accountId,
        res.resourceType,
        res.resourceArn,
        parsed.data.region,
        res.exposure,
        compliant ? 1 : 0,
        JSON.stringify({ issues, publicAccessBlock: res.publicAccessBlock, encryptionEnabled: res.encryptionEnabled }),
        now
      );

      if (!compliant) {
        const fp = crypto
          .createHash('sha256')
          .update(`cloud|${parsed.data.provider}|${res.resourceArn}|${issues[0]}`)
          .digest('hex')
          .slice(0, 16);
        const existing = db
          .prepare('SELECT id FROM findings WHERE org_id = ? AND fingerprint = ?')
          .get(authResult.auth.orgId, fp);
        if (!existing) {
          newFindingsCount += 1;
          db.prepare(
            `INSERT INTO findings (id, org_id, project_id, asset_id, fingerprint, title, severity, category, scanner, asset_name, file_path, line, cve, cvss, exploitability, status, evidence, suggested_fix, assigned_owner, discovered_at)
             VALUES (?, ?, NULL, NULL, ?, ?, ?, 'CLOUD', 'trustrail-cspm-evaluator', ?, NULL, NULL, NULL, ?, 'High', 'Open', ?, ?, ?, ?)`
          ).run(
            `finding-${crypto.randomUUID().slice(0, 8)}`,
            authResult.auth.orgId,
            fp,
            `${parsed.data.provider.toUpperCase()} CSPM Drift: ${res.resourceType} (${res.resourceArn.split('/').pop()})`,
            res.exposure === 'Public' || res.wildcardPermissions ? 'CRITICAL' : 'HIGH',
            res.resourceArn,
            res.exposure === 'Public' ? 9.1 : 7.8,
            issues.join(' '),
            'Enforce least-privilege IAM, private ACLs, and KMS at-rest encryption on the cloud resource.',
            authResult.auth.name,
            now
          );
        }
      }
    }
  }

  if (parsed.data.terraformPlanJson) {
    const iac = scanTerraformAndIaC(parsed.data.terraformPlanJson, `cloud-${parsed.data.provider}`);
    evaluatedCount += iac.resourcesEvaluated;
    for (const f of iac.findings) {
      nonCompliantCount += 1;
      const existing = db
        .prepare('SELECT id FROM findings WHERE org_id = ? AND fingerprint = ?')
        .get(authResult.auth.orgId, f.fingerprint);
      if (!existing) {
        newFindingsCount += 1;
        db.prepare(
          `INSERT INTO findings (id, org_id, project_id, asset_id, fingerprint, title, severity, category, scanner, asset_name, file_path, line, cve, cvss, exploitability, status, evidence, suggested_fix, assigned_owner, discovered_at)
           VALUES (?, ?, NULL, NULL, ?, ?, ?, 'CLOUD', ?, ?, ?, NULL, NULL, ?, ?, 'Open', ?, ?, ?, ?)`
        ).run(
          `finding-${crypto.randomUUID().slice(0, 8)}`,
          authResult.auth.orgId,
          f.fingerprint,
          f.title,
          f.severity,
          f.scanner,
          `${parsed.data.provider}:${parsed.data.accountId}`,
          f.filePath || 'terraform.tfplan.json',
          f.cvss,
          f.exploitability,
          f.evidence,
          f.suggestedFix,
          authResult.auth.name,
          now
        );
      }
    }
  }

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'CLOUD_POSTURE_EVALUATED',
    resourceType: 'CloudAccount',
    resourceId: `${parsed.data.provider}:${parsed.data.accountId}`,
    details: `Evaluated ${evaluatedCount} cloud resources (${nonCompliantCount} non-compliant, ${newFindingsCount} new findings).`,
  });

  publishEvent(db, {
    orgId: authResult.auth.orgId,
    eventType: nonCompliantCount > 0 ? 'state.drift_detected' : 'cloud.resource.discovered',
    actorId: authResult.auth.email,
    sourceConnector: parsed.data.provider,
    sourceResourceId: `${parsed.data.provider}:${parsed.data.accountId}`,
    payload: {
      provider: parsed.data.provider,
      accountId: parsed.data.accountId,
      region: parsed.data.region,
      evaluatedCount,
      nonCompliantCount,
      newFindingsCount,
    },
  });

  return jsonOk(
    {
      evaluatedCount,
      nonCompliantCount,
      newFindingsCount,
      organization: computeOrganizationSnapshot(db, authResult.auth.orgId),
    },
    201
  );
}
