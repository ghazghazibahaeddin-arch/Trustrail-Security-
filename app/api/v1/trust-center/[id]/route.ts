import { NextRequest } from 'next/server';
import { getDb } from '@/lib/db';
import { jsonError, jsonOk } from '@/lib/api-response';
import { computeOrganizationSnapshot } from '@/lib/domain-mappers';

export async function GET(
  _req: NextRequest,
  context: { params: Promise<{ id: string }> }
) {
  const { id } = await context.params;
  const db = getDb();

  const row = db
    .prepare(
      `SELECT id, org_id, title, issued_at, expires_at, scope_json, signature, revoked, access_count
       FROM trust_receipts WHERE id = ?`
    )
    .get(id) as
    | {
        id: string;
        org_id: string;
        title: string;
        issued_at: string;
        expires_at: string;
        scope_json: string;
        signature: string;
        revoked: number;
        access_count: number;
      }
    | undefined;

  if (!row) {
    return jsonError('Trust Passport not found.', 404, 'NOT_FOUND');
  }

  if (row.revoked) {
    return jsonError('This Trust Passport has been revoked by the issuing organization.', 410, 'PASSPORT_REVOKED');
  }

  const today = new Date().toISOString().slice(0, 10);
  if (row.expires_at < today) {
    return jsonError('This Trust Passport has expired.', 410, 'PASSPORT_EXPIRED');
  }

  db.prepare('UPDATE trust_receipts SET access_count = access_count + 1 WHERE id = ?').run(id);

  const org = computeOrganizationSnapshot(db, row.org_id);
  const verifiedControls = db
    .prepare(
      `SELECT framework, code, title, status, last_verified as lastVerified
       FROM compliance_controls WHERE org_id = ? AND status = 'Verified'`
    )
    .all(row.org_id);

  // Publicly shared sanitized posture ONLY — zero internal code, zero secrets, zero raw vulnerabilities
  return jsonOk({
    passport: {
      id: row.id,
      title: row.title,
      organizationName: org?.name || 'Organization',
      securityRating: org?.securityRating || 'A',
      compliancePercentage: org?.compliancePercentage ?? 0,
      issuedAt: row.issued_at,
      expiresAt: row.expires_at,
      scope: JSON.parse(row.scope_json || '[]') as string[],
      signature: row.signature,
      accessCount: row.access_count + 1,
      verifiedControls,
    },
  });
}
