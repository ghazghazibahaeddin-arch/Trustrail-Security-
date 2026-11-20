import { NextRequest, NextResponse } from 'next/server';
import { getDb, appendAuditLog } from '@/lib/db';
import { requireAuth } from '@/lib/api-response';
import { computeOrganizationSnapshot } from '@/lib/domain-mappers';

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const format = req.nextUrl.searchParams.get('format') || 'json';
  const db = getDb();
  const org = computeOrganizationSnapshot(db, authResult.auth.orgId);
  const controls = db
    .prepare(
      `SELECT id, framework, code, title, status, evidence_count as evidenceCount, last_verified as lastVerified, owner
       FROM compliance_controls WHERE org_id = ?`
    )
    .all(authResult.auth.orgId) as Array<{
    id: string;
    framework: string;
    code: string;
    title: string;
    status: string;
    evidenceCount: number;
    lastVerified: string;
    owner: string;
  }>;

  appendAuditLog(db, {
    orgId: authResult.auth.orgId,
    actorEmail: authResult.auth.email,
    action: 'COMPLIANCE_EVIDENCE_EXPORTED',
    resourceType: 'ComplianceReport',
    resourceId: authResult.auth.orgId,
    details: `Exported compliance audit bundle in ${format.toUpperCase()} format.`,
  });

  if (format === 'csv') {
    const header = 'ID,Framework,Code,Title,Status,EvidenceCount,LastVerified,Owner';
    const rows = controls.map((c) =>
      [c.id, c.framework, c.code, `"${c.title.replace(/"/g, '""')}"`, c.status, c.evidenceCount, c.lastVerified, `"${c.owner.replace(/"/g, '""')}"`].join(',')
    );
    const csv = [header, ...rows].join('\n');
    return new NextResponse(csv, {
      status: 200,
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="trustrail-compliance-${org?.slug || 'org'}.csv"`,
      },
    });
  }

  const bundle = {
    generatedAt: new Date().toISOString(),
    organization: org,
    controls,
  };

  return new NextResponse(JSON.stringify(bundle, null, 2), {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename="trustrail-compliance-${org?.slug || 'org'}.json"`,
    },
  });
}
