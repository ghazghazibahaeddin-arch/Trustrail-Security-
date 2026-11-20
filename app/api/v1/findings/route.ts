import { NextRequest } from 'next/server';
import { getDb } from '@/lib/db';
import { jsonOk, requireAuth } from '@/lib/api-response';
import { listEnrichedFindings } from '@/lib/domain-mappers';

export async function GET(req: NextRequest) {
  const authResult = requireAuth(req, 'Viewer');
  if ('error' in authResult) return authResult.error;

  const db = getDb();
  let items = listEnrichedFindings(db, authResult.auth.orgId);

  const severity = req.nextUrl.searchParams.get('severity');
  const category = req.nextUrl.searchParams.get('category');
  const status = req.nextUrl.searchParams.get('status');
  const projectId = req.nextUrl.searchParams.get('projectId');
  const q = req.nextUrl.searchParams.get('q')?.trim().toLowerCase();

  if (severity && severity !== 'ALL') {
    items = items.filter((f) => f.severity === severity);
  }
  if (category && category !== 'ALL') {
    items = items.filter((f) => f.category === category);
  }
  if (status && status !== 'ALL') {
    items = items.filter((f) => f.status === status);
  }
  if (projectId) {
    items = items.filter((f) => f.projectId === projectId);
  }
  if (q) {
    items = items.filter(
      (f) =>
        f.title.toLowerCase().includes(q) ||
        f.assetName.toLowerCase().includes(q) ||
        (f.cve && f.cve.toLowerCase().includes(q)) ||
        (f.filePath && f.filePath.toLowerCase().includes(q))
    );
  }

  return jsonOk({ findings: items, total: items.length });
}
