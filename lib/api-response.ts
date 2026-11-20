import { NextRequest, NextResponse } from 'next/server';
import { AuthContext, Role, authenticateRequest, hasMinRole } from '@/lib/security/auth';
import { checkRateLimit } from '@/lib/security/rate-limit';

export function jsonOk<T>(data: T, status = 200): NextResponse {
  return NextResponse.json(data, { status });
}

export function jsonError(
  message: string,
  status = 400,
  code = 'BAD_REQUEST',
  details?: unknown
): NextResponse {
  const payload: Record<string, unknown> = {
    error: message,
    code,
  };
  if (details !== undefined) {
    payload.details = details;
  }
  return NextResponse.json(payload, { status });
}

export function getClientIp(req: NextRequest): string {
  const fwd = req.headers.get('x-forwarded-for');
  if (fwd) return fwd.split(',')[0].trim();
  return req.headers.get('x-real-ip') || '127.0.0.1';
}

export function requireScope(auth: AuthContext, scope: string): NextResponse | null {
  if (auth.scopes.includes('admin') || auth.scopes.includes(scope)) {
    return null;
  }
  return jsonError(
    `API credential lacks required scope "${scope}".`,
    403,
    'INSUFFICIENT_SCOPE'
  );
}

export function requireAuth(
  req: NextRequest,
  minRole: Role = 'Viewer',
  requiredScope?: string
): { auth: AuthContext } | { error: NextResponse } {
  const ip = getClientIp(req);
  const rl = checkRateLimit(`api:${ip}:${req.nextUrl.pathname}`, 180, 60_000);
  if (!rl.allowed) {
    return {
      error: jsonError('Rate limit exceeded. Please retry later.', 429, 'RATE_LIMITED', {
        resetAt: new Date(rl.resetAt).toISOString(),
      }),
    };
  }

  const auth = authenticateRequest(req);
  if (!auth) {
    return { error: jsonError('Authentication required.', 401, 'UNAUTHORIZED') };
  }

  if (!hasMinRole(auth.role, minRole)) {
    return {
      error: jsonError(
        `Insufficient permissions: requires ${minRole} role (current role: ${auth.role}).`,
        403,
        'FORBIDDEN'
      ),
    };
  }

  if (requiredScope) {
    const scopeErr = requireScope(auth, requiredScope);
    if (scopeErr) return { error: scopeErr };
  }

  return { auth };
}

