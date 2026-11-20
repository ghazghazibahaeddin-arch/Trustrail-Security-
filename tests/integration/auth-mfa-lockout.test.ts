import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { NextRequest } from 'next/server';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { closeDbForTests, getDb } from '@/lib/db';
import { generateTotpCode } from '@/lib/security/crypto';

import * as RegisterRoute from '@/app/api/v1/auth/register/route';
import * as VerifyEmailRoute from '@/app/api/v1/auth/verify-email/route';
import * as LoginRoute from '@/app/api/v1/auth/login/route';
import * as LogoutRoute from '@/app/api/v1/auth/logout/route';
import * as RefreshRoute from '@/app/api/v1/auth/refresh/route';
import * as ForgotPasswordRoute from '@/app/api/v1/auth/forgot-password/route';
import * as ResetPasswordRoute from '@/app/api/v1/auth/reset-password/route';
import * as MfaSetupRoute from '@/app/api/v1/auth/mfa/setup/route';
import * as MfaVerifyRoute from '@/app/api/v1/auth/mfa/verify/route';
import * as OrgsRoute from '@/app/api/v1/organizations/route';
import * as TeamRoute from '@/app/api/v1/team/route';
import * as ApiKeysRoute from '@/app/api/v1/api-keys/route';
import * as ApiKeyRotateRoute from '@/app/api/v1/api-keys/[id]/rotate/route';
import * as ProjectsRoute from '@/app/api/v1/projects/route';
import * as ScansRoute from '@/app/api/v1/scans/route';

let tempDbPath = '';

function makeReq(
  url: string,
  opts: { method?: string; token?: string; apiKey?: string; body?: unknown; ip?: string } = {}
) {
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'x-forwarded-for': opts.ip || '198.51.100.42',
  };
  if (opts.token) headers.authorization = `Bearer ${opts.token}`;
  if (opts.apiKey) headers['x-api-key'] = opts.apiKey;
  return new NextRequest(`http://127.0.0.1:3000${url}`, {
    method: opts.method || 'GET',
    headers,
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
}

beforeAll(() => {
  closeDbForTests();
  tempDbPath = path.join(os.tmpdir(), `trustrail-auth-int-${crypto.randomUUID()}.db`);
  process.env.TRUSTRAIL_DB_PATH = tempDbPath;
  getDb();
});

afterAll(() => {
  closeDbForTests();
  delete process.env.TRUSTRAIL_DB_PATH;
  for (const suffix of ['', '-wal', '-shm']) {
    if (fs.existsSync(`${tempDbPath}${suffix}`)) {
      fs.rmSync(`${tempDbPath}${suffix}`, { force: true });
    }
  }
});

describe('Auth Lifecycle: Email Verify, Brute-Force Lockout, Password Reset, TOTP MFA, JWT Revocation, Account Disable & API Key Scopes', () => {
  it('completes registration email verification and enforces single-use token replay protection', async () => {
    const regRes = await RegisterRoute.POST(
      makeReq('/api/v1/auth/register', {
        method: 'POST',
        body: {
          email: 'founder@sentinel-ops.io',
          name: 'Mira Patel',
          password: 'InitialPassword!2026',
          organizationName: 'Sentinel Ops Security',
          edition: 'smb',
        },
      })
    );
    expect(regRes.status).toBe(201);
    const regJson = (await regRes.json()) as {
      token: string;
      verificationTokenPreview: string;
      user: { emailVerified: boolean };
    };
    expect(regJson.user.emailVerified).toBe(false);
    expect(regJson.verificationTokenPreview).toBeTruthy();

    const verifyRes = await VerifyEmailRoute.POST(
      makeReq('/api/v1/auth/verify-email', {
        method: 'POST',
        body: { token: regJson.verificationTokenPreview },
      })
    );
    expect(verifyRes.status).toBe(200);
    const verifyJson = (await verifyRes.json()) as { verified: boolean; emailVerified: boolean };
    expect(verifyJson.verified).toBe(true);
    expect(verifyJson.emailVerified).toBe(true);

    // Replaying single-use verification token must fail
    const replayRes = await VerifyEmailRoute.POST(
      makeReq('/api/v1/auth/verify-email', {
        method: 'POST',
        body: { token: regJson.verificationTokenPreview },
      })
    );
    expect(replayRes.status).toBe(400);
  });

  it('locks account after 5 failed logins (429 ACCOUNT_LOCKED) and clears lockout via forgot/reset password flow', async () => {
    const email = 'founder@sentinel-ops.io';
    for (let i = 1; i <= 4; i++) {
      const failRes = await LoginRoute.POST(
        makeReq('/api/v1/auth/login', {
          method: 'POST',
          body: { email, password: `WrongPassword!${i}` },
        })
      );
      expect(failRes.status).toBe(401);
    }

    // 5th consecutive failed attempt locks the account
    const fifthFail = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email, password: 'WrongPassword!5' },
      })
    );
    expect(fifthFail.status).toBe(429);
    const fifthJson = (await fifthFail.json()) as { code: string };
    expect(fifthJson.code).toBe('ACCOUNT_LOCKED');

    // Even the correct password is blocked while locked
    const lockedGoodAttempt = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email, password: 'InitialPassword!2026' },
      })
    );
    expect(lockedGoodAttempt.status).toBe(429);

    // Forgot password issues single-use reset token; Reset clears lockout and updates password
    const forgotRes = await ForgotPasswordRoute.POST(
      makeReq('/api/v1/auth/forgot-password', {
        method: 'POST',
        body: { email },
      })
    );
    expect(forgotRes.status).toBe(200);
    const forgotJson = (await forgotRes.json()) as { resetTokenPreview: string };
    expect(forgotJson.resetTokenPreview).toBeTruthy();

    const resetRes = await ResetPasswordRoute.POST(
      makeReq('/api/v1/auth/reset-password', {
        method: 'POST',
        body: {
          token: forgotJson.resetTokenPreview,
          newPassword: 'RotatedPassword!2026',
        },
      })
    );
    expect(resetRes.status).toBe(200);

    const unlockedLogin = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email, password: 'RotatedPassword!2026' },
      })
    );
    expect(unlockedLogin.status).toBe(200);
  });

  it('enforces TOTP MFA login challenges, JWT logout revocation, and session token rotation', async () => {
    const email = 'founder@sentinel-ops.io';
    const password = 'RotatedPassword!2026';

    const loginRes = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', { method: 'POST', body: { email, password } })
    );
    expect(loginRes.status).toBe(200);
    const { token: initialToken } = (await loginRes.json()) as { token: string };

    // Enroll TOTP MFA
    const setupRes = await MfaSetupRoute.POST(
      makeReq('/api/v1/auth/mfa/setup', { method: 'POST', token: initialToken })
    );
    expect(setupRes.status).toBe(200);
    const setupJson = (await setupRes.json()) as { secret: string; otpauthUri: string };
    expect(setupJson.secret).toBeTruthy();

    const code = generateTotpCode(setupJson.secret);
    const verifyMfaRes = await MfaVerifyRoute.POST(
      makeReq('/api/v1/auth/mfa/verify', {
        method: 'POST',
        token: initialToken,
        body: { code },
      })
    );
    expect(verifyMfaRes.status).toBe(200);

    // Login without mfaCode must fail with 401 MFA_REQUIRED
    const noMfaLogin = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', { method: 'POST', body: { email, password } })
    );
    expect(noMfaLogin.status).toBe(401);
    expect(((await noMfaLogin.json()) as { code: string }).code).toBe('MFA_REQUIRED');

    // Login with invalid mfaCode must fail with 401 INVALID_MFA_CODE
    const badMfaCode = code === '000000' ? '111111' : '000000';
    const badMfaLogin = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', { method: 'POST', body: { email, password, mfaCode: badMfaCode } })
    );
    expect(badMfaLogin.status).toBe(401);
    expect(((await badMfaLogin.json()) as { code: string }).code).toBe('INVALID_MFA_CODE');

    // Login with valid mfaCode succeeds
    const validMfaLogin = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', { method: 'POST', body: { email, password, mfaCode: code } })
    );
    expect(validMfaLogin.status).toBe(200);
    const { token: mfaToken } = (await validMfaLogin.json()) as { token: string };

    // Refresh rotates JWT and revokes prior jti
    const refreshRes = await RefreshRoute.POST(
      makeReq('/api/v1/auth/refresh', { method: 'POST', token: mfaToken })
    );
    expect(refreshRes.status).toBe(200);
    const { token: rotatedToken } = (await refreshRes.json()) as { token: string };
    expect(rotatedToken).not.toBe(mfaToken);

    const oldTokenCheck = await OrgsRoute.GET(
      makeReq('/api/v1/organizations', { token: mfaToken })
    );
    expect(oldTokenCheck.status).toBe(401);

    const newTokenCheck = await OrgsRoute.GET(
      makeReq('/api/v1/organizations', { token: rotatedToken })
    );
    expect(newTokenCheck.status).toBe(200);

    // Logout explicitly revokes active JWT jti
    const logoutRes = await LogoutRoute.POST(
      makeReq('/api/v1/auth/logout', { method: 'POST', token: rotatedToken })
    );
    expect(logoutRes.status).toBe(200);

    const afterLogoutCheck = await OrgsRoute.GET(
      makeReq('/api/v1/organizations', { token: rotatedToken })
    );
    expect(afterLogoutCheck.status).toBe(401);
  });

  it('blocks disabled user accounts across both active sessions and new logins, and enforces API key scopes + rotation', async () => {
    const adminLogin = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email: 'sarah@acme.cloud', password: 'Trustrail!2026' },
      })
    );
    expect(adminLogin.status).toBe(200);
    const { token: adminToken } = (await adminLogin.json()) as { token: string };

    const devLogin = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email: 'alex@acme.cloud', password: 'Trustrail!2026' },
      })
    );
    expect(devLogin.status).toBe(200);
    const { token: devToken } = (await devLogin.json()) as { token: string };

    // Find Alex's membership ID
    const teamRes = await TeamRoute.GET(makeReq('/api/v1/team', { token: adminToken }));
    const teamJson = (await teamRes.json()) as {
      members: Array<{ membershipId: string; email: string }>;
    };
    const alexMember = teamJson.members.find((m) => m.email === 'alex@acme.cloud');
    expect(alexMember).toBeTruthy();

    // Disable Alex account
    const disableRes = await TeamRoute.PATCH(
      makeReq('/api/v1/team', {
        method: 'PATCH',
        token: adminToken,
        body: { membershipId: alexMember!.membershipId, userStatus: 'Disabled' },
      })
    );
    expect(disableRes.status).toBe(200);

    // Existing active JWT for Alex must now fail with 401
    const activeTokenBlocked = await ProjectsRoute.GET(
      makeReq('/api/v1/projects', { token: devToken })
    );
    expect(activeTokenBlocked.status).toBe(401);

    // New login for disabled Alex must fail with 403 ACCOUNT_DISABLED
    const disabledLogin = await LoginRoute.POST(
      makeReq('/api/v1/auth/login', {
        method: 'POST',
        body: { email: 'alex@acme.cloud', password: 'Trustrail!2026' },
      })
    );
    expect(disabledLogin.status).toBe(403);
    expect(((await disabledLogin.json()) as { code: string }).code).toBe('ACCOUNT_DISABLED');

    // Re-enable Alex cleanly
    const enableRes = await TeamRoute.PATCH(
      makeReq('/api/v1/team', {
        method: 'PATCH',
        token: adminToken,
        body: { membershipId: alexMember!.membershipId, userStatus: 'Active' },
      })
    );
    expect(enableRes.status).toBe(200);

    // Create read-only scoped API key
    const keyRes = await ApiKeysRoute.POST(
      makeReq('/api/v1/api-keys', {
        method: 'POST',
        token: adminToken,
        body: { name: 'read-only-auditor', role: 'Developer', scopes: ['read'], expiresInDays: 30 },
      })
    );
    expect(keyRes.status).toBe(201);
    const keyJson = (await keyRes.json()) as {
      apiKey: { id: string; scopes: string[] };
      secret: string;
    };
    expect(keyJson.apiKey.scopes).toEqual(['read']);

    const readOk = await ProjectsRoute.GET(
      makeReq('/api/v1/projects', { apiKey: keyJson.secret })
    );
    expect(readOk.status).toBe(200);

    const scanBlocked = await ScansRoute.POST(
      makeReq('/api/v1/scans', {
        method: 'POST',
        apiKey: keyJson.secret,
        body: { projectName: 'payment-gateway-service', codeContent: 'const x = 1;' },
      })
    );
    expect(scanBlocked.status).toBe(403);
    expect(((await scanBlocked.json()) as { code: string }).code).toBe('INSUFFICIENT_SCOPE');

    // Rotate API key -> revokes old key and issues new active key preserving scopes
    const rotRes = await ApiKeyRotateRoute.POST(
      makeReq(`/api/v1/api-keys/${keyJson.apiKey.id}/rotate`, {
        method: 'POST',
        token: adminToken,
      }),
      { params: Promise.resolve({ id: keyJson.apiKey.id }) }
    );
    expect(rotRes.status).toBe(201);
    const rotJson = (await rotRes.json()) as { secret: string; rotatedFromId: string };
    expect(rotJson.rotatedFromId).toBe(keyJson.apiKey.id);
    expect(rotJson.secret).not.toBe(keyJson.secret);

    const oldKeyRejected = await ProjectsRoute.GET(
      makeReq('/api/v1/projects', { apiKey: keyJson.secret })
    );
    expect(oldKeyRejected.status).toBe(401);

    const newKeyWorks = await ProjectsRoute.GET(
      makeReq('/api/v1/projects', { apiKey: rotJson.secret })
    );
    expect(newKeyWorks.status).toBe(200);
  });
});
