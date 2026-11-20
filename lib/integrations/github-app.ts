import crypto from 'node:crypto';

function base64UrlEncode(input: string | Buffer): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/**
 * Generates a short-lived RS256 GitHub App JWT (valid up to 10 minutes) signed with the App's PEM private key.
 */
export function createGithubAppJwt(appId: string, privateKeyPem: string): string {
  const nowSec = Math.floor(Date.now() / 1000);
  const header = base64UrlEncode(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = base64UrlEncode(
    JSON.stringify({
      iat: nowSec - 60,
      exp: nowSec + 540,
      iss: appId.trim(),
    })
  );
  const signingInput = `${header}.${payload}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign(privateKeyPem);
  return `${signingInput}.${base64UrlEncode(signature)}`;
}

export async function exchangeGithubInstallationToken(opts: {
  appId: string;
  installationId: string;
  privateKeyPem: string;
}): Promise<{ ok: boolean; token?: string; expiresAt?: string; error?: string }> {
  try {
    const jwt = createGithubAppJwt(opts.appId, opts.privateKeyPem);
    const res = await fetch(
      `https://api.github.com/app/installations/${encodeURIComponent(opts.installationId)}/access_tokens`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${jwt}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'Trustrail-Security-Cloud',
        },
        signal: AbortSignal.timeout(8000),
      }
    );
    if (!res.ok) {
      return { ok: false, error: `GitHub App installation token exchange returned HTTP ${res.status}` };
    }
    const json = (await res.json()) as { token?: string; expires_at?: string };
    return { ok: Boolean(json.token), token: json.token, expiresAt: json.expires_at };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}

export async function publishGithubCheckRun(opts: {
  token: string;
  owner: string;
  repo: string;
  headSha: string;
  conclusion: 'success' | 'failure' | 'neutral' | 'action_required';
  title: string;
  summary: string;
}): Promise<{ ok: boolean; checkRunUrl?: string; error?: string }> {
  try {
    const res = await fetch(`https://api.github.com/repos/${opts.owner}/${opts.repo}/check-runs`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${opts.token}`,
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
        'User-Agent': 'Trustrail-Security-Cloud',
      },
      body: JSON.stringify({
        name: 'Trustrail Security Cloud Gate',
        head_sha: opts.headSha,
        status: 'completed',
        conclusion: opts.conclusion,
        output: {
          title: opts.title,
          summary: opts.summary,
        },
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!res.ok) {
      return { ok: false, error: `GitHub Checks API returned HTTP ${res.status}` };
    }
    const json = (await res.json()) as { html_url?: string };
    return { ok: true, checkRunUrl: json.html_url };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}
