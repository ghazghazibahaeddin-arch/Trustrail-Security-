import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const g = globalThis as typeof globalThis & { __trustrailSessionSecret?: string };

function getSigningSecret(): string {
  if (process.env.TRUSTRAIL_SESSION_SECRET && process.env.TRUSTRAIL_SESSION_SECRET.length >= 16) {
    return process.env.TRUSTRAIL_SESSION_SECRET;
  }
  if (g.__trustrailSessionSecret) {
    return g.__trustrailSessionSecret;
  }

  const secretDir = path.join(process.cwd(), '.data');
  const secretFile = path.join(secretDir, '.session-secret');
  try {
    if (fs.existsSync(secretFile)) {
      const stored = fs.readFileSync(secretFile, 'utf8').trim();
      if (stored.length >= 32) {
        g.__trustrailSessionSecret = stored;
        return stored;
      }
    }
    if (!fs.existsSync(secretDir)) {
      fs.mkdirSync(secretDir, { recursive: true });
    }
    const generated = crypto.randomBytes(32).toString('hex');
    fs.writeFileSync(secretFile, generated, { encoding: 'utf8', mode: 0o600 });
    g.__trustrailSessionSecret = generated;
    return generated;
  } catch {
    const ephemeral = crypto.randomBytes(32).toString('hex');
    g.__trustrailSessionSecret = ephemeral;
    return ephemeral;
  }
}

export function sha256(input: string): string {
  return crypto.createHash('sha256').update(input, 'utf8').digest('hex');
}

function sortKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortKeysDeep);
  }
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(record).sort()) {
      sorted[key] = sortKeysDeep(record[key]);
    }
    return sorted;
  }
  return value;
}

export function canonicalHash(payload: unknown): string {
  const normalized = JSON.stringify(sortKeysDeep(payload));
  return `sha256:${sha256(normalized)}`;
}

/**
 * Redacts sensitive secret literals so full credentials are never persisted or exposed.
 */
export function redactSecret(secret: string): string {
  const trimmed = secret.trim();
  if (trimmed.length <= 6) {
    return '***REDACTED***';
  }
  const prefixLen = Math.min(4, Math.floor(trimmed.length / 4));
  const suffixLen = Math.min(4, Math.floor(trimmed.length / 4));
  const prefix = trimmed.slice(0, prefixLen);
  const suffix = trimmed.slice(trimmed.length - suffixLen);
  return `${prefix}****${suffix}`;
}

export function redactEvidenceSecrets(text: string): string {
  let out = text;
  // AWS Access Key IDs
  out = out.replace(/AKIA[0-9A-Z]{16}/g, (m) => redactSecret(m));
  // GitHub PATs
  out = out.replace(/gh[pousr]_[A-Za-z0-9_]{16,}/g, (m) => redactSecret(m));
  // Stripe live/test secret keys
  out = out.replace(/sk_(?:live|test)_[A-Za-z0-9]{12,}/g, (m) => redactSecret(m));
  // Bearer tokens in headers/logs
  out = out.replace(/(Authorization:\s*Bearer\s+)([A-Za-z0-9._\-]{8,})/gi, (_all, pre, tok) => `${pre}${redactSecret(tok)}`);
  // URL embedded passwords (e.g. postgres://user:pass@host)
  out = out.replace(/([a-z][a-z0-9+.-]*:\/\/[^:\s/@]+:)([^@\s]+)(@)/gi, (_all, pre, pwd, post) => `${pre}${redactSecret(pwd)}${post}`);
  // Quoted secrets / JWT / API keys
  out = out.replace(
    /((?:secret|password|passwd|token|api_key|apikey|jwt_secret|private_key|stripe)\s*[:=]\s*["'])([^"']{6,})(["'])/gi,
    (_all, pre, val, post) => `${pre}${redactSecret(val)}${post}`
  );
  return out;
}

export function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split(':');
  if (parts.length !== 2) return false;
  const [salt, expectedHex] = parts;
  const actualBuf = crypto.scryptSync(password, salt, 64);
  const expectedBuf = Buffer.from(expectedHex, 'hex');
  if (actualBuf.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(actualBuf, expectedBuf);
}

export function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

export function signToken(payload: Record<string, unknown>, expiresInSeconds = 86400): string {
  const data = {
    ...payload,
    jti: typeof payload.jti === 'string' ? payload.jti : crypto.randomUUID(),
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + expiresInSeconds,
  };
  const encoded = Buffer.from(JSON.stringify(data), 'utf8').toString('base64url');
  const sig = crypto
    .createHmac('sha256', getSigningSecret())
    .update(encoded)
    .digest('base64url');
  return `${encoded}.${sig}`;
}

export function verifyToken(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 2) return null;
    const [encoded, sig] = parts;
    const expectedSig = crypto
      .createHmac('sha256', getSigningSecret())
      .update(encoded)
      .digest('base64url');
    const actualBuf = Buffer.from(sig, 'utf8');
    const expectedBuf = Buffer.from(expectedSig, 'utf8');
    if (actualBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(actualBuf, expectedBuf)) {
      return null;
    }
    const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as Record<string, unknown>;
    if (typeof parsed.exp === 'number' && parsed.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return parsed;
  } catch {
    return null;
  }
}

export function verifyGithubWebhookSignature(
  rawBody: string,
  signatureHeader: string | null,
  secret: string
): boolean {
  if (!signatureHeader || !secret) return false;
  const expected = `sha256=${crypto.createHmac('sha256', secret).update(rawBody, 'utf8').digest('hex')}`;
  const actualBuf = Buffer.from(signatureHeader, 'utf8');
  const expectedBuf = Buffer.from(expected, 'utf8');
  if (actualBuf.length !== expectedBuf.length) return false;
  return crypto.timingSafeEqual(actualBuf, expectedBuf);
}

// RFC 4648 Base32 & RFC 6238 TOTP Implementation
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function generateTotpSecret(byteLength = 20): string {
  const bytes = crypto.randomBytes(byteLength);
  let bits = '';
  for (const byte of bytes) {
    bits += byte.toString(2).padStart(8, '0');
  }
  let out = '';
  for (let i = 0; i < bits.length; i += 5) {
    const chunk = bits.slice(i, i + 5).padEnd(5, '0');
    out += BASE32_ALPHABET[Number.parseInt(chunk, 2)];
  }
  return out;
}

function decodeBase32(secret: string): Buffer {
  const cleaned = secret.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const ch of cleaned) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(Number.parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

export function generateTotpCode(secret: string, timestampMs = Date.now(), stepSeconds = 30): string {
  const counter = Math.floor(timestampMs / 1000 / stepSeconds);
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));
  const key = decodeBase32(secret);
  const hmac = crypto.createHmac('sha1', key).update(counterBuf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const codeInt =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
  return String(codeInt % 1_000_000).padStart(6, '0');
}

export function verifyTotpCode(secret: string, token: string, windowSteps = 1): boolean {
  const normalized = token.replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) return false;
  const now = Date.now();
  for (let w = -windowSteps; w <= windowSteps; w++) {
    const candidate = generateTotpCode(secret, now + w * 30_000);
    if (constantTimeEquals(candidate, normalized)) {
      return true;
    }
  }
  return false;
}

export function buildOtpAuthUri(email: string, secret: string, issuer = 'Trustrail Security Cloud'): string {
  const label = encodeURIComponent(`${issuer}:${email}`);
  return `otpauth://totp/${label}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

