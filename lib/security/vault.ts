import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export interface EncryptedEnvelope {
  v: 1;
  alg: 'aes-256-gcm';
  keyVersion: number;
  iv: string;
  authTag: string;
  ciphertext: string;
  updatedAt: string;
}

const g = globalThis as typeof globalThis & { __trustrailVaultMasterKeys?: Map<number, Buffer> };

function derive256BitKey(rawKeyMaterial: string, keyVersion: number): Buffer {
  return crypto.scryptSync(rawKeyMaterial, `trustrail-vault-v${keyVersion}`, 32);
}

function loadMasterKeys(): Map<number, Buffer> {
  if (g.__trustrailVaultMasterKeys && !process.env.TRUSTRAIL_VAULT_KEY && !process.env.TRUSTRAIL_VAULT_PREVIOUS_KEY) {
    return g.__trustrailVaultMasterKeys;
  }

  const keys = new Map<number, Buffer>();
  const currentVersion = Number.parseInt(process.env.TRUSTRAIL_VAULT_KEY_VERSION || '1', 10) || 1;

  if (process.env.TRUSTRAIL_VAULT_KEY && process.env.TRUSTRAIL_VAULT_KEY.length >= 16) {
    keys.set(currentVersion, derive256BitKey(process.env.TRUSTRAIL_VAULT_KEY, currentVersion));
  }
  if (process.env.TRUSTRAIL_VAULT_PREVIOUS_KEY && process.env.TRUSTRAIL_VAULT_PREVIOUS_KEY.length >= 16) {
    const prevVer = Math.max(1, currentVersion - 1);
    if (!keys.has(prevVer)) {
      keys.set(prevVer, derive256BitKey(process.env.TRUSTRAIL_VAULT_PREVIOUS_KEY, prevVer));
    }
  }

  if (keys.size > 0) {
    g.__trustrailVaultMasterKeys = keys;
    return keys;
  }

  const secretDir = path.join(process.cwd(), '.data');
  const keyFile = path.join(secretDir, '.vault-master-key');
  try {
    let rawHex: string;
    if (fs.existsSync(keyFile)) {
      rawHex = fs.readFileSync(keyFile, 'utf8').trim();
    } else {
      if (!fs.existsSync(secretDir)) {
        fs.mkdirSync(secretDir, { recursive: true });
      }
      rawHex = crypto.randomBytes(32).toString('hex');
      fs.writeFileSync(keyFile, rawHex, { encoding: 'utf8', mode: 0o600 });
    }
    keys.set(1, derive256BitKey(rawHex, 1));
    keys.set(2, derive256BitKey(`${rawHex}:v2`, 2));
  } catch {
    const ephemeral = crypto.randomBytes(32).toString('hex');
    keys.set(1, derive256BitKey(ephemeral, 1));
    keys.set(2, derive256BitKey(`${ephemeral}:v2`, 2));
  }

  g.__trustrailVaultMasterKeys = keys;
  return keys;
}

export function getActiveVaultKeyVersion(): number {
  const configured = Number.parseInt(process.env.TRUSTRAIL_VAULT_KEY_VERSION || '1', 10);
  return Number.isFinite(configured) && configured >= 1 ? configured : 1;
}

export function isEncryptedEnvelope(raw: string | null | undefined): boolean {
  if (!raw) return false;
  try {
    const parsed = JSON.parse(raw) as Partial<EncryptedEnvelope>;
    return (
      parsed.v === 1 &&
      parsed.alg === 'aes-256-gcm' &&
      typeof parsed.iv === 'string' &&
      typeof parsed.authTag === 'string' &&
      typeof parsed.ciphertext === 'string'
    );
  } catch {
    return false;
  }
}

export function encryptSecretPayload(
  payload: Record<string, unknown>,
  options: { aad?: string; keyVersion?: number } = {}
): string {
  const keys = loadMasterKeys();
  const keyVersion = options.keyVersion ?? getActiveVaultKeyVersion();
  let key = keys.get(keyVersion);
  if (!key) {
    // Derive dynamically for rotated version if explicitly requested
    const baseKey = keys.get(1) || crypto.randomBytes(32);
    key = derive256BitKey(baseKey.toString('hex'), keyVersion);
    keys.set(keyVersion, key);
  }

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  if (options.aad) {
    cipher.setAAD(Buffer.from(options.aad, 'utf8'));
  }

  const plaintext = JSON.stringify(payload);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  const envelope: EncryptedEnvelope = {
    v: 1,
    alg: 'aes-256-gcm',
    keyVersion,
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
    updatedAt: new Date().toISOString(),
  };

  return JSON.stringify(envelope);
}

export function decryptSecretPayload<T = Record<string, unknown>>(
  raw: string | null | undefined,
  options: { aad?: string } = {}
): { data: T | null; keyVersion: number | null; encrypted: boolean } {
  if (!raw || !raw.trim()) {
    return { data: null, keyVersion: null, encrypted: false };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { data: null, keyVersion: null, encrypted: false };
  }

  const candidate = parsed as Partial<EncryptedEnvelope>;
  if (
    candidate.v === 1 &&
    candidate.alg === 'aes-256-gcm' &&
    typeof candidate.iv === 'string' &&
    typeof candidate.authTag === 'string' &&
    typeof candidate.ciphertext === 'string'
  ) {
    const keys = loadMasterKeys();
    const version = typeof candidate.keyVersion === 'number' ? candidate.keyVersion : 1;
    let key = keys.get(version);
    if (!key && keys.has(1)) {
      key = derive256BitKey(keys.get(1)!.toString('hex'), version);
      keys.set(version, key);
    }
    if (!key) {
      throw new Error(`Vault key version ${version} unavailable for decryption.`);
    }

    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      key,
      Buffer.from(candidate.iv, 'base64')
    );
    if (options.aad) {
      decipher.setAAD(Buffer.from(options.aad, 'utf8'));
    }
    decipher.setAuthTag(Buffer.from(candidate.authTag, 'base64'));
    const decrypted = Buffer.concat([
      decipher.update(Buffer.from(candidate.ciphertext, 'base64')),
      decipher.final(),
    ]).toString('utf8');

    return {
      data: JSON.parse(decrypted) as T,
      keyVersion: version,
      encrypted: true,
    };
  }

  // Legacy unencrypted object fallback (caller can migrate on write)
  if (typeof parsed === 'object' && parsed !== null) {
    return { data: parsed as T, keyVersion: null, encrypted: false };
  }

  return { data: null, keyVersion: null, encrypted: false };
}

export function rotateSecretEnvelope(
  raw: string,
  targetKeyVersion: number,
  options: { aad?: string } = {}
): { rotatedEnvelope: string; previousVersion: number | null; newVersion: number } {
  const { data, keyVersion } = decryptSecretPayload<Record<string, unknown>>(raw, options);
  if (!data) {
    throw new Error('Cannot rotate empty or corrupted secret payload.');
  }
  const rotatedEnvelope = encryptSecretPayload(data, {
    aad: options.aad,
    keyVersion: targetKeyVersion,
  });
  return {
    rotatedEnvelope,
    previousVersion: keyVersion,
    newVersion: targetKeyVersion,
  };
}
