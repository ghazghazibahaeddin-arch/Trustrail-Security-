import dns from 'node:dns/promises';
import net from 'node:net';

function isPrivateOrReservedIpv4(ip: string): boolean {
  const parts = ip.split('.').map((p) => Number.parseInt(p, 10));
  if (parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    return true;
  }
  const [a, b] = parts;
  if (a === 0) return true; // 0.0.0.0/8
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 127) return true; // 127.0.0.0/8 Loopback
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 Link-local / Cloud Metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 192 && b === 0 && parts[2] === 0) return true; // 192.0.0.0/24
  if (a === 198 && (b === 18 || b === 19)) return true; // Benchmarking 198.18.0.0/15
  if (a >= 224) return true; // Multicast & Reserved
  return false;
}

function isPrivateOrReservedIpv6(ip: string): boolean {
  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return true;
  if (lower.startsWith('::ffff:')) {
    const v4 = lower.slice(7);
    if (net.isIPv4(v4)) return isPrivateOrReservedIpv4(v4);
    return true;
  }
  if (lower.startsWith('fe80:')) return true; // Link-local
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // Unique local
  if (lower.startsWith('ff')) return true; // Multicast
  return false;
}

export function isBlockedIpAddress(ip: string): boolean {
  const ipVersion = net.isIP(ip);
  if (ipVersion === 4) return isPrivateOrReservedIpv4(ip);
  if (ipVersion === 6) return isPrivateOrReservedIpv6(ip);
  return true;
}

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'metadata',
  'instance-data',
]);

const DEFAULT_ALLOWED_PORTS = new Set([80, 443]);

export async function assertSafeExternalUrl(
  rawUrl: string,
  options: { requireHttps?: boolean; skipDnsLookup?: boolean; allowedPorts?: number[] } = {}
): Promise<URL> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim());
  } catch {
    throw new Error('Invalid URL format. Provide a full http:// or https:// URL.');
  }

  if (options.requireHttps && parsed.protocol !== 'https:') {
    throw new Error('Only HTTPS URLs are permitted for this endpoint.');
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    throw new Error('Unsupported URL protocol. Only http: and https: are permitted.');
  }
  if (parsed.username || parsed.password) {
    throw new Error('Embedded credentials in URLs are not allowed.');
  }

  const effectivePort = parsed.port
    ? Number.parseInt(parsed.port, 10)
    : parsed.protocol === 'https:'
    ? 443
    : 80;
  const allowedPortSet = options.allowedPorts
    ? new Set(options.allowedPorts)
    : DEFAULT_ALLOWED_PORTS;

  if (!Number.isInteger(effectivePort) || effectivePort <= 0 || !allowedPortSet.has(effectivePort)) {
    throw new Error(`SSRF protection blocked non-standard external port "${effectivePort}".`);
  }

  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (!hostname) {
    throw new Error('URL hostname is missing.');
  }
  if (
    BLOCKED_HOSTNAMES.has(hostname) ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal')
  ) {
    throw new Error(`SSRF protection blocked internal/local hostname "${hostname}".`);
  }

  if (net.isIP(hostname) !== 0) {
    if (isBlockedIpAddress(hostname)) {
      throw new Error(`SSRF protection blocked private, loopback, or metadata IP "${hostname}".`);
    }
    return parsed;
  }

  if (!options.skipDnsLookup) {
    let records: Array<{ address: string; family: number }>;
    try {
      records = await dns.lookup(hostname, { all: true });
    } catch {
      throw new Error(`DNS resolution failed for hostname "${hostname}".`);
    }
    if (!records || records.length === 0) {
      throw new Error(`No DNS A/AAAA records found for "${hostname}".`);
    }
    for (const rec of records) {
      if (isBlockedIpAddress(rec.address)) {
        throw new Error(
          `SSRF protection blocked "${hostname}" because it resolves to non-public address ${rec.address}.`
        );
      }
    }
  }

  return parsed;
}

export async function fetchWithSafeRedirects(
  rawUrl: string,
  init: RequestInit = {},
  options: { requireHttps?: boolean; maxRedirects?: number; allowedPorts?: number[] } = {}
): Promise<{ response: Response; finalUrl: URL; redirectCount: number }> {
  const maxRedirects = options.maxRedirects ?? 3;
  let currentUrl = await assertSafeExternalUrl(rawUrl, {
    requireHttps: options.requireHttps,
    allowedPorts: options.allowedPorts,
  });

  let redirectCount = 0;
  while (true) {
    const response = await fetch(currentUrl.toString(), {
      ...init,
      redirect: 'manual',
    });

    if (
      response.status >= 300 &&
      response.status < 400 &&
      response.headers.get('location')
    ) {
      if (redirectCount >= maxRedirects) {
        return { response, finalUrl: currentUrl, redirectCount };
      }
      const nextRaw = new URL(response.headers.get('location')!, currentUrl).toString();
      currentUrl = await assertSafeExternalUrl(nextRaw, {
        requireHttps: options.requireHttps,
        allowedPorts: options.allowedPorts,
      });
      redirectCount += 1;
      continue;
    }

    return { response, finalUrl: currentUrl, redirectCount };
  }
}

