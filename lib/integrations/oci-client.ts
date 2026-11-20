import { assertSafeExternalUrl } from '@/lib/security/ssrf';

export interface OciInspectionResult {
  image: string;
  registry: string;
  repository: string;
  reference: string;
  digest: string | null;
  mediaType: string | null;
  layersCount: number;
  totalCompressedBytes: number;
  pinnedByDigest: boolean;
  platforms: string[];
}

export function parseOciReference(rawImage: string): {
  registry: string;
  repository: string;
  reference: string;
  pinnedByDigest: boolean;
} {
  let remaining = rawImage.trim();
  let digest: string | null = null;
  const atIdx = remaining.indexOf('@');
  if (atIdx !== -1) {
    digest = remaining.slice(atIdx + 1);
    remaining = remaining.slice(0, atIdx);
  }

  let registry = 'registry-1.docker.io';
  const slashIdx = remaining.indexOf('/');
  if (slashIdx !== -1) {
    const candidateRegistry = remaining.slice(0, slashIdx);
    if (candidateRegistry.includes('.') || candidateRegistry.includes(':') || candidateRegistry === 'localhost') {
      registry = candidateRegistry;
      remaining = remaining.slice(slashIdx + 1);
    }
  }

  let tag = 'latest';
  const colonIdx = remaining.lastIndexOf(':');
  if (colonIdx !== -1 && !digest) {
    tag = remaining.slice(colonIdx + 1);
    remaining = remaining.slice(0, colonIdx);
  }

  const repository =
    registry === 'registry-1.docker.io' && !remaining.includes('/')
      ? `library/${remaining}`
      : remaining;

  return {
    registry,
    repository,
    reference: digest || tag,
    pinnedByDigest: Boolean(digest && digest.startsWith('sha256:')),
  };
}

function parseBearerChallenge(headerVal: string): { realm: string; service?: string; scope?: string } | null {
  if (!headerVal.toLowerCase().startsWith('bearer ')) return null;
  const params: Record<string, string> = {};
  const regex = /(\w+)="([^"]*)"/g;
  let m: RegExpExecArray | null;
  while ((m = regex.exec(headerVal)) !== null) {
    params[m[1]] = m[2];
  }
  if (!params.realm) return null;
  return { realm: params.realm, service: params.service, scope: params.scope };
}

export async function inspectOciImage(rawImage: string): Promise<OciInspectionResult> {
  const parsed = parseOciReference(rawImage);
  const manifestUrl = `https://${parsed.registry}/v2/${parsed.repository}/manifests/${encodeURIComponent(parsed.reference)}`;
  await assertSafeExternalUrl(manifestUrl, { requireHttps: true });

  const acceptHeader = [
    'application/vnd.oci.image.manifest.v1+json',
    'application/vnd.oci.image.index.v1+json',
    'application/vnd.docker.distribution.manifest.v2+json',
    'application/vnd.docker.distribution.manifest.list.v2+json',
  ].join(', ');

  let manifestRes = await fetch(manifestUrl, {
    headers: { Accept: acceptHeader, 'User-Agent': 'Trustrail-OCI-Inspector/1.0' },
    signal: AbortSignal.timeout(8000),
  });

  if (manifestRes.status === 401) {
    const authHeader = manifestRes.headers.get('www-authenticate') || '';
    const challenge = parseBearerChallenge(authHeader);
    if (challenge) {
      const tokenUrl = new URL(challenge.realm);
      if (challenge.service) tokenUrl.searchParams.set('service', challenge.service);
      tokenUrl.searchParams.set('scope', challenge.scope || `repository:${parsed.repository}:pull`);
      await assertSafeExternalUrl(tokenUrl.toString(), { requireHttps: true });

      const tokRes = await fetch(tokenUrl.toString(), {
        headers: { 'User-Agent': 'Trustrail-OCI-Inspector/1.0' },
        signal: AbortSignal.timeout(8000),
      });
      if (tokRes.ok) {
        const tokJson = (await tokRes.json()) as { token?: string; access_token?: string };
        const bearer = tokJson.token || tokJson.access_token;
        if (bearer) {
          manifestRes = await fetch(manifestUrl, {
            headers: {
              Accept: acceptHeader,
              Authorization: `Bearer ${bearer}`,
              'User-Agent': 'Trustrail-OCI-Inspector/1.0',
            },
            signal: AbortSignal.timeout(8000),
          });
        }
      }
    }
  }

  if (!manifestRes.ok) {
    throw new Error(`OCI registry returned HTTP ${manifestRes.status} for ${rawImage}.`);
  }

  const digest = manifestRes.headers.get('docker-content-digest');
  const body = (await manifestRes.json()) as {
    mediaType?: string;
    layers?: Array<{ size?: number }>;
    manifests?: Array<{ platform?: { os?: string; architecture?: string } }>;
  };

  const layers = body.layers || [];
  const totalCompressedBytes = layers.reduce((acc, l) => acc + (l.size || 0), 0);
  const platforms = (body.manifests || [])
    .map((m) => (m.platform ? `${m.platform.os}/${m.platform.architecture}` : ''))
    .filter(Boolean);

  return {
    image: rawImage,
    registry: parsed.registry,
    repository: parsed.repository,
    reference: parsed.reference,
    digest,
    mediaType: body.mediaType || manifestRes.headers.get('content-type'),
    layersCount: layers.length,
    totalCompressedBytes,
    pinnedByDigest: parsed.pinnedByDigest,
    platforms,
  };
}
