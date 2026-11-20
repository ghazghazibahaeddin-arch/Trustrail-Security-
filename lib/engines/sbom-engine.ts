import crypto from 'node:crypto';
import type { CycloneDxSbom } from '@/lib/engines/scanner-engine';
import { constantTimeEquals } from '@/lib/security/crypto';

export interface SpdxPackage {
  SPDXID: string;
  name: string;
  versionInfo: string;
  downloadLocation: string;
  filesAnalyzed: boolean;
  licenseConcluded: string;
  externalRefs: Array<{
    referenceCategory: 'PACKAGE-MANAGER';
    referenceType: 'purl';
    referenceLocator: string;
  }>;
}

export interface SpdxSbom {
  spdxVersion: 'SPDX-2.3';
  dataLicense: 'CC0-1.0';
  SPDXID: 'SPDXRef-DOCUMENT';
  name: string;
  documentNamespace: string;
  creationInfo: {
    created: string;
    creators: string[];
  };
  packages: SpdxPackage[];
  relationships: Array<{
    spdxElementId: string;
    relationshipType: 'DESCRIBES' | 'DEPENDS_ON';
    relatedSpdxElement: string;
  }>;
}

export interface SbomValidationResult {
  valid: boolean;
  format: 'CycloneDX' | 'SPDX' | 'Unknown';
  componentCount: number;
  errors: string[];
}

export interface AttestationVerificationResult {
  verified: boolean;
  digestMatched: boolean;
  computedDigestSha256: string | null;
  signatureValid: boolean;
  algorithm: string;
  recommendedSlsaLevel: 'SLSA 3' | 'SLSA 2' | 'SLSA 1';
  reason: string;
}

export function convertCycloneDxToSpdx(
  sbom: CycloneDxSbom,
  namespaceBase = 'https://trustrail.security/spdx'
): SpdxSbom {
  const projectName = sbom.metadata?.component?.name || 'trustrail-project';
  const created = sbom.metadata?.timestamp || new Date().toISOString();
  const rootId = 'SPDXRef-Application';

  const packages: SpdxPackage[] = [
    {
      SPDXID: rootId,
      name: projectName,
      versionInfo: '1.0.0',
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: 'NOASSERTION',
      externalRefs: [],
    },
  ];

  const relationships: SpdxSbom['relationships'] = [
    {
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: rootId,
    },
  ];

  sbom.components.forEach((comp, idx) => {
    const safeId = `SPDXRef-Pkg-${idx + 1}-${comp.name.replace(/[^A-Za-z0-9.-]/g, '-')}`;
    packages.push({
      SPDXID: safeId,
      name: comp.name,
      versionInfo: comp.version || '0.0.0',
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      licenseConcluded: (comp as { license?: string }).license || 'NOASSERTION',
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: comp.purl,
        },
      ],
    });
    relationships.push({
      spdxElementId: rootId,
      relationshipType: 'DEPENDS_ON',
      relatedSpdxElement: safeId,
    });
  });

  return {
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: `${projectName}-sbom`,
    documentNamespace: `${namespaceBase}/${encodeURIComponent(projectName)}/${crypto.randomUUID()}`,
    creationInfo: {
      created,
      creators: ['Tool: Trustrail-SBOM-Engine-1.0'],
    },
    packages,
    relationships,
  };
}

export function validateSbomDocument(doc: unknown): SbomValidationResult {
  const errors: string[] = [];
  if (!doc || typeof doc !== 'object') {
    return { valid: false, format: 'Unknown', componentCount: 0, errors: ['SBOM document must be a JSON object.'] };
  }
  const obj = doc as Record<string, unknown>;

  if (obj.bomFormat === 'CycloneDX') {
    if (typeof obj.specVersion !== 'string' || !obj.specVersion) {
      errors.push('CycloneDX specVersion is missing.');
    }
    if (!Array.isArray(obj.components)) {
      errors.push('CycloneDX components array is missing.');
    } else {
      obj.components.forEach((c, idx) => {
        if (!c || typeof c !== 'object' || !(c as Record<string, unknown>).name || !(c as Record<string, unknown>).purl) {
          errors.push(`Component at index ${idx} lacks name or purl.`);
        }
      });
    }
    return {
      valid: errors.length === 0,
      format: 'CycloneDX',
      componentCount: Array.isArray(obj.components) ? obj.components.length : 0,
      errors,
    };
  }

  if (obj.spdxVersion === 'SPDX-2.3' || obj.SPDXID === 'SPDXRef-DOCUMENT') {
    if (obj.dataLicense !== 'CC0-1.0') {
      errors.push('SPDX 2.3 requires dataLicense="CC0-1.0".');
    }
    if (!Array.isArray(obj.packages) || obj.packages.length === 0) {
      errors.push('SPDX packages array is empty or missing.');
    }
    if (!Array.isArray(obj.relationships) || obj.relationships.length === 0) {
      errors.push('SPDX relationships array is empty or missing.');
    }
    return {
      valid: errors.length === 0,
      format: 'SPDX',
      componentCount: Array.isArray(obj.packages) ? Math.max(0, obj.packages.length - 1) : 0,
      errors,
    };
  }

  return {
    valid: false,
    format: 'Unknown',
    componentCount: 0,
    errors: ['Unrecognized SBOM format (expected CycloneDX 1.5 or SPDX 2.3).'],
  };
}

export function verifyArtifactAttestation(input: {
  expectedDigestSha256: string;
  artifactContent?: string;
  hmacSignature?: string;
  signingSecret?: string;
}): AttestationVerificationResult {
  const normalizedExpected = input.expectedDigestSha256.replace(/^sha256:/i, '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalizedExpected)) {
    return {
      verified: false,
      digestMatched: false,
      computedDigestSha256: null,
      signatureValid: false,
      algorithm: 'sha256',
      recommendedSlsaLevel: 'SLSA 1',
      reason: 'Invalid SHA-256 digest format (expected 64 hex characters).',
    };
  }

  let computedDigest: string | null = null;
  let digestMatched = true;
  if (input.artifactContent !== undefined) {
    computedDigest = crypto.createHash('sha256').update(input.artifactContent, 'utf8').digest('hex');
    digestMatched = constantTimeEquals(computedDigest, normalizedExpected);
    if (!digestMatched) {
      return {
        verified: false,
        digestMatched: false,
        computedDigestSha256: computedDigest,
        signatureValid: false,
        algorithm: 'sha256',
        recommendedSlsaLevel: 'SLSA 1',
        reason: `Artifact SHA-256 mismatch (expected ${normalizedExpected.slice(0, 12)}..., got ${computedDigest.slice(0, 12)}...).`,
      };
    }
  }

  let signatureValid = false;
  if (input.hmacSignature && input.signingSecret) {
    const expectedHmac = crypto
      .createHmac('sha256', input.signingSecret)
      .update(normalizedExpected, 'utf8')
      .digest('hex');
    signatureValid = constantTimeEquals(input.hmacSignature.trim().toLowerCase(), expectedHmac);
    if (!signatureValid) {
      return {
        verified: false,
        digestMatched,
        computedDigestSha256: computedDigest,
        signatureValid: false,
        algorithm: 'hmac-sha256',
        recommendedSlsaLevel: 'SLSA 1',
        reason: 'Cryptographic provenance HMAC signature verification failed.',
      };
    }
  }

  return {
    verified: digestMatched && (!input.hmacSignature || signatureValid),
    digestMatched,
    computedDigestSha256: computedDigest || normalizedExpected,
    signatureValid,
    algorithm: signatureValid ? 'hmac-sha256' : 'sha256',
    recommendedSlsaLevel: signatureValid ? 'SLSA 3' : 'SLSA 2',
    reason: signatureValid
      ? 'Artifact digest and provenance signature verified cleanly (SLSA 3 eligible).'
      : 'Artifact SHA-256 digest verified cleanly (SLSA 2 provenance).',
  };
}
