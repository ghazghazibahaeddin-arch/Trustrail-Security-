import crypto from 'node:crypto';
import { describe, it, expect } from 'vitest';
import {
  encryptSecretPayload,
  decryptSecretPayload,
  rotateSecretEnvelope,
  isEncryptedEnvelope,
} from '@/lib/security/vault';
import {
  generateTotpSecret,
  generateTotpCode,
  verifyTotpCode,
  buildOtpAuthUri,
  constantTimeEquals,
} from '@/lib/security/crypto';
import { assertSafeExternalUrl } from '@/lib/security/ssrf';
import { evaluatePolicies, type PolicyRule } from '@/lib/engines/policy-engine';
import {
  convertCycloneDxToSpdx,
  validateSbomDocument,
  verifyArtifactAttestation,
} from '@/lib/engines/sbom-engine';
import {
  scanMultiEcosystemManifests,
  scanGithubWorkflow,
  type CycloneDxSbom,
} from '@/lib/engines/scanner-engine';

describe('Security Hardening: Vault, TOTP MFA, SSRF, Policy Modes, SBOM & Multi-Ecosystem Scanners', () => {
  it('encrypts secrets with AES-256-GCM AAD binding, rejects tampered AAD, and rotates key versions cleanly', () => {
    const scopeAad = 'org-acme:conn-aws';
    const envelope = encryptSecretPayload(
      { awsAccessKeyId: 'AKIAEXAMPLE12345678', awsSecretAccessKey: 'super-secret-value-xyz' },
      { aad: scopeAad, keyVersion: 1 }
    );

    expect(isEncryptedEnvelope(envelope)).toBe(true);
    expect(envelope).not.toContain('AKIAEXAMPLE12345678');
    expect(envelope).not.toContain('super-secret-value-xyz');

    const dec = decryptSecretPayload<{ awsAccessKeyId: string; awsSecretAccessKey: string }>(envelope, {
      aad: scopeAad,
    });
    expect(dec.encrypted).toBe(true);
    expect(dec.keyVersion).toBe(1);
    expect(dec.data?.awsSecretAccessKey).toBe('super-secret-value-xyz');

    // Cross-tenant / cross-connector AAD tampering must fail GCM authTag verification
    expect(() =>
      decryptSecretPayload(envelope, { aad: 'org-other:conn-aws' })
    ).toThrow();

    // Rotate envelope from v1 -> v2
    const rotated = rotateSecretEnvelope(envelope, 2, { aad: scopeAad });
    expect(rotated.previousVersion).toBe(1);
    expect(rotated.newVersion).toBe(2);
    expect(rotated.rotatedEnvelope).not.toBe(envelope);

    const decRotated = decryptSecretPayload<{ awsSecretAccessKey: string }>(rotated.rotatedEnvelope, {
      aad: scopeAad,
    });
    expect(decRotated.keyVersion).toBe(2);
    expect(decRotated.data?.awsSecretAccessKey).toBe('super-secret-value-xyz');
  });

  it('generates and verifies RFC 6238 TOTP codes, otpauth URIs, and constant-time comparisons', () => {
    const secret = generateTotpSecret();
    expect(secret.length).toBeGreaterThanOrEqual(16);

    const code = generateTotpCode(secret);
    expect(code).toMatch(/^\d{6}$/);
    expect(verifyTotpCode(secret, code)).toBe(true);

    const wrongCode = code === '000000' ? '111111' : '000000';
    expect(verifyTotpCode(secret, wrongCode)).toBe(false);

    const uri = buildOtpAuthUri('sarah@acme.cloud', secret);
    expect(uri.startsWith('otpauth://totp/')).toBe(true);
    expect(uri).toContain(`secret=${encodeURIComponent(secret)}`);

    expect(constantTimeEquals('trustrail-secret', 'trustrail-secret')).toBe(true);
    expect(constantTimeEquals('trustrail-secret', 'trustrail-secrex')).toBe(false);
    expect(constantTimeEquals('short', 'longer-string')).toBe(false);
  });

  it('blocks SSRF against non-80/443 ports, loopback IPs, and cloud metadata endpoints', async () => {
    await expect(
      assertSafeExternalUrl('https://example.com:8443/webhook', { skipDnsLookup: true })
    ).rejects.toThrow(/non-standard external port/i);

    await expect(
      assertSafeExternalUrl('http://127.0.0.1/internal', { skipDnsLookup: true })
    ).rejects.toThrow(/private, loopback, or metadata IP/i);

    await expect(
      assertSafeExternalUrl('http://169.254.169.254/latest/meta-data', { skipDnsLookup: true })
    ).rejects.toThrow(/private, loopback, or metadata IP/i);

    await expect(
      assertSafeExternalUrl('https://metadata.google.internal/computeMetadata/v1/', { skipDnsLookup: true })
    ).rejects.toThrow(/internal\/local hostname/i);

    const safeUrl = await assertSafeExternalUrl('https://93.184.216.34/webhook', {
      requireHttps: true,
      skipDnsLookup: true,
    });
    expect(safeUrl.hostname).toBe('93.184.216.34');
  });

  it('enforces Observe, Recommend, and Enforce policy evaluation modes deterministically', () => {
    const policies: PolicyRule[] = [
      {
        id: 'pol-s3',
        name: 'Block Public S3 Buckets',
        engine: 'Cloud Guard',
        severity: 'Critical',
        status: 'Enforced',
        ruleCode: 'BLOCK_PUBLIC_S3_ACL',
      },
    ];
    const target = { type: 'terraform_plan' as const, hasPublicS3: true };

    const observe = evaluatePolicies(policies, target, 'Observe');
    expect(observe.decision).toBe('ALLOW');
    expect(observe.allowed).toBe(true);
    expect(observe.wouldBlock).toBe(true);
    expect(observe.violatedRules).toHaveLength(1);

    const recommend = evaluatePolicies(policies, target, 'Recommend');
    expect(recommend.decision).toBe('REQUIRE_APPROVAL');
    expect(recommend.allowed).toBe(false);
    expect(recommend.wouldBlock).toBe(true);

    const enforce = evaluatePolicies(policies, target, 'Enforce');
    expect(enforce.decision).toBe('DENY');
    expect(enforce.allowed).toBe(false);
    expect(enforce.wouldBlock).toBe(true);
  });

  it('converts CycloneDX 1.5 to SPDX 2.3, validates both formats, and verifies SLSA 2 / SLSA 3 attestations', () => {
    const cdx: CycloneDxSbom = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${crypto.randomUUID()}`,
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        component: { name: 'payments-api', type: 'application' },
      },
      components: [
        { type: 'library', name: 'express', version: '4.21.1', purl: 'pkg:npm/express@4.21.1', license: 'MIT' },
        { type: 'library', name: 'zod', version: '4.6.7', purl: 'pkg:npm/zod@4.6.7', license: 'MIT' },
      ],
    };

    const cdxCheck = validateSbomDocument(cdx);
    expect(cdxCheck.valid).toBe(true);
    expect(cdxCheck.format).toBe('CycloneDX');
    expect(cdxCheck.componentCount).toBe(2);

    const spdx = convertCycloneDxToSpdx(cdx);
    expect(spdx.spdxVersion).toBe('SPDX-2.3');
    expect(spdx.dataLicense).toBe('CC0-1.0');
    const spdxCheck = validateSbomDocument(spdx);
    expect(spdxCheck.valid).toBe(true);
    expect(spdxCheck.format).toBe('SPDX');
    expect(spdxCheck.componentCount).toBe(2);

    expect(validateSbomDocument({}).valid).toBe(false);

    const artifact = 'trustrail-release-tarball-v2.1.0';
    const digest = crypto.createHash('sha256').update(artifact, 'utf8').digest('hex');
    const slsa2 = verifyArtifactAttestation({
      expectedDigestSha256: digest,
      artifactContent: artifact,
    });
    expect(slsa2.verified).toBe(true);
    expect(slsa2.recommendedSlsaLevel).toBe('SLSA 2');

    const secret = 'ci-signing-key-2026';
    const hmac = crypto.createHmac('sha256', secret).update(digest, 'utf8').digest('hex');
    const slsa3 = verifyArtifactAttestation({
      expectedDigestSha256: digest,
      artifactContent: artifact,
      hmacSignature: hmac,
      signingSecret: secret,
    });
    expect(slsa3.verified).toBe(true);
    expect(slsa3.signatureValid).toBe(true);
    expect(slsa3.recommendedSlsaLevel).toBe('SLSA 3');

    const tampered = verifyArtifactAttestation({
      expectedDigestSha256: digest,
      artifactContent: 'tampered-binary',
    });
    expect(tampered.verified).toBe(false);
    expect(tampered.digestMatched).toBe(false);
  });

  it('scans multi-ecosystem manifests (npm lockfile, PyPI, Go, Maven) and GitHub Actions workflows', () => {
    const multi = scanMultiEcosystemManifests(
      {
        packageLockContent: JSON.stringify({
          packages: {
            'node_modules/copyleft-lib': { version: '1.0.0', license: 'GPL-3.0' },
          },
        }),
        requirementsTxtContent: 'PyYAML==5.3.1\nrequests>=2.31.0\n',
        goModContent: 'module github.com/acme/api\nrequire (\n\tgolang.org/x/net v0.12.0\n)\n',
        pomXmlContent: `<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>`,
      },
      'polyglot-service'
    );

    expect(multi.filesScanned).toBe(4);
    expect(multi.components.some((c) => c.purl === 'pkg:pypi/pyyaml@5.3.1')).toBe(true);
    expect(multi.findings.some((f) => f.title.includes('GPL-3.0'))).toBe(true);
    expect(multi.findings.some((f) => f.cve === 'CVE-2020-14343')).toBe(true);
    expect(multi.findings.some((f) => f.cve === 'CVE-2023-44487')).toBe(true);
    expect(multi.findings.some((f) => f.cve === 'CVE-2021-44228' && f.severity === 'CRITICAL')).toBe(true);

    const ghaFindings = scanGithubWorkflow(
      `name: CI\non:\n  pull_request_target:\npermissions: write-all\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\n      - run: echo "\${{ github.event.pull_request.title }}"\n`,
      'polyglot-service'
    );
    expect(ghaFindings.some((f) => f.title.includes('write-all'))).toBe(true);
    expect(ghaFindings.some((f) => f.title.includes('actions/checkout@main'))).toBe(true);
    expect(ghaFindings.some((f) => f.severity === 'CRITICAL' && f.title.includes('pull_request_target'))).toBe(true);
  });
});
