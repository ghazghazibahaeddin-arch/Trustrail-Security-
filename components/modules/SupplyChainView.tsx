'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Project } from '@/lib/trustrail-store';
import { PackageCheck, Download, CheckCircle2, AlertTriangle, X, ShieldCheck, FileCode2 } from 'lucide-react';

export function SupplyChainView() {
  const { projects, findings, org, fetchProjectSbom, verifySlsaAttestation, user } = useTrustrail();
  const [viewingProj, setViewingProj] = useState<Project | null>(null);
  const [sbomFormat, setSbomFormat] = useState<'cyclonedx' | 'spdx'>('cyclonedx');
  const [sbomPayload, setSbomPayload] = useState<Record<string, unknown> | null>(null);

  // SLSA Attestation Form
  const [attestProjectId, setAttestProjectId] = useState('');
  const [artifactSample, setArtifactSample] = useState('release-bundle-v1.0.0');
  const [expectedDigest, setExpectedDigest] = useState('');
  const [hmacSig, setHmacSig] = useState('');
  const [signingSecret, setSigningSecret] = useState('');

  const canWrite = user?.role !== 'Viewer';

  const openSbomModal = async (proj: Project, format: 'cyclonedx' | 'spdx') => {
    setViewingProj(proj);
    setSbomFormat(format);
    const res = await fetchProjectSbom(proj.id, format);
    if (res) {
      setSbomPayload(res);
    } else if (proj.sbom) {
      setSbomPayload({ format: 'cyclonedx', sbom: proj.sbom });
    }
  };

  const handleComputeDigestHelper = async () => {
    const enc = new TextEncoder().encode(artifactSample);
    const hashBuf = await crypto.subtle.digest('SHA-256', enc);
    const hex = Array.from(new Uint8Array(hashBuf))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
    setExpectedDigest(hex);
  };

  const handleAttestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const targetId = attestProjectId || projects[0]?.id;
    if (!targetId || !expectedDigest.trim()) return;
    await verifySlsaAttestation(targetId, {
      expectedDigestSha256: expectedDigest.trim(),
      artifactContent: artifactSample,
      ...(hmacSig.trim() ? { hmacSignature: hmacSig.trim() } : {}),
      ...(signingSecret.trim() ? { signingSecret: signingSecret.trim() } : {}),
    });
  };

  const exportEnterpriseSbom = () => {
    const bundle = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      organization: org.name,
      exportedAt: new Date().toISOString(),
      projects: projects.map((p) => ({
        name: p.name,
        slsaLevel: p.slsaLevel,
        sbomGenerated: p.sbomGenerated,
        sbom: p.sbom || null,
      })),
    };
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `trustrail-sbom-${org.slug}.cdx.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <PackageCheck className="w-5 h-5 text-emerald-500" />
              <span>Secure Software Supply Chain &amp; SBOM (CycloneDX 1.5 / SPDX 2.3)</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Multi-ecosystem SBOM generation, schema validation, typosquatting &amp; restrictive license alerts, and cryptographic SLSA provenance verification.
            </p>
          </div>
          <button
            type="button"
            onClick={exportEnterpriseSbom}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition whitespace-nowrap shrink-0 self-start"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export All CycloneDX SBOMs</span>
          </button>
        </div>

        {/* SLSA Provenance Verification Panel */}
        {canWrite && projects.length > 0 && (
          <form
            onSubmit={handleAttestSubmit}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-3"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-cyan-500" />
                <span>Verify Build Artifact SHA-256 &amp; SLSA Provenance Attestation</span>
              </span>
              <button
                type="button"
                onClick={handleComputeDigestHelper}
                className="px-2.5 py-1 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-[11px] font-mono text-cyan-500 hover:border-cyan-500/40"
              >
                Compute SHA-256 of Sample Artifact
              </button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <select
                value={attestProjectId || projects[0]?.id || ''}
                onChange={(e) => setAttestProjectId(e.target.value)}
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
              >
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name} ({p.slsaLevel})
                  </option>
                ))}
              </select>
              <input
                type="text"
                value={artifactSample}
                onChange={(e) => setArtifactSample(e.target.value)}
                placeholder="Release artifact payload / manifest"
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono"
              />
              <input
                type="text"
                required
                value={expectedDigest}
                onChange={(e) => setExpectedDigest(e.target.value)}
                placeholder="Expected SHA-256 hex digest (64 chars)"
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono"
              />
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 items-center">
              <input
                type="text"
                value={hmacSig}
                onChange={(e) => setHmacSig(e.target.value)}
                placeholder="Optional HMAC-SHA256 signature for SLSA 3"
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono"
              />
              <input
                type="password"
                value={signingSecret}
                onChange={(e) => setSigningSecret(e.target.value)}
                placeholder="Optional HMAC signing key"
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono"
              />
              <button
                type="submit"
                className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition"
              >
                Verify Attestation &amp; Upgrade SLSA
              </button>
            </div>
          </form>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {projects.map((proj) => {
            const supplyFindings = findings.filter(
              (f) => f.projectId === proj.id && (f.category === 'SUPPLY_CHAIN' || f.category === 'SCA') && f.status !== 'Resolved'
            );
            const hasCosign = proj.slsaLevel === 'SLSA 2' || proj.slsaLevel === 'SLSA 3';

            return (
              <div
                key={proj.id}
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-sm font-bold text-slate-900 dark:text-white">{proj.name}</span>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500/15 text-cyan-600 dark:text-cyan-300 border border-cyan-500/30">
                      {proj.slsaLevel}
                    </span>
                  </div>
                  <div className="space-y-2 text-xs text-slate-600 dark:text-slate-400 font-mono mb-4">
                    <div className="flex items-center justify-between">
                      <span>SBOM Status:</span>
                      {proj.sbomGenerated ? (
                        <span className="text-emerald-600 dark:text-emerald-400 flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Validated ({proj.sbom?.components?.length ?? 0} pkgs)
                        </span>
                      ) : (
                        <span className="text-amber-600 dark:text-amber-400 flex items-center gap-1">
                          <AlertTriangle className="w-3.5 h-3.5" /> Missing (Scan manifest)
                        </span>
                      )}
                    </div>
                    <div className="flex items-center justify-between">
                      <span>Build Provenance:</span>
                      <span className={hasCosign ? 'text-emerald-600 dark:text-emerald-400' : 'text-slate-500'}>
                        {hasCosign ? `Verified (${proj.slsaLevel})` : 'Unverified (No Attestation)'}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span>SCA / Supply Signals:</span>
                      <span className={supplyFindings.length > 0 ? 'text-rose-500' : 'text-emerald-600 dark:text-emerald-400'}>
                        {supplyFindings.length > 0 ? `${supplyFindings.length} open issue(s)` : '0 anomalies'}
                      </span>
                    </div>
                  </div>
                </div>
                <div className="pt-3 border-t border-slate-200 dark:border-slate-900 flex flex-wrap items-center justify-between gap-2">
                  <span className="text-[11px] text-slate-500 font-mono">Last Scan: {proj.lastScanned}</span>
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      disabled={!proj.sbomGenerated}
                      onClick={() => openSbomModal(proj, 'cyclonedx')}
                      className="px-2.5 py-1.5 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-cyan-600 dark:text-cyan-400 text-xs font-semibold transition border border-slate-200 dark:border-slate-800 disabled:opacity-40"
                    >
                      CycloneDX
                    </button>
                    <button
                      type="button"
                      disabled={!proj.sbomGenerated}
                      onClick={() => openSbomModal(proj, 'spdx')}
                      className="px-2.5 py-1.5 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-emerald-600 dark:text-emerald-400 text-xs font-semibold transition border border-slate-200 dark:border-slate-800 disabled:opacity-40 flex items-center gap-1"
                    >
                      <FileCode2 className="w-3 h-3" />
                      <span>SPDX 2.3</span>
                    </button>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {viewingProj && (
        <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl p-6 space-y-4 text-slate-100">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-3">
                <h3 className="text-sm font-bold">
                  {sbomFormat === 'spdx' ? 'SPDX 2.3' : 'CycloneDX 1.5'} SBOM — {viewingProj.name}
                </h3>
                <button
                  type="button"
                  onClick={() => openSbomModal(viewingProj, sbomFormat === 'cyclonedx' ? 'spdx' : 'cyclonedx')}
                  className="px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 text-[11px] font-mono"
                >
                  Switch to {sbomFormat === 'cyclonedx' ? 'SPDX 2.3' : 'CycloneDX 1.5'}
                </button>
              </div>
              <button type="button" onClick={() => setViewingProj(null)} className="text-slate-400 hover:text-white">
                <X className="w-4 h-4" />
              </button>
            </div>
            <pre className="bg-slate-950 border border-slate-800 rounded-xl p-4 text-xs font-mono text-emerald-300 max-h-96 overflow-auto">
              {JSON.stringify(sbomPayload || viewingProj.sbom, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}
