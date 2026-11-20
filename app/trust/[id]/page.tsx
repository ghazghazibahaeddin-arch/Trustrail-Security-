'use client';

import React, { useEffect, useState } from 'react';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { ShieldCheck, CheckCircle2, XCircle, ArrowLeft, Lock } from 'lucide-react';

interface PublicPassport {
  id: string;
  title: string;
  organizationName: string;
  securityRating: string;
  compliancePercentage: number;
  issuedAt: string;
  expiresAt: string;
  scope: string[];
  signature: string;
  accessCount: number;
  verifiedControls: Array<{
    framework: string;
    code: string;
    title: string;
    status: string;
    lastVerified: string;
  }>;
}

export default function PublicTrustPassportPage() {
  const params = useParams<{ id: string }>();
  const [passport, setPassport] = useState<PublicPassport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!params?.id) return;
    fetch(`/api/v1/trust-center/${encodeURIComponent(params.id)}`)
      .then(async (res) => {
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || 'Passport unavailable');
        setPassport(data.passport);
      })
      .catch((err) => setError((err as Error).message))
      .finally(() => setLoading(false));
  }, [params?.id]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 py-12 px-4">
      <div className="max-w-3xl mx-auto space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-10 h-10 rounded-xl bg-cyan-600 flex items-center justify-center">
              <ShieldCheck className="w-6 h-6 text-white" />
            </div>
            <div>
              <div className="font-bold tracking-wider text-white">TRUSTRAIL SECURITY PASSPORT</div>
              <div className="text-xs text-slate-400">Cryptographically Verifiable Customer Trust Attestation</div>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <Link
              href="/login"
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-xs text-white font-semibold transition whitespace-nowrap"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Sign In</span>
            </Link>
            <Link
              href="/"
              className="inline-flex items-center space-x-1.5 text-xs text-cyan-400 hover:underline font-medium whitespace-nowrap"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span>Platform Console</span>
            </Link>
          </div>
        </div>

        {loading && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 text-center text-sm text-slate-400">
            Verifying passport signature and revocation state...
          </div>
        )}

        {error && (
          <div className="bg-slate-900 border border-rose-500/40 rounded-2xl p-8 text-center space-y-3">
            <XCircle className="w-10 h-10 text-rose-400 mx-auto" />
            <div className="text-lg font-bold text-white">Trust Passport Unavailable</div>
            <div className="text-sm text-rose-300">{error}</div>
          </div>
        )}

        {passport && (
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-8 space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-800">
              <div>
                <div className="text-xs font-mono text-cyan-400 mb-1">
                  ORGANIZATION: {passport.organizationName.toUpperCase()}
                </div>
                <h1 className="text-xl font-bold text-white">{passport.title}</h1>
                <div className="text-xs text-slate-400 font-mono mt-1">
                  ID: {passport.id} • Issued: {passport.issuedAt} • Expires: {passport.expiresAt}
                </div>
              </div>
              <div className="flex items-center space-x-3 shrink-0">
                <div className="bg-slate-950 border border-slate-800 rounded-xl px-4 py-2 text-center">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Rating</div>
                  <div className="text-lg font-bold font-mono text-emerald-400 tabular-nums">{passport.securityRating}</div>
                </div>
                <div className="bg-slate-950 border border-slate-800 rounded-xl px-4 py-2 text-center">
                  <div className="text-[10px] font-mono text-slate-400 uppercase">Compliance</div>
                  <div className="text-lg font-bold font-mono text-cyan-400 tabular-nums">{passport.compliancePercentage}%</div>
                </div>
              </div>
            </div>

            <div className="space-y-3">
              <h2 className="text-xs font-mono uppercase tracking-wider text-slate-400">Attested Security Scope</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {passport.scope.map((item, idx) => (
                  <div key={idx} className="bg-slate-950 border border-slate-800 rounded-xl p-3 flex items-center space-x-2 text-xs text-slate-200">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="space-y-3">
              <h2 className="text-xs font-mono uppercase tracking-wider text-slate-400">
                Verified Compliance Controls ({passport.verifiedControls.length})
              </h2>
              <div className="space-y-2">
                {passport.verifiedControls.map((ctrl, idx) => (
                  <div key={idx} className="bg-slate-950 border border-slate-800 rounded-xl p-3 flex items-center justify-between text-xs">
                    <div>
                      <span className="font-mono text-cyan-400 font-semibold">{ctrl.framework} {ctrl.code}</span>
                      <span className="text-slate-300 ml-2">{ctrl.title}</span>
                    </div>
                    <span className="font-mono text-emerald-400">{ctrl.lastVerified}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-4 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-[11px] font-mono text-slate-400">
              <span className="flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-emerald-400" />
                Signature: {passport.signature}
              </span>
              <span className="tabular-nums">Verified Views: {passport.accessCount}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
