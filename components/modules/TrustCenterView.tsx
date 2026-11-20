'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { BadgeCheck, Share2, CheckCircle2, ExternalLink, Copy, Ban, RotateCcw } from 'lucide-react';

export function TrustCenterView() {
  const { trustReceipts, issueTrustPassport, revokeTrustPassport, user, org } = useTrustrail();
  const [showCreate, setShowCreate] = useState(false);
  const [title, setTitle] = useState('');
  const [scopeText, setScopeText] = useState(
    'SOC 2 Type II Continuous Monitoring, Cryptographic Audit Chain, SAST/SCA Enforcement'
  );
  const [expiresDays, setExpiresDays] = useState(180);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const isAdmin = user?.role === 'Owner' || user?.role === 'Admin';

  const handleIssue = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    const scope = scopeText
      .split(',')
      .map((s) => s.trim())
      .filter((s) => s.length >= 2);
    if (scope.length === 0) return;
    await issueTrustPassport(title.trim(), scope, expiresDays);
    setTitle('');
    setShowCreate(false);
  };

  const handleCopy = async (id: string) => {
    const shareUrl = `${window.location.origin}/trust/${id}`;
    try {
      await navigator.clipboard.writeText(shareUrl);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      // Fallback ignored if clipboard blocked
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <BadgeCheck className="w-5 h-5 text-cyan-500" />
              <span>Customer Trust Center &amp; Security Passport</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Cryptographically signed public Trust Passports for {org.name} (Rating: {org.securityRating}).
            </p>
          </div>
          {isAdmin && (
            <button
              type="button"
              onClick={() => setShowCreate(!showCreate)}
              className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition shrink-0 self-start"
            >
              <Share2 className="w-3.5 h-3.5" />
              <span>Issue Trust Passport</span>
            </button>
          )}
        </div>

        {showCreate && (
          <form
            onSubmit={handleIssue}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 mb-6 space-y-3"
          >
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="md:col-span-2">
                <label className="text-[10px] font-mono text-slate-500 uppercase">Passport Title</label>
                <input
                  type="text"
                  required
                  placeholder="Enterprise Customer Security Attestation Q4"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  className="w-full mt-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
                />
              </div>
              <div>
                <label className="text-[10px] font-mono text-slate-500 uppercase">Validity (Days)</label>
                <input
                  type="number"
                  min={1}
                  max={365}
                  value={expiresDays}
                  onChange={(e) => setExpiresDays(Number(e.target.value) || 180)}
                  className="w-full mt-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono"
                />
              </div>
            </div>
            <div>
              <label className="text-[10px] font-mono text-slate-500 uppercase">
                Verified Attestation Scope (comma-separated)
              </label>
              <input
                type="text"
                required
                value={scopeText}
                onChange={(e) => setScopeText(e.target.value)}
                className="w-full mt-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
              />
            </div>
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setShowCreate(false)}
                className="px-3 py-1.5 rounded-lg border border-slate-200 dark:border-slate-800 text-xs"
              >
                Cancel
              </button>
              <button type="submit" className="px-4 py-1.5 rounded-lg bg-cyan-600 text-white text-xs font-semibold">
                Sign &amp; Issue Passport
              </button>
            </div>
          </form>
        )}

        <div className="space-y-4">
          {trustReceipts.length === 0 ? (
            <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-8 text-center text-xs text-slate-500">
              No Trust Passports issued yet for {org.name}. Issue one to share sanitized compliance posture with external auditors or customers.
            </div>
          ) : (
            trustReceipts.map((tr) => (
              <div
                key={tr.id}
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-6"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 mb-4">
                  <div className="flex items-center space-x-2">
                    <span
                      className={`px-2.5 py-1 rounded text-xs font-mono font-bold border ${
                        tr.revoked
                          ? 'bg-rose-500/15 text-rose-500 border-rose-500/30'
                          : 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                      }`}
                    >
                      {tr.revoked ? 'Revoked' : 'Passport Active'}
                    </span>
                    <span className="text-xs font-mono text-cyan-600 dark:text-cyan-400">ID: {tr.id}</span>
                  </div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-xs text-slate-500 font-mono mr-2">Access Views: {tr.accessCount}</span>
                    <button
                      type="button"
                      onClick={() => handleCopy(tr.id)}
                      className="flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs hover:border-cyan-500/40"
                    >
                      <Copy className="w-3 h-3" />
                      <span>{copiedId === tr.id ? 'Copied!' : 'Copy Share Link'}</span>
                    </button>
                    <a
                      href={`/trust/${tr.id}`}
                      target="_blank"
                      rel="noreferrer"
                      className="flex items-center space-x-1 px-2.5 py-1 rounded-lg bg-cyan-600/15 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30 text-xs font-semibold hover:bg-cyan-600/25"
                    >
                      <ExternalLink className="w-3 h-3" />
                      <span>Open Public View</span>
                    </a>
                    {isAdmin && (
                      <button
                        type="button"
                        onClick={() => revokeTrustPassport(tr.id)}
                        className={`flex items-center space-x-1 px-2.5 py-1 rounded-lg text-xs font-semibold border ${
                          tr.revoked
                            ? 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                            : 'bg-rose-500/15 text-rose-500 border-rose-500/30'
                        }`}
                      >
                        {tr.revoked ? <RotateCcw className="w-3 h-3" /> : <Ban className="w-3 h-3" />}
                        <span>{tr.revoked ? 'Reinstate' : 'Revoke'}</span>
                      </button>
                    )}
                  </div>
                </div>

                <div className="text-base font-bold text-slate-900 dark:text-white mb-2">{tr.title}</div>
                <div className="text-xs text-slate-500 mb-4 font-mono">
                  Issued: {tr.issuedAt} • Expires: {tr.expiresAt}
                </div>

                <div className="space-y-2 mb-4">
                  <div className="text-[10px] font-mono text-slate-500 uppercase">Verified Scope &amp; Attestations</div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {tr.scope.map((s, i) => (
                      <div
                        key={i}
                        className="text-xs text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 flex items-center space-x-2"
                      >
                        <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                        <span>{s}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="text-[11px] font-mono text-slate-500 pt-3 border-t border-slate-200 dark:border-slate-900 truncate">
                  Cryptographic Signature: {tr.signature}
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
