'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { LifeBuoy, RefreshCw, DatabaseBackup, ShieldCheck } from 'lucide-react';

export function RecoveryView() {
  const {
    projects,
    incidents,
    canaries,
    auditChainVerified,
    recoveryBackups,
    createBackupSnapshot,
    verifyBackupRestore,
    refreshAll,
    org,
    user,
  } = useTrustrail();
  const [verifying, setVerifying] = useState(false);
  const [targetName, setTargetName] = useState('primary-tenant-security-state');
  const [backupType, setBackupType] = useState<'Full Snapshot' | 'Incremental WAL' | 'Config & Keys'>('Full Snapshot');

  const isAdmin = user?.role === 'Owner' || user?.role === 'Admin';
  const openIncidents = incidents.filter((i) => i.status === 'Open').length;
  const armedCanaries = canaries.filter((c) => c.status === 'Armed').length;
  const sbomReadyCount = projects.filter((p) => p.sbomGenerated).length;
  const verifiedBackupCount = recoveryBackups.filter((b) => b.restoreStatus === 'Verified').length;

  const readinessChecks = [
    {
      name: 'Immutable Audit Ledger SHA-256 Chain',
      detail: auditChainVerified ? 'Hash linkage verified across all tenant entries' : 'Chain discrepancy detected',
      ok: auditChainVerified,
    },
    {
      name: 'Repository SBOM & Provenance Inventory',
      detail: `${sbomReadyCount} of ${projects.length} repositories have CycloneDX SBOM snapshots`,
      ok: projects.length === 0 || sbomReadyCount === projects.length,
    },
    {
      name: 'Checksummed Recovery Backup Verification',
      detail: `${verifiedBackupCount} restore-verified snapshot(s) across ${recoveryBackups.length} total backup(s)`,
      ok: verifiedBackupCount > 0,
    },
    {
      name: 'Incident Containment & Recovery Posture',
      detail: `${openIncidents} uncontained SEV incidents across ${incidents.length} total incidents`,
      ok: openIncidents === 0,
    },
    {
      name: 'Ransomware & Lateral-Movement Tripwires',
      detail: `${armedCanaries} armed deception canaries monitoring repositories & vaults`,
      ok: armedCanaries > 0,
    },
  ];

  const passed = readinessChecks.filter((c) => c.ok).length;
  const readinessScore = Math.round((passed / readinessChecks.length) * 100);

  const handleVerify = async () => {
    setVerifying(true);
    try {
      await refreshAll();
    } finally {
      setVerifying(false);
    }
  };

  const handleCreateSnapshot = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetName.trim()) return;
    await createBackupSnapshot(targetName.trim(), backupType);
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <LifeBuoy className="w-5 h-5 text-cyan-500" />
              <span>Recovery, Backups &amp; Ransomware Readiness</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Live resilience posture, SHA-256 checksummed snapshots, and SQLite PRAGMA restore integrity tests for {org.name}.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-cyan-500/15 text-cyan-600 dark:text-cyan-300 border border-cyan-500/30">
              Readiness Score: {readinessScore}%
            </span>
            <button
              type="button"
              onClick={handleVerify}
              disabled={verifying}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold transition"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
              <span>{verifying ? 'Verifying...' : 'Run Readiness Verification'}</span>
            </button>
          </div>
        </div>

        {/* Backup Snapshot Creation & Restore Verification */}
        {isAdmin && (
          <form
            onSubmit={handleCreateSnapshot}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row gap-3 items-stretch sm:items-center"
          >
            <DatabaseBackup className="w-4 h-4 text-cyan-500 shrink-0" />
            <input
              type="text"
              required
              value={targetName}
              onChange={(e) => setTargetName(e.target.value)}
              placeholder="Snapshot Target Name"
              className="flex-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono"
            />
            <select
              value={backupType}
              onChange={(e) => setBackupType(e.target.value as 'Full Snapshot' | 'Incremental WAL' | 'Config & Keys')}
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs"
            >
              <option value="Full Snapshot">Full Snapshot</option>
              <option value="Incremental WAL">Incremental WAL</option>
              <option value="Config & Keys">Config &amp; Keys</option>
            </select>
            <button
              type="submit"
              className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold whitespace-nowrap"
            >
              Create Checksummed Snapshot
            </button>
          </form>
        )}

        {recoveryBackups.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono">
              Recovery Snapshots ({recoveryBackups.length})
            </div>
            {recoveryBackups.map((b) => (
              <div
                key={b.id}
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="min-w-0">
                  <div className="text-xs font-bold font-mono text-slate-900 dark:text-white">
                    {b.targetName} ({b.backupType})
                  </div>
                  <div className="text-[11px] font-mono text-slate-500 truncate">
                    {b.checksumSha256} • {b.sizeBytes} bytes • Status: {b.restoreStatus}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-mono font-bold border ${
                      b.restoreStatus === 'Verified'
                        ? 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                        : b.restoreStatus === 'Failed'
                        ? 'bg-rose-500/15 text-rose-500 border-rose-500/30'
                        : 'bg-amber-500/15 text-amber-500 border-amber-500/30'
                    }`}
                  >
                    {b.restoreStatus}
                  </span>
                  {isAdmin && (
                    <button
                      type="button"
                      onClick={() => verifyBackupRestore(b.id)}
                      className="inline-flex items-center gap-1 px-3 py-1 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
                    >
                      <ShieldCheck className="w-3.5 h-3.5" />
                      <span>Verify Restore</span>
                    </button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}

        <div className="space-y-3">
          {readinessChecks.map((check, idx) => (
            <div
              key={idx}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div className="flex items-center space-x-3">
                <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-500 shrink-0">
                  <LifeBuoy className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-sm font-bold text-slate-900 dark:text-white font-mono">{check.name}</div>
                  <div className="text-xs text-slate-500">{check.detail}</div>
                </div>
              </div>
              <span
                className={`px-2.5 py-1 rounded text-xs font-mono font-bold border self-start sm:self-center ${
                  check.ok
                    ? 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                    : 'bg-amber-500/15 text-amber-500 border-amber-500/30'
                }`}
              >
                {check.ok ? 'Verified' : 'Attention Needed'}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
