'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { EnforcementMode, Role } from '@/lib/trustrail-store';
import {
  Settings as SettingsIcon,
  ShieldCheck,
  Download,
  Save,
  CheckCircle2,
  AlertTriangle,
  KeyRound,
  Plus,
  Trash2,
  Copy,
  Check,
  Terminal,
  RefreshCw,
  Lock,
  UserCheck,
  Activity,
  RotateCcw,
} from 'lucide-react';

export function SettingsView() {
  const {
    org,
    auditLogs,
    auditChainVerified,
    updateOrgSettings,
    apiKeys,
    createApiKey,
    rotateApiKey,
    revokeApiKey,
    rotateVaultSecrets,
    user,
    updateProfile,
    setupMfa,
    verifyMfa,
    disableMfa,
    verifyEmail,
    refreshSessionToken,
    systemMetrics,
    backgroundJobs,
    enqueueBackgroundJob,
    retryBackgroundJob,
  } = useTrustrail();

  const [draft, setDraft] = useState<{
    orgId: string;
    name?: string;
    retentionDays?: number;
    threatSharing?: boolean;
    enforcementMode?: EnforcementMode;
  }>({ orgId: org.id });
  const [saving, setSaving] = useState(false);

  // Profile & MFA state
  const [profileName, setProfileName] = useState(user?.name || '');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [mfaSecretInfo, setMfaSecretInfo] = useState<{ secret: string; otpauthUri: string } | null>(null);
  const [mfaCodeInput, setMfaCodeInput] = useState('');
  const [emailTokenInput, setEmailTokenInput] = useState('');

  // API Key creation state
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyRole, setNewKeyRole] = useState<Role>('Developer');
  const [newKeyScopes, setNewKeyScopes] = useState<string[]>(['read', 'scan', 'write']);
  const [newKeyExpiresDays, setNewKeyExpiresDays] = useState<number>(90);
  const [creatingKey, setCreatingKey] = useState(false);
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);
  const [copiedSecret, setCopiedSecret] = useState(false);

  const isAdmin = user?.role === 'Owner' || user?.role === 'Admin';
  const canIssueKeys = user?.role !== 'Viewer';

  const allowedKeyRoles: Role[] =
    user?.role === 'Owner'
      ? ['Owner', 'Admin', 'Developer', 'Viewer']
      : user?.role === 'Admin'
      ? ['Admin', 'Developer', 'Viewer']
      : ['Developer', 'Viewer'];

  const name = draft.orgId === org.id && draft.name !== undefined ? draft.name : org.name;
  const retentionDays =
    draft.orgId === org.id && draft.retentionDays !== undefined
      ? draft.retentionDays
      : (org.dataRetentionDays ?? 90);
  const threatSharing =
    draft.orgId === org.id && draft.threatSharing !== undefined
      ? draft.threatSharing
      : (org.threatSharingOptIn ?? false);
  const enforcementMode: EnforcementMode =
    draft.orgId === org.id && draft.enforcementMode !== undefined
      ? draft.enforcementMode
      : (org.enforcementMode ?? 'Enforce');

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isAdmin || !name.trim()) return;
    setSaving(true);
    try {
      await updateOrgSettings({
        name: name.trim(),
        dataRetentionDays: retentionDays,
        threatSharingOptIn: threatSharing,
        enforcementMode,
      });
      setDraft({ orgId: org.id });
    } finally {
      setSaving(false);
    }
  };

  const handleProfileSave = async (e: React.FormEvent) => {
    e.preventDefault();
    const ok = await updateProfile({
      ...(profileName.trim() ? { name: profileName.trim() } : {}),
      ...(newPassword.trim() ? { currentPassword, newPassword: newPassword.trim() } : {}),
    });
    if (ok) {
      setCurrentPassword('');
      setNewPassword('');
    }
  };

  const handleStartMfa = async () => {
    const res = await setupMfa();
    if (res) setMfaSecretInfo(res);
  };

  const handleVerifyMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaCodeInput.trim()) return;
    const ok = await verifyMfa(mfaCodeInput.trim());
    if (ok) {
      setMfaSecretInfo(null);
      setMfaCodeInput('');
    }
  };

  const toggleScope = (scope: string) => {
    setNewKeyScopes((prev) =>
      prev.includes(scope)
        ? prev.length > 1
          ? prev.filter((s) => s !== scope)
          : prev
        : [...prev, scope]
    );
  };

  const handleCreateApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newKeyName.trim()) return;
    setCreatingKey(true);
    try {
      const res = await createApiKey(newKeyName.trim(), newKeyRole, newKeyScopes, newKeyExpiresDays);
      if (res?.secret) {
        setRevealedSecret(res.secret);
        setCopiedSecret(false);
        setNewKeyName('');
      }
    } finally {
      setCreatingKey(false);
    }
  };

  const handleRotateApiKey = async (id: string) => {
    const res = await rotateApiKey(id);
    if (res?.secret) {
      setRevealedSecret(res.secret);
      setCopiedSecret(false);
    }
  };

  const handleCopySecret = async () => {
    if (!revealedSecret) return;
    try {
      await navigator.clipboard.writeText(revealedSecret);
      setCopiedSecret(true);
      setTimeout(() => setCopiedSecret(false), 2500);
    } catch {
      // Clipboard fallback ignored
    }
  };

  const handleDownloadAuditLedger = () => {
    const payload = {
      exportedAt: new Date().toISOString(),
      organization: { id: org.id, name: org.name, slug: org.slug },
      hashChainVerified: auditChainVerified,
      totalEntries: auditLogs.length,
      entries: auditLogs,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `trustrail-audit-ledger-${org.slug || 'org'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <SettingsIcon className="w-5 h-5 text-cyan-500" />
              <span>Settings, Account MFA, Vault &amp; Security Governance</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Workspace policy enforcement mode, AES-256-GCM vault rotation, TOTP MFA, scoped API keys, worker queues, and SHA-256 audit ledger.
            </p>
          </div>
          <span
            className={`px-3 py-1 rounded-full text-xs font-mono font-bold border flex items-center gap-1.5 self-start whitespace-nowrap ${
              auditChainVerified
                ? 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                : 'bg-rose-500/15 text-rose-500 border-rose-500/30'
            }`}
          >
            {auditChainVerified ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertTriangle className="w-3.5 h-3.5" />}
            <span>{auditChainVerified ? 'SHA-256 Audit Chain Verified' : 'Chain Verification Failed'}</span>
          </span>
        </div>

        <div className="space-y-6">
          {/* Account Security: Profile, Email Verification & TOTP MFA */}
          <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                <UserCheck className="w-4 h-4 text-cyan-500" />
                <span>Personal Account Security ({user?.email})</span>
              </h2>
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                    user?.emailVerified
                      ? 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                      : 'bg-amber-500/15 text-amber-500 border-amber-500/30'
                  }`}
                >
                  {user?.emailVerified ? 'Email Verified' : 'Email Unverified'}
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${
                    user?.mfaVerified
                      ? 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                      : 'bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-300 border-slate-300 dark:border-slate-700'
                  }`}
                >
                  {user?.mfaVerified ? 'TOTP MFA Enforced' : 'TOTP MFA Not Verified'}
                </span>
                <button
                  type="button"
                  onClick={refreshSessionToken}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-[11px] font-semibold hover:border-cyan-500/40"
                >
                  <RefreshCw className="w-3 h-3 text-cyan-500" />
                  <span>Rotate Session JWT</span>
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Profile & Password Update */}
              <form onSubmit={handleProfileSave} className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 space-y-3">
                <div className="text-xs font-bold text-slate-900 dark:text-white">Profile &amp; Password Rotation</div>
                <input
                  type="text"
                  value={profileName}
                  onChange={(e) => setProfileName(e.target.value)}
                  placeholder="Display Name"
                  className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs"
                />
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <input
                    type="password"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    placeholder="Current password (if changing)"
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs"
                  />
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="New password (min 8 chars)"
                    className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs"
                  />
                </div>
                <button
                  type="submit"
                  className="px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
                >
                  Save Profile &amp; Password
                </button>
              </form>

              {/* TOTP MFA Setup & Email Verify */}
              <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
                    <Lock className="w-3.5 h-3.5 text-cyan-500" />
                    <span>RFC 6238 Two-Factor Authentication (TOTP)</span>
                  </span>
                  {user?.mfaVerified ? (
                    <button
                      type="button"
                      onClick={disableMfa}
                      className="px-2.5 py-1 rounded bg-rose-500/15 text-rose-500 text-[11px] font-semibold"
                    >
                      Disable MFA
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={handleStartMfa}
                      className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-[11px] font-semibold"
                    >
                      Setup TOTP MFA
                    </button>
                  )}
                </div>

                {mfaSecretInfo && (
                  <form onSubmit={handleVerifyMfa} className="space-y-2 p-2.5 rounded bg-slate-50 dark:bg-slate-950 border border-cyan-500/30">
                    <div className="text-[11px] font-mono text-cyan-500 break-all">
                      Secret: {mfaSecretInfo.secret}
                    </div>
                    <div className="text-[10px] font-mono text-slate-500 break-all">
                      URI: {mfaSecretInfo.otpauthUri}
                    </div>
                    <div className="flex gap-2">
                      <input
                        type="text"
                        required
                        value={mfaCodeInput}
                        onChange={(e) => setMfaCodeInput(e.target.value)}
                        placeholder="Enter 6-digit TOTP code"
                        className="flex-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded px-2.5 py-1 text-xs font-mono"
                      />
                      <button type="submit" className="px-3 py-1 rounded bg-emerald-600 text-white text-xs font-semibold">
                        Verify Code
                      </button>
                    </div>
                  </form>
                )}

                {!user?.emailVerified && (
                  <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-200 dark:border-slate-800">
                    <input
                      type="text"
                      value={emailTokenInput}
                      onChange={(e) => setEmailTokenInput(e.target.value)}
                      placeholder="Paste tr_ver_... token"
                      className="flex-1 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded px-2.5 py-1 text-xs font-mono"
                    />
                    <button
                      type="button"
                      onClick={() => verifyEmail({ token: emailTokenInput.trim() })}
                      className="px-2.5 py-1 rounded bg-emerald-600 text-white text-[11px] font-semibold"
                    >
                      Verify Email
                    </button>
                    <button
                      type="button"
                      onClick={async () => {
                        const r = await verifyEmail({ resend: true });
                        if (r?.verificationTokenPreview) setEmailTokenInput(r.verificationTokenPreview);
                      }}
                      className="px-2.5 py-1 rounded bg-slate-200 dark:bg-slate-800 text-[11px] font-semibold"
                    >
                      Resend Token
                    </button>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Organization Governance */}
          <form
            onSubmit={handleSave}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 className="text-sm font-bold text-slate-900 dark:text-white">Organization Governance &amp; Vault Controls</h2>
              {isAdmin && (
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={rotateVaultSecrets}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 hover:border-cyan-500/40 text-xs font-semibold transition whitespace-nowrap"
                  >
                    <RotateCcw className="w-3.5 h-3.5 text-cyan-500" />
                    <span>Rotate Vault Keys (v{systemMetrics?.vaultKeyVersion ?? 1})</span>
                  </button>
                  <button
                    type="submit"
                    disabled={saving}
                    className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold transition whitespace-nowrap"
                  >
                    <Save className="w-3.5 h-3.5" />
                    <span>{saving ? 'Saving...' : 'Save Settings'}</span>
                  </button>
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-4">
              <div>
                <label className="text-[10px] font-mono text-slate-500 uppercase">Organization Name</label>
                <input
                  type="text"
                  value={name}
                  disabled={!isAdmin}
                  onChange={(e) => setDraft((d) => ({ ...d, orgId: org.id, name: e.target.value }))}
                  className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs mt-1 disabled:opacity-60"
                />
              </div>
              <div>
                <label className="text-[10px] font-mono text-slate-500 uppercase">Organization Slug</label>
                <input
                  type="text"
                  value={org.slug}
                  readOnly
                  className="w-full bg-slate-100 dark:bg-slate-900/60 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-500 mt-1"
                />
              </div>
              <div>
                <label className="text-[10px] font-mono text-slate-500 uppercase">Audit Retention (Days)</label>
                <input
                  type="number"
                  min={7}
                  max={3650}
                  disabled={!isAdmin}
                  value={retentionDays}
                  onChange={(e) => setDraft((d) => ({ ...d, orgId: org.id, retentionDays: Number(e.target.value) || 90 }))}
                  className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono mt-1 disabled:opacity-60 tabular-nums"
                />
              </div>
              <div>
                <label className="text-[10px] font-mono text-slate-500 uppercase">Policy Enforcement Mode</label>
                <select
                  disabled={!isAdmin}
                  value={enforcementMode}
                  onChange={(e) => setDraft((d) => ({ ...d, orgId: org.id, enforcementMode: e.target.value as EnforcementMode }))}
                  className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono mt-1 disabled:opacity-60"
                >
                  <option value="Observe">Observe (Log only)</option>
                  <option value="Recommend">Recommend (Warn)</option>
                  <option value="Enforce">Enforce (Block violations)</option>
                </select>
              </div>
            </div>

            <label className="flex items-center space-x-2 text-xs text-slate-700 dark:text-slate-300 cursor-pointer">
              <input
                type="checkbox"
                disabled={!isAdmin}
                checked={threatSharing}
                onChange={(e) => setDraft((d) => ({ ...d, orgId: org.id, threatSharing: e.target.checked }))}
                className="rounded border-slate-300 dark:border-slate-700"
              />
              <span>Participate in anonymized IOC &amp; malicious package threat intelligence sharing (opt-in)</span>
            </label>
          </form>

          {/* Scoped API Keys */}
          <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <KeyRound className="w-4 h-4 text-cyan-500" />
                  <span>Scoped Developer &amp; CI/CD API Keys</span>
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Keys are SHA-256 hashed server-side, support least-privilege scopes &amp; TTL expiry, and rotate atomically.
                </p>
              </div>
            </div>

            {canIssueKeys && (
              <form onSubmit={handleCreateApiKey} className="space-y-3">
                <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 items-end">
                  <div className="sm:col-span-2">
                    <label className="text-[10px] font-mono text-slate-500 uppercase">Key Name</label>
                    <input
                      type="text"
                      required
                      minLength={2}
                      value={newKeyName}
                      onChange={(e) => setNewKeyName(e.target.value)}
                      placeholder="github-actions-ci"
                      className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs mt-1"
                    />
                  </div>
                  <div>
                    <label className="text-[10px] font-mono text-slate-500 uppercase">RBAC Role</label>
                    <select
                      value={newKeyRole}
                      onChange={(e) => setNewKeyRole(e.target.value as Role)}
                      className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs mt-1"
                    >
                      {allowedKeyRoles.map((r) => (
                        <option key={r} value={r}>
                          {r}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] font-mono text-slate-500 uppercase">Expires (Days)</label>
                    <select
                      value={newKeyExpiresDays}
                      onChange={(e) => setNewKeyExpiresDays(Number(e.target.value))}
                      className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs mt-1"
                    >
                      <option value={30}>30 Days</option>
                      <option value={90}>90 Days</option>
                      <option value={180}>180 Days</option>
                      <option value={365}>365 Days</option>
                    </select>
                  </div>
                  <button
                    type="submit"
                    disabled={creatingKey}
                    className="flex items-center justify-center space-x-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold transition whitespace-nowrap"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>{creatingKey ? 'Issuing...' : 'Generate API Key'}</span>
                  </button>
                </div>

                <div className="flex flex-wrap items-center gap-3 text-xs text-slate-600 dark:text-slate-300">
                  <span className="text-[10px] font-mono uppercase text-slate-500">Scopes:</span>
                  {(['read', 'scan', 'write', ...(isAdmin ? ['admin'] : [])] as const).map((sc) => (
                    <label key={sc} className="inline-flex items-center gap-1.5 cursor-pointer font-mono">
                      <input
                        type="checkbox"
                        checked={newKeyScopes.includes(sc)}
                        onChange={() => toggleScope(sc)}
                      />
                      <span>{sc}</span>
                    </label>
                  ))}
                </div>
              </form>
            )}

            {revealedSecret && (
              <div className="p-4 rounded-xl bg-emerald-500/10 border border-emerald-500/30 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-bold text-emerald-600 dark:text-emerald-300">
                    Copy Your API Key Now — It Will Not Be Shown Again
                  </span>
                  <button
                    type="button"
                    onClick={handleCopySecret}
                    className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold whitespace-nowrap"
                  >
                    {copiedSecret ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                    <span>{copiedSecret ? 'Copied' : 'Copy Secret'}</span>
                  </button>
                </div>
                <div className="bg-slate-950 text-emerald-300 font-mono text-xs p-2.5 rounded-lg break-all border border-emerald-500/20">
                  {revealedSecret}
                </div>
              </div>
            )}

            <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
              <table className="w-full text-left border-collapse text-xs">
                <thead className="bg-white dark:bg-slate-900 text-[10px] font-mono uppercase text-slate-500 border-b border-slate-200 dark:border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">Name</th>
                    <th className="py-2.5 px-3">Prefix</th>
                    <th className="py-2.5 px-3">Role &amp; Scopes</th>
                    <th className="py-2.5 px-3">Expires</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                  {apiKeys.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="py-6 text-center text-slate-500">
                        No API keys issued yet for {org.name}. Generate one above for CI/CD, SDK, or MCP automation.
                      </td>
                    </tr>
                  ) : (
                    apiKeys.map((k) => (
                      <tr key={k.id} className="hover:bg-white/60 dark:hover:bg-slate-900/60">
                        <td className="py-2 px-3 font-semibold text-slate-900 dark:text-white">{k.name}</td>
                        <td className="py-2 px-3 font-mono text-cyan-600 dark:text-cyan-400">{k.keyPrefix}</td>
                        <td className="py-2 px-3 font-mono text-[11px]">
                          {k.role} ({(k.scopes || []).join(', ')})
                        </td>
                        <td className="py-2 px-3 font-mono text-[11px] text-slate-500">
                          {k.expiresAt ? k.expiresAt.slice(0, 10) : 'Never'}
                        </td>
                        <td className="py-2 px-3 font-mono">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              k.revoked
                                ? 'bg-rose-500/15 text-rose-500'
                                : 'bg-emerald-500/15 text-emerald-500'
                            }`}
                          >
                            {k.revoked ? 'Revoked' : 'Active'}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-right">
                          {!k.revoked && canIssueKeys && (
                            <div className="inline-flex items-center gap-1.5">
                              <button
                                type="button"
                                onClick={() => handleRotateApiKey(k.id)}
                                className="inline-flex items-center space-x-1 px-2 py-1 rounded bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-500 text-[11px] font-semibold"
                              >
                                <RefreshCw className="w-3 h-3" />
                                <span>Rotate</span>
                              </button>
                              <button
                                type="button"
                                onClick={() => revokeApiKey(k.id)}
                                className="inline-flex items-center space-x-1 px-2 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-500 text-[11px] font-semibold"
                              >
                                <Trash2 className="w-3 h-3" />
                                <span>Revoke</span>
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 text-[11px] font-mono text-slate-300 space-y-1.5">
              <div className="flex items-center gap-1.5 text-cyan-400 font-semibold">
                <Terminal className="w-3.5 h-3.5" />
                <span>CI/CD API Quickstart (cURL / GitHub Actions)</span>
              </div>
              <pre className="overflow-x-auto text-slate-300">
{`curl -X POST https://your-host/api/v1/integrations/github/scan-repo \\
  -H "Authorization: Bearer tr_live_YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"repo": "owner/service"}'`}
              </pre>
            </div>
          </div>

          {/* Background Jobs & Webhook Deliveries */}
          <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-500" />
                  <span>Background Job Queue &amp; Webhook Delivery Telemetry</span>
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Persistent worker jobs with Dead-Letter retry controls and outbound notification delivery log.
                </p>
              </div>
              {canIssueKeys && (
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => enqueueBackgroundJob('sbom_rescan_sweep', { trigger: 'manual' })}
                    className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
                  >
                    Enqueue Security Sweep
                  </button>
                </div>
              )}
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900 p-3 space-y-2">
                <div className="text-xs font-bold text-slate-900 dark:text-white">
                  Worker Jobs ({backgroundJobs.length})
                </div>
                {backgroundJobs.length === 0 ? (
                  <div className="text-xs text-slate-500 py-3">No background jobs queued yet.</div>
                ) : (
                  backgroundJobs.slice(0, 6).map((j) => (
                    <div key={j.id} className="flex items-center justify-between gap-2 text-xs py-1.5 border-b border-slate-100 dark:border-slate-800 last:border-0">
                      <div className="min-w-0">
                        <div className="font-mono font-semibold truncate">{j.jobType}</div>
                        <div className="text-[10px] font-mono text-slate-500">
                          {j.status} • Attempt {j.attempts}/{j.maxAttempts}
                        </div>
                      </div>
                      {(j.status === 'Dead_Letter' || j.status === 'Queued') && canIssueKeys && (
                        <button
                          type="button"
                          onClick={() => retryBackgroundJob(j.id)}
                          className="px-2 py-1 rounded bg-cyan-500/15 text-cyan-500 text-[11px] font-semibold shrink-0"
                        >
                          Retry
                        </button>
                      )}
                    </div>
                  ))
                )}
              </div>

              <div className="border border-slate-200 dark:border-slate-800 rounded-lg bg-white dark:bg-slate-900 p-3 space-y-2">
                <div className="text-xs font-bold text-slate-900 dark:text-white">
                  Webhook Deliveries ({systemMetrics?.recentNotifications?.length ?? 0})
                </div>
                {!systemMetrics?.recentNotifications?.length ? (
                  <div className="text-xs text-slate-500 py-3">No outbound webhook deliveries recorded yet.</div>
                ) : (
                  systemMetrics.recentNotifications.slice(0, 6).map((n) => (
                    <div key={n.id} className="flex items-center justify-between gap-2 text-xs py-1.5 border-b border-slate-100 dark:border-slate-800 last:border-0">
                      <div className="min-w-0">
                        <div className="font-mono font-semibold truncate">{n.channel} • {n.eventType}</div>
                        <div className="text-[10px] text-slate-500 truncate">{n.summary}</div>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold shrink-0 ${
                          n.status === 'Delivered'
                            ? 'bg-emerald-500/15 text-emerald-500'
                            : 'bg-rose-500/15 text-rose-500'
                        }`}
                      >
                        {n.status} {n.httpStatus ? `(${n.httpStatus})` : ''}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Audit Ledger */}
          <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-cyan-500" />
                  <span>Immutable Hash-Chained Audit Ledger ({auditLogs.length} Recent Entries)</span>
                </h2>
                <p className="text-xs text-slate-500 mt-0.5">
                  Every entry stores prevHash → entryHash SHA-256 linkage verified server-side on retrieval.
                </p>
              </div>
              <button
                type="button"
                onClick={handleDownloadAuditLedger}
                className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-cyan-600 dark:text-cyan-400 text-xs font-semibold transition border border-slate-200 dark:border-slate-800 shrink-0 self-start whitespace-nowrap"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Download Audit Ledger (JSON)</span>
              </button>
            </div>

            <div className="overflow-x-auto border border-slate-200 dark:border-slate-800 rounded-lg">
              <table className="w-full text-left border-collapse text-xs">
                <thead className="bg-white dark:bg-slate-900 text-[10px] font-mono uppercase text-slate-500 border-b border-slate-200 dark:border-slate-800">
                  <tr>
                    <th className="py-2.5 px-3">ID</th>
                    <th className="py-2.5 px-3">Actor</th>
                    <th className="py-2.5 px-3">Action</th>
                    <th className="py-2.5 px-3">Details</th>
                    <th className="py-2.5 px-3">Entry Hash</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                  {auditLogs.slice(0, 20).map((log) => (
                    <tr key={log.id} className="hover:bg-white/60 dark:hover:bg-slate-900/60">
                      <td className="py-2 px-3 font-mono text-slate-500 tabular-nums">#{log.id}</td>
                      <td className="py-2 px-3 font-mono">{log.actorEmail}</td>
                      <td className="py-2 px-3 font-mono font-semibold text-cyan-600 dark:text-cyan-400">{log.action}</td>
                      <td className="py-2 px-3 max-w-md truncate">{log.details}</td>
                      <td className="py-2 px-3 font-mono text-[11px] text-slate-500">{log.entryHash.slice(0, 14)}…</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
