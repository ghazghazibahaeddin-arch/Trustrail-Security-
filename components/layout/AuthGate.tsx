'use client';

import React, { useState } from 'react';
import Link from 'next/link';
import { useTrustrail, type ApiError } from '@/lib/use-trustrail';
import { Edition } from '@/lib/trustrail-store';
import {
  ShieldCheck,
  Lock,
  Mail,
  User,
  Building2,
  ArrowRight,
  Loader2,
  KeyRound,
  Eye,
  EyeOff,
  ChevronDown,
  ChevronUp,
  ShieldAlert,
  CheckCircle2,
} from 'lucide-react';

const SANDBOX_PRESETS = [
  { label: 'Acme Cloud (Owner)', email: 'sarah@acme.cloud', role: 'Owner' },
  { label: 'Acme Cloud (Developer)', email: 'alex@acme.cloud', role: 'Developer' },
  { label: 'Acme Cloud (Viewer)', email: 'auditor@acme.cloud', role: 'Viewer' },
  { label: 'Northstar FinTech (Tenant 2)', email: 'admin@northstar.io', role: 'Owner' },
];

export function AuthGate({
  initialMode = 'login',
  onAuthenticated,
}: {
  initialMode?: 'login' | 'register';
  onAuthenticated?: () => void;
}) {
  const { login, register, forgotPassword, resetPassword } = useTrustrail();
  const [mode, setMode] = useState<'login' | 'register' | 'forgot' | 'reset'>(initialMode);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [mfaRequired, setMfaRequired] = useState(false);
  const [resetToken, setResetToken] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [infoBanner, setInfoBanner] = useState<string | null>(null);
  const [showPassword, setShowPassword] = useState(false);
  const [name, setName] = useState('');
  const [organizationName, setOrganizationName] = useState('');
  const [edition, setEdition] = useState<Edition>('developer');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showSandbox, setShowSandbox] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setInfoBanner(null);
    setSubmitting(true);
    try {
      if (mode === 'login') {
        await login(email.trim(), password, undefined, mfaRequired ? mfaCode.trim() : undefined);
        onAuthenticated?.();
      } else if (mode === 'register') {
        const reg = await register({
          email: email.trim(),
          name: name.trim(),
          password,
          organizationName: organizationName.trim(),
          edition,
        });
        if (reg.verificationTokenPreview) {
          setInfoBanner(`Workspace created. Email verification token issued: ${reg.verificationTokenPreview}`);
        }
        onAuthenticated?.();
      } else if (mode === 'forgot') {
        const res = await forgotPassword(email.trim());
        setInfoBanner(
          res.resetTokenPreview
            ? `${res.message} Dev preview token: ${res.resetTokenPreview}`
            : res.message
        );
        if (res.resetTokenPreview) {
          setResetToken(res.resetTokenPreview);
        }
        setMode('reset');
      } else if (mode === 'reset') {
        await resetPassword(resetToken.trim(), newPassword);
        setInfoBanner('Password reset complete. Sign in with your new password.');
        setPassword('');
        setMode('login');
      }
    } catch (err) {
      const apiErr = err as ApiError;
      if (apiErr.code === 'MFA_REQUIRED' || apiErr.code === 'INVALID_MFA_CODE') {
        setMfaRequired(true);
      }
      setError(apiErr.message);
    } finally {
      setSubmitting(false);
    }
  };

  const quickSandboxSignIn = async (presetEmail: string) => {
    setError(null);
    setInfoBanner(null);
    setMfaRequired(false);
    setEmail(presetEmail);
    setPassword('Trustrail!2026');
    setSubmitting(true);
    try {
      await login(presetEmail, 'Trustrail!2026');
      onAuthenticated?.();
    } catch (err) {
      const apiErr = err as ApiError;
      if (apiErr.code === 'MFA_REQUIRED') {
        setMfaRequired(true);
      }
      setError(apiErr.message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-4">
      <div className="w-full max-w-4xl grid grid-cols-1 lg:grid-cols-5 bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
        {/* Left Brand & Sandbox Drawer */}
        <div className="lg:col-span-2 bg-slate-950 p-6 sm:p-8 border-b lg:border-b-0 lg:border-r border-slate-800 flex flex-col justify-between space-y-6">
          <div>
            <div className="flex items-center space-x-3 mb-6">
              <div className="w-10 h-10 rounded-xl bg-cyan-600 flex items-center justify-center shrink-0">
                <ShieldCheck className="w-6 h-6 text-white" />
              </div>
              <div>
                <div className="font-bold text-white tracking-wider text-sm">TRUSTRAIL</div>
                <div className="text-[11px] font-mono text-cyan-400">SECURITY CLOUD</div>
              </div>
            </div>
            <h1 className="text-lg font-bold text-white mb-2">Unified Cyber Defense Control Plane</h1>
            <p className="text-xs text-slate-400 leading-relaxed">
              Sign in with your organization account (with optional TOTP MFA &amp; brute-force lockout protection) or create an isolated tenant workspace with real GitHub repo scanning, OSV.dev CVE intelligence, HTTP/TLS probing, IntentLock governance, and scoped CI/CD API keys.
            </p>
            <div className="mt-5 space-y-2 text-[11px] text-slate-400 font-mono">
              <div className="flex items-center justify-between py-1.5 border-b border-slate-800/80">
                <span>Sign-In Route</span>
                <Link href="/login" className="text-cyan-400 hover:underline">/login</Link>
              </div>
              <div className="flex items-center justify-between py-1.5 border-b border-slate-800/80">
                <span>Registration Route</span>
                <Link href="/register" className="text-cyan-400 hover:underline">/register</Link>
              </div>
              <div className="flex items-center justify-between py-1.5">
                <span>API Spec</span>
                <a href="/api/v1/openapi.json" target="_blank" rel="noreferrer" className="text-cyan-400 hover:underline">
                  /api/v1/openapi.json
                </a>
              </div>
            </div>
          </div>

          <div className="border-t border-slate-800 pt-4">
            <button
              type="button"
              onClick={() => setShowSandbox(!showSandbox)}
              className="w-full flex items-center justify-between text-[11px] font-mono uppercase tracking-wider text-slate-400 hover:text-slate-200 transition"
            >
              <span>Sandbox Evaluator Accounts</span>
              {showSandbox ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>
            {showSandbox && (
              <div className="space-y-2 mt-3">
                {SANDBOX_PRESETS.map((preset) => (
                  <button
                    key={preset.email}
                    type="button"
                    disabled={submitting}
                    onClick={() => quickSandboxSignIn(preset.email)}
                    className="w-full text-left p-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 border border-slate-800 transition flex items-center justify-between gap-2"
                  >
                    <div className="min-w-0">
                      <div className="text-xs font-semibold text-white truncate">{preset.label}</div>
                      <div className="text-[10px] font-mono text-slate-400 truncate">{preset.email}</div>
                    </div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-500/15 text-cyan-300 shrink-0">
                      {preset.role}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Form */}
        <div className="lg:col-span-3 p-6 sm:p-8 flex flex-col justify-center">
          <div className="flex flex-wrap items-center gap-2 mb-6 border-b border-slate-800 pb-3">
            <button
              type="button"
              onClick={() => {
                setMode('login');
                setError(null);
                setMfaRequired(false);
              }}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition whitespace-nowrap ${
                mode === 'login' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('register');
                setError(null);
                setMfaRequired(false);
              }}
              className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold transition whitespace-nowrap ${
                mode === 'register' ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-white'
              }`}
            >
              Create Account &amp; Workspace
            </button>
            <button
              type="button"
              onClick={() => {
                setMode('forgot');
                setError(null);
              }}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition whitespace-nowrap ${
                mode === 'forgot' || mode === 'reset'
                  ? 'bg-cyan-600 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              Reset Password
            </button>
          </div>

          <form onSubmit={handleSubmit} className="space-y-4">
            {mode === 'register' && (
              <>
                <div>
                  <label htmlFor="auth-name" className="text-[11px] font-mono text-slate-400 uppercase block mb-1">
                    Full Name
                  </label>
                  <div className="relative">
                    <User className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      id="auth-name"
                      type="text"
                      required
                      minLength={2}
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="Jordan Mercer"
                      autoComplete="name"
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                    />
                  </div>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label htmlFor="auth-org" className="text-[11px] font-mono text-slate-400 uppercase block mb-1">
                      Organization Name
                    </label>
                    <div className="relative">
                      <Building2 className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                      <input
                        id="auth-org"
                        type="text"
                        required
                        minLength={2}
                        value={organizationName}
                        onChange={(e) => setOrganizationName(e.target.value)}
                        placeholder="Acme Security Labs"
                        autoComplete="organization"
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                      />
                    </div>
                  </div>
                  <div>
                    <label htmlFor="auth-edition" className="text-[11px] font-mono text-slate-400 uppercase block mb-1">
                      Workspace Edition
                    </label>
                    <select
                      id="auth-edition"
                      value={edition}
                      onChange={(e) => setEdition(e.target.value as Edition)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                    >
                      <option value="developer">Developer Edition</option>
                      <option value="smb">Teams &amp; SMB Edition</option>
                      <option value="enterprise">Enterprise Security Grid</option>
                    </select>
                  </div>
                </div>
              </>
            )}

            {(mode === 'login' || mode === 'register' || mode === 'forgot') && (
              <div>
                <label htmlFor="auth-email" className="text-[11px] font-mono text-slate-400 uppercase block mb-1">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    id="auth-email"
                    type="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    autoComplete="email"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
            )}

            {(mode === 'login' || mode === 'register') && (
              <div>
                <label htmlFor="auth-password" className="text-[11px] font-mono text-slate-400 uppercase block mb-1">
                  Password
                </label>
                <div className="relative">
                  <KeyRound className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    id="auth-password"
                    type={showPassword ? 'text' : 'password'}
                    required
                    minLength={mode === 'register' ? 8 : 6}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder={mode === 'register' ? 'Minimum 8 characters' : 'Enter your password'}
                    autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-10 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>
            )}

            {mode === 'login' && mfaRequired && (
              <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/40 space-y-2">
                <label htmlFor="auth-mfa" className="text-[11px] font-mono text-cyan-300 uppercase flex items-center gap-1.5">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>6-Digit TOTP Authenticator Code</span>
                </label>
                <input
                  id="auth-mfa"
                  type="text"
                  required
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value)}
                  placeholder="123456"
                  inputMode="numeric"
                  className="w-full bg-slate-950 border border-cyan-500/40 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-cyan-400"
                />
              </div>
            )}

            {mode === 'reset' && (
              <>
                <div>
                  <label htmlFor="reset-token" className="text-[11px] font-mono text-slate-400 uppercase block mb-1">
                    Reset Token
                  </label>
                  <input
                    id="reset-token"
                    type="text"
                    required
                    value={resetToken}
                    onChange={(e) => setResetToken(e.target.value)}
                    placeholder="tr_rst_..."
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-white"
                  />
                </div>
                <div>
                  <label htmlFor="reset-new-password" className="text-[11px] font-mono text-slate-400 uppercase block mb-1">
                    New Password (min 8 chars)
                  </label>
                  <input
                    id="reset-new-password"
                    type="password"
                    required
                    minLength={8}
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Enter new strong password"
                    className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white"
                  />
                </div>
              </>
            )}

            {infoBanner && (
              <div className="p-3 rounded-lg bg-emerald-500/15 border border-emerald-500/40 text-xs text-emerald-300 flex items-start gap-2 break-all">
                <CheckCircle2 className="w-4 h-4 shrink-0 mt-0.5" />
                <span>{infoBanner}</span>
              </div>
            )}

            {error && (
              <div className="p-3 rounded-lg bg-rose-500/15 border border-rose-500/40 text-xs text-rose-300">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={submitting}
              className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition flex items-center justify-center space-x-2 disabled:opacity-50"
            >
              {submitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Processing...</span>
                </>
              ) : (
                <>
                  <Lock className="w-4 h-4" />
                  <span>
                    {mode === 'login'
                      ? mfaRequired
                        ? 'Verify TOTP & Sign In'
                        : 'Sign In'
                      : mode === 'register'
                      ? 'Create Account & Workspace'
                      : mode === 'forgot'
                      ? 'Request Reset Token'
                      : 'Complete Password Reset'}
                  </span>
                  <ArrowRight className="w-4 h-4" />
                </>
              )}
            </button>
          </form>

          <div className="mt-5 pt-4 border-t border-slate-800/80 text-center text-xs text-slate-400">
            {mode === 'login' ? (
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span>
                  New workspace?{' '}
                  <button
                    type="button"
                    onClick={() => {
                      setMode('register');
                      setError(null);
                    }}
                    className="text-cyan-400 hover:underline font-medium"
                  >
                    Register here
                  </button>
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setMode('forgot');
                    setError(null);
                  }}
                  className="text-slate-400 hover:text-cyan-400 underline"
                >
                  Forgot password?
                </button>
              </div>
            ) : (
              <span>
                Already have a Trustrail account?{' '}
                <button
                  type="button"
                  onClick={() => {
                    setMode('login');
                    setError(null);
                    setMfaRequired(false);
                  }}
                  className="text-cyan-400 hover:underline font-medium"
                >
                  Sign in here
                </button>
              </span>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
