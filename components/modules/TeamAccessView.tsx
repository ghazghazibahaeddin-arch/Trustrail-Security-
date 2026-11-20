'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Role } from '@/lib/trustrail-store';
import { Users, UserPlus, ShieldCheck } from 'lucide-react';

export function TeamAccessView() {
  const { teamMembers, inviteMember, updateMemberRole, updateMemberStatus, user, org } = useTrustrail();
  const [showInvite, setShowInvite] = useState(false);
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState<Role>('Developer');
  const [title, setTitle] = useState('Security Engineer');

  const isAdmin = user?.role === 'Owner' || user?.role === 'Admin';

  const handleInvite = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !name.trim()) return;
    await inviteMember({
      email: email.trim(),
      name: name.trim(),
      role,
      title: title.trim() || role,
    });
    setEmail('');
    setName('');
    setShowInvite(false);
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Users className="w-5 h-5 text-cyan-500" />
              <span>Team &amp; Access Management (RBAC)</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Tenant-isolated role-based access control &amp; account lifecycle for {org.name} ({teamMembers.length} members).
            </p>
          </div>
          {isAdmin && (
            <button
              type="button"
              onClick={() => setShowInvite(!showInvite)}
              className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition shrink-0 self-start"
            >
              <UserPlus className="w-3.5 h-3.5" />
              <span>Invite Team Member</span>
            </button>
          )}
        </div>

        {showInvite && (
          <form
            onSubmit={handleInvite}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 mb-6 grid grid-cols-1 md:grid-cols-5 gap-3 items-end"
          >
            <input
              type="text"
              required
              placeholder="Full Name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
            />
            <input
              type="email"
              required
              placeholder="Work Email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
            />
            <input
              type="text"
              placeholder="Job Title"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
            />
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as Role)}
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
            >
              <option value="Admin">Admin</option>
              <option value="Developer">Developer</option>
              <option value="Viewer">Viewer</option>
            </select>
            <button type="submit" className="px-4 py-2 rounded-lg bg-cyan-600 text-white text-xs font-semibold">
              Add Member
            </button>
          </form>
        )}

        <div className="space-y-3">
          {teamMembers.map((m) => {
            const isDisabled = m.userStatus === 'Disabled';
            const canEdit = isAdmin && m.role !== 'Owner' && m.userId !== user?.id;

            return (
              <div
                key={m.membershipId}
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                <div className="flex items-center space-x-3">
                  <div className="w-9 h-9 rounded-lg bg-indigo-600/15 text-indigo-500 border border-indigo-500/30 flex items-center justify-center font-bold text-xs shrink-0">
                    {m.name.slice(0, 2).toUpperCase()}
                  </div>
                  <div>
                    <div className="text-sm font-bold text-slate-900 dark:text-white">
                      {m.name} <span className="font-mono text-xs text-slate-500">({m.email})</span>
                    </div>
                    <div className="text-xs text-slate-500">
                      {m.title} • TOTP MFA: {m.mfaVerified ? 'Verified' : 'Not Verified'}
                    </div>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2 shrink-0">
                  {isAdmin && m.role !== 'Owner' ? (
                    <select
                      aria-label={`Role for ${m.email}`}
                      value={m.role}
                      onChange={(e) => updateMemberRole(m.membershipId, e.target.value as Role)}
                      className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono font-bold text-cyan-600 dark:text-cyan-400"
                    >
                      <option value="Admin">Admin</option>
                      <option value="Developer">Developer</option>
                      <option value="Viewer">Viewer</option>
                    </select>
                  ) : (
                    <span className="px-2.5 py-1 rounded bg-cyan-500/15 text-cyan-600 dark:text-cyan-300 border border-cyan-500/30 text-xs font-mono font-bold flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3" />
                      <span>{m.role}</span>
                    </span>
                  )}

                  {canEdit ? (
                    <button
                      type="button"
                      onClick={() => updateMemberStatus(m.membershipId, isDisabled ? 'Active' : 'Disabled')}
                      className={`px-2.5 py-1 rounded text-xs font-mono font-bold border transition ${
                        isDisabled
                          ? 'bg-rose-500/15 text-rose-500 border-rose-500/30 hover:bg-rose-500/25'
                          : 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30 hover:bg-emerald-500/25'
                      }`}
                    >
                      {isDisabled ? 'Disabled (Click to Enable)' : 'Active'}
                    </button>
                  ) : (
                    <span
                      className={`px-2.5 py-1 rounded border text-xs font-mono font-bold ${
                        isDisabled
                          ? 'bg-rose-500/15 text-rose-500 border-rose-500/30'
                          : 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                      }`}
                    >
                      {m.userStatus || m.status}
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
