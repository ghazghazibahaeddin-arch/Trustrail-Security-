'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Eye, Plus, Zap } from 'lucide-react';

export function DeceptionView() {
  const { canaries, deployCanary, triggerCanary, user } = useTrustrail();
  const [type, setType] = useState<'Canary Token URL' | 'Honey API Key' | 'Decoy Database User' | 'Honeypot Endpoint'>(
    'Honey API Key'
  );
  const [location, setLocation] = useState('');

  const handleDeploy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!location.trim()) return;
    await deployCanary(type, location);
    setLocation('');
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Eye className="w-5 h-5 text-cyan-500" />
              <span>Deception & Canary Intelligence</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Canary tokens, honey credentials, and decoy identities for high-signal intrusion detection.
            </p>
          </div>
          <span className="px-3 py-1 rounded-lg text-xs font-mono font-bold bg-emerald-500/15 text-emerald-500 border border-emerald-500/30 tabular-nums">
            {canaries.length} Decoys Active
          </span>
        </div>

        {user?.role !== 'Viewer' && (
          <form
            onSubmit={handleDeploy}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 mb-6 grid grid-cols-1 md:grid-cols-4 gap-3 items-end"
          >
            <select
              value={type}
              onChange={(e) => setType(e.target.value as typeof type)}
              className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
            >
              <option value="Honey API Key">Honey API Key</option>
              <option value="Canary Token URL">Canary Token URL</option>
              <option value="Decoy Database User">Decoy Database User</option>
              <option value="Honeypot Endpoint">Honeypot Endpoint</option>
            </select>
            <input
              type="text"
              required
              placeholder="Location (e.g., .env.backup or /api/internal/trap)"
              value={location}
              onChange={(e) => setLocation(e.target.value)}
              className="md:col-span-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
            />
            <button
              type="submit"
              className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center justify-center space-x-1.5"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Deploy Canary</span>
            </button>
          </form>
        )}

        <div className="space-y-3">
          {canaries.map((d) => (
            <div
              key={d.id}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div className="flex items-center space-x-3">
                <div
                  className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                    d.alertsCount > 0
                      ? 'bg-rose-500/15 text-rose-500 border border-rose-500/30'
                      : 'bg-cyan-500/15 text-cyan-500 border border-cyan-500/30'
                  }`}
                >
                  <Eye className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-sm font-bold text-slate-900 dark:text-white font-mono">{d.type}</div>
                  <div className="text-xs text-slate-500">
                    Location: {d.location} • Hint: <span className="font-mono">{d.tokenHint}</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center space-x-3 shrink-0">
                <span
                  className={`px-2.5 py-1 rounded text-xs font-mono font-bold tabular-nums ${
                    d.alertsCount > 0
                      ? 'bg-rose-500/20 text-rose-500 border border-rose-500/30'
                      : 'bg-emerald-500/20 text-emerald-500 border border-emerald-500/30'
                  }`}
                >
                  {d.status} ({d.alertsCount} alerts)
                </span>
                {user?.role !== 'Viewer' && (
                  <button
                    type="button"
                    onClick={() => triggerCanary(d.id)}
                    className="px-3 py-1.5 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 text-amber-500 border border-amber-500/30 text-xs font-semibold flex items-center space-x-1"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    <span>Test Tripwire</span>
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
