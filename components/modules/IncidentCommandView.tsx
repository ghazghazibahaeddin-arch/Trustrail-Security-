'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Flame, Plus, CheckCircle2 } from 'lucide-react';

export function IncidentCommandView() {
  const { incidents, createIncident, updateIncident, user } = useTrustrail();
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState<'SEV-1' | 'SEV-2' | 'SEV-3'>('SEV-2');
  const [asset, setAsset] = useState('aws-prod-us-east-1');
  const [actionNote, setActionNote] = useState<Record<string, string>>({});

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    await createIncident(title, severity, asset);
    setTitle('');
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Flame className="w-5 h-5 text-rose-500" />
              <span>Incident Response Command Center</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Persistent incident lifecycle (Open → Contained → Recovered → Closed), playbooks, and audit log integration.
            </p>
          </div>
          <span className="px-3 py-1 rounded-lg text-xs font-mono font-bold bg-rose-500/15 text-rose-500 border border-rose-500/30 tabular-nums">
            {incidents.length} Incidents
          </span>
        </div>

        {user?.role !== 'Viewer' && (
          <form
            onSubmit={handleCreate}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 mb-6 grid grid-cols-1 md:grid-cols-4 gap-3 items-end"
          >
            <div className="md:col-span-2 space-y-1.5">
              <label className="text-[10px] font-mono text-slate-500 uppercase">Incident Title</label>
              <input
                type="text"
                required
                placeholder="e.g., Compromised CI Deployment Key..."
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-[10px] font-mono text-slate-500 uppercase">Affected Asset & Severity</label>
              <div className="flex space-x-2">
                <input
                  type="text"
                  value={asset}
                  onChange={(e) => setAsset(e.target.value)}
                  className="flex-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-2 text-xs font-mono"
                />
                <select
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as 'SEV-1' | 'SEV-2' | 'SEV-3')}
                  className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2 py-2 text-xs"
                >
                  <option value="SEV-1">SEV-1</option>
                  <option value="SEV-2">SEV-2</option>
                  <option value="SEV-3">SEV-3</option>
                </select>
              </div>
            </div>
            <button
              type="submit"
              className="px-5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-semibold transition flex items-center justify-center space-x-1.5"
            >
              <Plus className="w-4 h-4" />
              <span>Open Incident</span>
            </button>
          </form>
        )}

        <div className="space-y-4">
          {incidents.map((inc) => (
            <div
              key={inc.id}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-3"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center space-x-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      inc.severity === 'SEV-1' ? 'bg-rose-500/20 text-rose-500' : 'bg-amber-500/20 text-amber-500'
                    }`}
                  >
                    {inc.severity}
                  </span>
                  <span className="text-xs font-mono text-cyan-600 dark:text-cyan-400">{inc.affectedAsset}</span>
                </div>
                {user?.role !== 'Viewer' ? (
                  <select
                    aria-label={`Status for ${inc.title}`}
                    value={inc.status}
                    onChange={(e) =>
                      updateIncident(inc.id, { status: e.target.value as 'Open' | 'Contained' | 'Recovered' | 'Closed' })
                    }
                    className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono text-emerald-600 dark:text-emerald-400"
                  >
                    <option value="Open">Open</option>
                    <option value="Contained">Contained</option>
                    <option value="Recovered">Recovered</option>
                    <option value="Closed">Closed</option>
                  </select>
                ) : (
                  <span className="px-2.5 py-1 rounded bg-white dark:bg-slate-900 text-xs font-mono text-emerald-500 border border-slate-200 dark:border-slate-800">
                    {inc.status}
                  </span>
                )}
              </div>

              <div className="text-sm font-bold text-slate-900 dark:text-white">{inc.title}</div>
              <div className="text-xs text-slate-600 dark:text-slate-300">{inc.summary}</div>

              <div className="bg-white dark:bg-slate-900 p-3 rounded-lg border border-slate-200 dark:border-slate-800 space-y-1.5">
                <div className="text-[10px] font-mono text-slate-500 uppercase">Playbook: {inc.playbookName}</div>
                {inc.actionsTaken.map((act, i) => (
                  <div key={i} className="text-xs text-slate-700 dark:text-slate-300 flex items-center space-x-2">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
                    <span>{act}</span>
                  </div>
                ))}
                {user?.role !== 'Viewer' && (
                  <div className="flex items-center space-x-2 pt-2">
                    <input
                      type="text"
                      placeholder="Log containment or recovery action..."
                      value={actionNote[inc.id] || ''}
                      onChange={(e) => setActionNote((prev) => ({ ...prev, [inc.id]: e.target.value }))}
                      className="flex-1 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs"
                    />
                    <button
                      type="button"
                      onClick={async () => {
                        const text = actionNote[inc.id]?.trim();
                        if (!text) return;
                        await updateIncident(inc.id, { appendAction: text });
                        setActionNote((prev) => ({ ...prev, [inc.id]: '' }));
                      }}
                      className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
                    >
                      Log Step
                    </button>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
