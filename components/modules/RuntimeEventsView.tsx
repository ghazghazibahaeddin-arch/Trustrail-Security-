'use client';

import React from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Activity } from 'lucide-react';

export function RuntimeEventsView() {
  const { auditLogs, incidents, canaries, org } = useTrustrail();

  const triggeredCanaries = canaries.filter((c) => c.alertsCount > 0);
  const events = [
    ...triggeredCanaries.map((c) => ({
      id: `canary-${c.id}`,
      title: `Deception Tripwire Triggered: ${c.type} (${c.location})`,
      source: 'Deception Engine',
      time: c.lastTriggeredAt || 'Triggered',
      severity: 'Critical',
    })),
    ...incidents.map((inc) => ({
      id: `inc-${inc.id}`,
      title: `${inc.severity} Incident (${inc.status}): ${inc.title}`,
      source: 'Incident Command',
      time: inc.openedAt,
      severity: inc.severity === 'SEV-1' ? 'Critical' : 'High',
    })),
    ...auditLogs.slice(0, 15).map((log) => ({
      id: `audit-${log.id}`,
      title: `${log.action}: ${log.details}`,
      source: `Audit Ledger (${log.actorEmail})`,
      time: log.createdAt,
      severity: /REVOKE|TRIGGERED|TAMPER|DENY/i.test(log.action) ? 'High' : 'Info',
    })),
  ];

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-500" />
              <span>Runtime Threat Telemetry &amp; Audit Stream</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Live correlation across deception tripwires, incident timelines, and SHA-256 audit events for {org.name}.
            </p>
          </div>
          <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-cyan-500/15 text-cyan-600 dark:text-cyan-300 border border-cyan-500/30 self-start">
            {events.length} Telemetry Events
          </span>
        </div>

        <div className="space-y-3">
          {events.map((ev) => (
            <div
              key={ev.id}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
            >
              <div className="flex items-center space-x-3">
                <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-500 shrink-0">
                  <Activity className="w-4 h-4" />
                </div>
                <div>
                  <div className="text-sm font-bold text-slate-900 dark:text-white">{ev.title}</div>
                  <div className="text-xs text-slate-500 font-mono">
                    Source: {ev.source} • {ev.time}
                  </div>
                </div>
              </div>
              <span
                className={`px-2.5 py-1 rounded text-xs font-mono font-bold border self-start sm:self-center ${
                  ev.severity === 'Critical'
                    ? 'bg-rose-500/15 text-rose-500 border-rose-500/30'
                    : ev.severity === 'High'
                    ? 'bg-amber-500/15 text-amber-500 border-amber-500/30'
                    : 'bg-cyan-500/15 text-cyan-600 dark:text-cyan-300 border-cyan-500/30'
                }`}
              >
                {ev.severity}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
