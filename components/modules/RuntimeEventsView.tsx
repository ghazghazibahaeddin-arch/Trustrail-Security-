'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Activity, Radio, RefreshCw, Send, ShieldAlert, CheckCircle2, AlertTriangle } from 'lucide-react';

export function RuntimeEventsView() {
  const {
    auditLogs,
    incidents,
    canaries,
    org,
    runtimeEvents,
    fabricEvents,
    ingestRuntimeEvent,
    replayFabricEvent,
    user,
  } = useTrustrail();

  const canWrite = user?.role !== 'Viewer';
  const [activePanel, setActivePanel] = useState<'telemetry' | 'fabric' | 'audit'>('telemetry');

  // Telemetry ingestion form state
  const [source, setSource] = useState<'otel' | 'kubernetes_audit' | 'falco' | 'cloudtrail' | 'custom'>('falco');
  const [severity, setSeverity] = useState<'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'>('CRITICAL');
  const [eventType, setEventType] = useState('container_privilege_escalation');
  const [actor, setActor] = useState('system:serviceaccount:prod:api-gateway');
  const [resource, setResource] = useState('eks-prod/pod/api-gateway-7f9b');
  const [summary, setSummary] = useState('Detected unexpected nsenter privilege escalation attempt in runtime container.');
  const [ingesting, setIngesting] = useState(false);

  const triggeredCanaries = canaries.filter((c) => c.alertsCount > 0);
  const unifiedStream = [
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

  const handleIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    setIngesting(true);
    try {
      await ingestRuntimeEvent({
        source,
        severity,
        eventType: eventType.trim(),
        actor: actor.trim(),
        resource: resource.trim(),
        summary: summary.trim(),
      });
    } finally {
      setIngesting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Activity className="w-5 h-5 text-cyan-500" />
              <span>Runtime Threat Telemetry &amp; Internal Event Bus</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Ingest OpenTelemetry, Kubernetes Audit, Falco, and CloudTrail signals, correlate anomalies to incidents, and inspect/replay transactional outbox events for {org.name}.
            </p>
          </div>
          <div className="inline-flex rounded-lg bg-slate-100 dark:bg-slate-800 p-1 border border-slate-200 dark:border-slate-700 self-start">
            <button
              type="button"
              onClick={() => setActivePanel('telemetry')}
              className={`px-3 py-1 rounded-md text-xs font-semibold transition ${
                activePanel === 'telemetry'
                  ? 'bg-cyan-600 text-white'
                  : 'text-slate-600 dark:text-slate-300'
              }`}
            >
              Runtime Collector ({runtimeEvents.length})
            </button>
            <button
              type="button"
              onClick={() => setActivePanel('fabric')}
              className={`px-3 py-1 rounded-md text-xs font-semibold transition ${
                activePanel === 'fabric'
                  ? 'bg-cyan-600 text-white'
                  : 'text-slate-600 dark:text-slate-300'
              }`}
            >
              Event Bus Outbox ({fabricEvents.length})
            </button>
            <button
              type="button"
              onClick={() => setActivePanel('audit')}
              className={`px-3 py-1 rounded-md text-xs font-semibold transition ${
                activePanel === 'audit'
                  ? 'bg-cyan-600 text-white'
                  : 'text-slate-600 dark:text-slate-300'
              }`}
            >
              Correlated Audit ({unifiedStream.length})
            </button>
          </div>
        </div>

        {/* Panel 1: Runtime Telemetry Collector */}
        {activePanel === 'telemetry' && (
          <div className="space-y-5">
            {canWrite && (
              <form
                onSubmit={handleIngest}
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 space-y-3"
              >
                <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-2">
                  <Radio className="w-4 h-4 text-cyan-500" />
                  <span>Ingest Runtime Telemetry Signal (`/api/v1/events/ingest`)</span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-2">
                  <select
                    value={source}
                    onChange={(e) =>
                      setSource(e.target.value as 'otel' | 'kubernetes_audit' | 'falco' | 'cloudtrail' | 'custom')
                    }
                    className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                  >
                    <option value="falco">Falco Runtime</option>
                    <option value="kubernetes_audit">Kubernetes Audit</option>
                    <option value="otel">OpenTelemetry</option>
                    <option value="cloudtrail">AWS CloudTrail</option>
                    <option value="custom">Custom Collector</option>
                  </select>
                  <select
                    value={severity}
                    onChange={(e) =>
                      setSeverity(e.target.value as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO')
                    }
                    className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                  >
                    <option value="CRITICAL">CRITICAL (Auto-Incident)</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                    <option value="INFO">INFO</option>
                  </select>
                  <input
                    type="text"
                    required
                    value={eventType}
                    onChange={(e) => setEventType(e.target.value)}
                    placeholder="Event Type"
                    className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                  />
                  <input
                    type="text"
                    required
                    value={actor}
                    onChange={(e) => setActor(e.target.value)}
                    placeholder="Actor / Principal"
                    className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                  />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <input
                    type="text"
                    required
                    value={resource}
                    onChange={(e) => setResource(e.target.value)}
                    placeholder="Target Resource / Asset"
                    className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                  />
                  <input
                    type="text"
                    required
                    value={summary}
                    onChange={(e) => setSummary(e.target.value)}
                    placeholder="Telemetry summary"
                    className="sm:col-span-2 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs"
                  />
                </div>
                <div className="flex justify-end">
                  <button
                    type="submit"
                    disabled={ingesting}
                    className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white text-xs font-semibold flex items-center gap-1.5"
                  >
                    <Send className="w-3.5 h-3.5" />
                    <span>{ingesting ? 'Ingesting...' : 'Ingest & Correlate Signal'}</span>
                  </button>
                </div>
              </form>
            )}

            <div className="space-y-3">
              {runtimeEvents.length === 0 ? (
                <div className="p-6 text-center text-xs text-slate-500 bg-slate-50 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800">
                  No runtime telemetry events ingested yet. Submit a signal above or point a TRUSTRAIL Runtime Collector (`tr_run_`) at `/api/v1/events/ingest`.
                </div>
              ) : (
                runtimeEvents.map((ev) => (
                  <div
                    key={ev.id}
                    className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div className="space-y-1">
                      <div className="text-sm font-bold text-slate-900 dark:text-white flex items-center gap-2">
                        <span>{ev.eventType}</span>
                        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-300">
                          {ev.source}
                        </span>
                      </div>
                      <div className="text-xs text-slate-600 dark:text-slate-300">{ev.summary}</div>
                      <div className="text-[11px] font-mono text-slate-500">
                        Actor: {ev.actor} • Resource: {ev.resource} • {ev.receivedAt}
                      </div>
                      {ev.correlatedIncidentId && (
                        <div className="text-[11px] font-mono text-rose-500 flex items-center gap-1">
                          <ShieldAlert className="w-3.5 h-3.5" />
                          <span>Auto-correlated Incident: {ev.correlatedIncidentId}</span>
                        </div>
                      )}
                    </div>
                    <span
                      className={`px-2.5 py-1 rounded text-xs font-mono font-bold border self-start sm:self-center ${
                        ev.severity === 'CRITICAL'
                          ? 'bg-rose-500/15 text-rose-500 border-rose-500/30'
                          : ev.severity === 'HIGH'
                          ? 'bg-amber-500/15 text-amber-500 border-amber-500/30'
                          : 'bg-cyan-500/15 text-cyan-600 dark:text-cyan-300 border-cyan-500/30'
                      }`}
                    >
                      {ev.severity}
                    </span>
                  </div>
                ))
              )}
            </div>
          </div>
        )}

        {/* Panel 2: Internal Event Bus & Outbox */}
        {activePanel === 'fabric' && (
          <div className="space-y-3">
            {fabricEvents.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 bg-slate-50 dark:bg-slate-950 rounded-xl border border-slate-200 dark:border-slate-800">
                No internal event bus records yet. Trigger a scan, remediation, or connector sync to observe outbox events.
              </div>
            ) : (
              fabricEvents.map((evt) => {
                const needsReplay =
                  evt.processingStatus === 'Failed' || evt.processingStatus === 'Dead_Letter';
                return (
                  <div
                    key={evt.eventId}
                    className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                  >
                    <div className="space-y-1 min-w-0">
                      <div className="flex items-center gap-2">
                        {evt.processingStatus === 'Processed' ? (
                          <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-amber-500 shrink-0" />
                        )}
                        <span className="text-sm font-bold font-mono text-slate-900 dark:text-white">
                          {evt.eventType}
                        </span>
                        <span className="text-[10px] font-mono text-cyan-500">corr={evt.correlationId}</span>
                      </div>
                      <div className="text-xs font-mono text-slate-500 truncate">
                        Connector: {evt.sourceConnector} • Resource: {evt.sourceResourceId} • Actor: {evt.actorId}
                      </div>
                      {evt.lastError && (
                        <div className="text-[11px] font-mono text-rose-500">Error: {evt.lastError}</div>
                      )}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span
                        className={`px-2.5 py-1 rounded text-[11px] font-mono font-bold border ${
                          evt.processingStatus === 'Processed'
                            ? 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                            : needsReplay
                            ? 'bg-rose-500/15 text-rose-500 border-rose-500/30'
                            : 'bg-amber-500/15 text-amber-500 border-amber-500/30'
                        }`}
                      >
                        {evt.processingStatus} (x{evt.attempts})
                      </span>
                      {canWrite && needsReplay && (
                        <button
                          type="button"
                          onClick={() => replayFabricEvent(evt.eventId, false)}
                          className="px-2.5 py-1 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1"
                        >
                          <RefreshCw className="w-3 h-3" />
                          <span>Replay</span>
                        </button>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        )}

        {/* Panel 3: Correlated Audit & Deception Stream */}
        {activePanel === 'audit' && (
          <div className="space-y-3">
            {unifiedStream.map((ev) => (
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
        )}
      </div>
    </div>
  );
}
