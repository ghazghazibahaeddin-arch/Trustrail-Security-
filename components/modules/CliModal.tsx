'use client';

import React, { useState, useRef, useEffect } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Terminal, X, Send, Cpu, Trash2, Plus } from 'lucide-react';

export function CliModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const {
    runScan,
    findings,
    projects,
    org,
    graphNodes,
    issueTrustPassport,
    queryVulnerabilityIntel,
    runners,
    ciSnippets,
    createRunner,
    revokeRunner,
    user,
  } = useTrustrail();

  const isAdmin = user?.role === 'Owner' || user?.role === 'Admin';
  const [tab, setTab] = useState<'terminal' | 'runner'>('terminal');
  const [input, setInput] = useState('');
  const [logs, setLogs] = useState<string[]>([
    'Trustrail Security Cloud CLI [v4.3-FABRIC]',
    'Authenticated to Unified Security Control Plane.',
    'Type "help" for commands: trustrail status | scan | findings | intel <CVE> | runner | graph | attest',
    '',
  ]);
  const [runnerName, setRunnerName] = useState('github-actions-runner');
  const [runnerMode, setRunnerMode] = useState<'scan' | 'cicd' | 'runtime_collector'>('cicd');
  const [newToken, setNewToken] = useState<string | null>(null);
  const [ciTab, setCiTab] = useState<'githubActions' | 'gitlabCi' | 'jenkins'>('githubActions');
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  if (!isOpen) return null;

  const handleCommand = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    const cmd = input.trim();
    setInput('');
    setLogs((prev) => [...prev, `$ ${cmd}`]);

    if (cmd === 'help') {
      setLogs((prev) => [
        ...prev,
        'Available Trustrail CLI commands:',
        '  trustrail status       - Display real-time security score, rating, and posture metrics',
        '  trustrail scan         - Execute backend security scan sweep across organization assets',
        '  trustrail findings     - List prioritized open findings with KEV/EPSS risk scoring',
        '  trustrail intel <CVE>  - Query NVD v2 + CISA KEV + FIRST EPSS for a CVE ID',
        '  trustrail runner       - List enrolled TRUSTRAIL Runners and CI/CD agents',
        '  trustrail graph        - Query Unified Security Intelligence Graph nodes',
        '  trustrail attest       - Issue a signed Trust Passport attestation',
        '  clear                  - Clear terminal output',
        '  exit                   - Close CLI window',
        '',
      ]);
    } else if (cmd === 'clear') {
      setLogs(['Trustrail Security Cloud CLI [v4.3-FABRIC]', '']);
    } else if (cmd === 'exit') {
      onClose();
    } else if (cmd === 'trustrail status') {
      setLogs((prev) => [
        ...prev,
        `Organization: ${org.name} (${org.slug}) [${org.edition.toUpperCase()}]`,
        `Risk Score: ${org.riskScore}/100 | Security Rating: ${org.securityRating}`,
        `Assets: ${org.assetsCount} | Open Findings: ${org.openFindingsCount} | Critical Attack Paths: ${org.criticalPathsCount}`,
        `Active Incidents: ${org.activeIncidentsCount} | Compliance: ${org.compliancePercentage}%`,
        '',
      ]);
    } else if (cmd === 'trustrail scan') {
      setLogs((prev) => [...prev, '>>> Dispatching authenticated scan request to /api/v1/scans...']);
      const res = await runScan();
      if (res) {
        const scan = res.scan as { id?: string; findingsDetected?: number; scannersRun?: string[] } | undefined;
        setLogs((prev) => [
          ...prev,
          `[SUCCESS] Scan ${scan?.id || ''} finished (${scan?.scannersRun?.join(', ') || 'unified'}).`,
          `Findings evaluated: ${scan?.findingsDetected ?? 0}`,
          '',
        ]);
      } else {
        setLogs((prev) => [...prev, '[ERROR] Scan failed or forbidden for current RBAC role.', '']);
      }
    } else if (cmd === 'trustrail findings') {
      if (findings.length === 0) {
        setLogs((prev) => [...prev, 'No findings recorded for this organization.', '']);
      } else {
        setLogs((prev) => [
          ...prev,
          ...findings.map(
            (f) =>
              `[${f.severity}] (${f.status}) ${f.title} — Asset: ${f.assetName} (Risk ${f.riskScore ?? 'N/A'}${f.kevListed ? ' • KEV' : ''})`
          ),
          '',
        ]);
      }
    } else if (cmd.startsWith('trustrail intel ')) {
      const cve = cmd.replace('trustrail intel ', '').trim().toUpperCase();
      setLogs((prev) => [...prev, `>>> Querying NVD + CISA KEV + FIRST EPSS for ${cve}...`]);
      const res = await queryVulnerabilityIntel({ cveIds: [cve] });
      if (res && Array.isArray(res.cveResults)) {
        const rows = res.cveResults as Array<{ cveId: string; kevListed: boolean; epssScore: number | null; cvssScore: number | null }>;
        setLogs((prev) => [
          ...prev,
          ...rows.map(
            (r) =>
              `[SUCCESS] ${r.cveId}: KEV=${r.kevListed ? 'YES' : 'NO'} | EPSS=${r.epssScore ?? 'n/a'} | CVSS=${r.cvssScore ?? 'n/a'}`
          ),
          '',
        ]);
      } else {
        setLogs((prev) => [...prev, `[ERROR] Could not fetch intelligence for ${cve}.`, '']);
      }
    } else if (cmd === 'trustrail runner') {
      setLogs((prev) => [
        ...prev,
        `Registered TRUSTRAIL Runners (${runners.length}):`,
        ...runners.map(
          (r) => `  - ${r.name} [${r.mode}] status=${r.status} env=${r.environment} prefix=${r.tokenPrefix}`
        ),
        '',
      ]);
    } else if (cmd === 'trustrail graph') {
      setLogs((prev) => [
        ...prev,
        `Organization: ${org.name} (Risk Index: ${org.riskScore}/100, Rating: ${org.securityRating})`,
        `Projects: ${projects.length} | Graph Nodes: ${graphNodes.length}`,
        ...graphNodes.map((n) => `  - [${n.assetType}] ${n.name} (${n.criticality})`),
        '',
      ]);
    } else if (cmd === 'trustrail attest') {
      setLogs((prev) => [...prev, '>>> Issuing signed Trust Passport via /api/v1/trust-center...']);
      await issueTrustPassport(`CLI Attestation (${new Date().toISOString().slice(0, 10)})`, [
        `Security Rating ${org.securityRating}`,
        `${org.compliancePercentage}% Controls Verified`,
      ]);
      setLogs((prev) => [...prev, '[SUCCESS] Trust Passport generated and stored.', '']);
    } else {
      setLogs((prev) => [...prev, `command not found: ${cmd}. Type "help" for valid commands.`, '']);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="w-full max-w-3xl bg-slate-950 border border-slate-800 rounded-xl shadow-2xl flex flex-col h-[560px] max-h-[88vh] overflow-hidden font-mono">
        <div className="bg-slate-900 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex items-center space-x-2 text-xs text-cyan-400 font-bold">
              <Terminal className="w-4 h-4" />
              <span>trustrail-cli ~ {org.slug}</span>
            </div>
            <div className="inline-flex rounded-md bg-slate-950 p-0.5 border border-slate-800 text-[11px]">
              <button
                type="button"
                onClick={() => setTab('terminal')}
                className={`px-2.5 py-1 rounded ${tab === 'terminal' ? 'bg-cyan-600 text-white' : 'text-slate-400'}`}
              >
                CLI Terminal
              </button>
              <button
                type="button"
                onClick={() => setTab('runner')}
                className={`px-2.5 py-1 rounded flex items-center gap-1 ${tab === 'runner' ? 'bg-cyan-600 text-white' : 'text-slate-400'}`}
              >
                <Cpu className="w-3 h-3" />
                <span>Runner &amp; CI/CD ({runners.length})</span>
              </button>
            </div>
          </div>
          <button type="button" onClick={onClose} className="text-slate-400 hover:text-white transition" aria-label="Close CLI">
            <X className="w-4 h-4" />
          </button>
        </div>

        {tab === 'terminal' ? (
          <>
            <div className="flex-1 p-4 overflow-y-auto text-xs text-slate-300 space-y-1.5 bg-slate-950">
              {logs.map((log, idx) => (
                <div
                  key={idx}
                  className={
                    log.startsWith('$')
                      ? 'text-cyan-300 font-bold'
                      : log.startsWith('[SUCCESS]')
                      ? 'text-emerald-400'
                      : log.startsWith('[ERROR]')
                      ? 'text-rose-400'
                      : 'text-slate-300'
                  }
                >
                  {log}
                </div>
              ))}
              <div ref={bottomRef} />
            </div>

            <form onSubmit={handleCommand} className="bg-slate-900 border-t border-slate-800 p-3 flex items-center space-x-2">
              <span className="text-cyan-400 font-bold text-xs">$</span>
              <input
                type="text"
                placeholder="Type a command (e.g., trustrail status, trustrail intel CVE-2021-44228)..."
                value={input}
                onChange={(e) => setInput(e.target.value)}
                className="flex-1 bg-transparent border-none text-xs text-slate-200 placeholder-slate-600 focus:outline-none font-mono"
                autoFocus
              />
              <button type="submit" className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono transition">
                <Send className="w-3.5 h-3.5" />
              </button>
            </form>
          </>
        ) : (
          <div className="flex-1 p-4 overflow-y-auto text-xs text-slate-200 space-y-4">
            {isAdmin && (
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-2.5">
                <div className="font-bold text-cyan-400">Enroll TRUSTRAIL Runner / Collector</div>
                <div className="flex flex-wrap gap-2">
                  <input
                    type="text"
                    value={runnerName}
                    onChange={(e) => setRunnerName(e.target.value)}
                    placeholder="Runner Name"
                    className="flex-1 bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs"
                  />
                  <select
                    value={runnerMode}
                    onChange={(e) => setRunnerMode(e.target.value as 'scan' | 'cicd' | 'runtime_collector')}
                    className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs"
                  >
                    <option value="cicd">CI/CD Gate</option>
                    <option value="scan">Private Repo Scanner</option>
                    <option value="runtime_collector">Runtime Collector</option>
                  </select>
                  <button
                    type="button"
                    onClick={async () => {
                      const res = await createRunner(runnerName.trim() || 'ci-runner', runnerMode);
                      if (res) setNewToken(res.enrollmentToken);
                    }}
                    className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-semibold flex items-center gap-1"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Issue Token</span>
                  </button>
                </div>
                {newToken && (
                  <div className="p-2 rounded bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 break-all">
                    Enrollment Token (copy now): {newToken}
                  </div>
                )}
              </div>
            )}

            <div className="space-y-2">
              <div className="text-slate-400 font-bold">Active &amp; Pending Runners ({runners.length})</div>
              {runners.length === 0 ? (
                <div className="text-slate-500">No runners registered yet.</div>
              ) : (
                runners.map((r) => (
                  <div
                    key={r.id}
                    className="bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 flex items-center justify-between"
                  >
                    <div>
                      <div className="text-white font-bold">
                        {r.name} ({r.mode})
                      </div>
                      <div className="text-[11px] text-slate-400">
                        Status: {r.status} • Prefix: {r.tokenPrefix} • Env: {r.environment}
                      </div>
                    </div>
                    {isAdmin && r.status !== 'Revoked' && (
                      <button
                        type="button"
                        onClick={() => revokeRunner(r.id)}
                        className="text-rose-400 hover:text-rose-300 flex items-center gap-1"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        <span>Revoke</span>
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-slate-400 font-bold">CI/CD Pipeline Snippets</span>
                <div className="flex gap-1">
                  {(['githubActions', 'gitlabCi', 'jenkins'] as const).map((k) => (
                    <button
                      key={k}
                      type="button"
                      onClick={() => setCiTab(k)}
                      className={`px-2 py-0.5 rounded text-[10px] ${
                        ciTab === k ? 'bg-cyan-600 text-white' : 'bg-slate-900 text-slate-400'
                      }`}
                    >
                      {k === 'githubActions' ? 'GitHub Actions' : k === 'gitlabCi' ? 'GitLab CI' : 'Jenkins'}
                    </button>
                  ))}
                </div>
              </div>
              <pre className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-emerald-300 overflow-x-auto whitespace-pre">
                {ciSnippets[ciTab] || '# Sign in to load tenant CI/CD pipeline template'}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
