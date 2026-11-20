'use client';

import React, { useState, useRef, useEffect } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Terminal, X, Send } from 'lucide-react';

export function CliModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { runScan, findings, projects, org, graphNodes, issueTrustPassport } = useTrustrail();
  const [input, setInput] = useState('');
  const [logs, setLogs] = useState<string[]>([
    'Trustrail Security Cloud CLI [v4.2-PROD]',
    'Authenticated to Unified Security Control Plane.',
    'Type "help" for commands: trustrail scan | trustrail findings | trustrail graph | trustrail attest',
    '',
  ]);
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
        '  trustrail scan      - Execute backend security scan sweep across organization assets',
        '  trustrail findings  - List prioritized open findings from SQLite store',
        '  trustrail graph     - Query Unified Security Intelligence Graph nodes',
        '  trustrail attest    - Issue a signed Trust Passport attestation',
        '  clear               - Clear terminal output',
        '  exit                - Close CLI window',
        '',
      ]);
    } else if (cmd === 'clear') {
      setLogs(['Trustrail Security Cloud CLI [v4.2-PROD]', '']);
    } else if (cmd === 'exit') {
      onClose();
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
              `[${f.severity}] (${f.status}) ${f.title} — Asset: ${f.assetName} (Risk ${f.riskScore ?? 'N/A'})`
          ),
          '',
        ]);
      }
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
      <div className="w-full max-w-3xl bg-slate-950 border border-slate-800 rounded-xl shadow-2xl flex flex-col h-[500px] max-h-[85vh] overflow-hidden font-mono">
        <div className="bg-slate-900 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-2 text-xs text-cyan-400 font-bold">
            <Terminal className="w-4 h-4" />
            <span>trustrail-cli ~ {org.slug}</span>
          </div>
          <button type="button" onClick={onClose} className="text-slate-400 hover:text-white transition" aria-label="Close CLI">
            <X className="w-4 h-4" />
          </button>
        </div>

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
            placeholder="Type a command (e.g., trustrail findings, trustrail scan)..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="flex-1 bg-transparent border-none text-xs text-slate-200 placeholder-slate-600 focus:outline-none font-mono"
            autoFocus
          />
          <button type="submit" className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono transition">
            <Send className="w-3.5 h-3.5" />
          </button>
        </form>
      </div>
    </div>
  );
}
