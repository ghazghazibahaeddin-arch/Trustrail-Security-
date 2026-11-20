'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Bot, Play } from 'lucide-react';

export function AiAgentsView() {
  const { aiAgents, executeAgentTool, revokeAgent, user } = useTrustrail();
  const [toolInputs, setToolInputs] = useState<Record<string, string>>({});

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Bot className="w-5 h-5 text-cyan-500" />
              <span>AI Agent & MCP Security</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Enforce allowlisted tools, cumulative session action limits, automatic quarantine on violation, and instant revocation.
            </p>
          </div>
          <span className="px-3 py-1 rounded-lg text-xs font-mono font-bold bg-cyan-500/15 text-cyan-600 dark:text-cyan-300 border border-cyan-500/30 tabular-nums">
            {aiAgents.length} Agents Managed
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {aiAgents.map((agent) => {
            const toolVal = toolInputs[agent.id] ?? agent.allowlistedTools[0] ?? 'search_kb';
            return (
              <div
                key={agent.id}
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col justify-between"
              >
                <div className="space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2 min-w-0">
                      <Bot className="w-4 h-4 text-cyan-500 shrink-0" />
                      <span className="text-sm font-bold text-slate-900 dark:text-white truncate">{agent.name}</span>
                    </div>
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold shrink-0 ${
                        agent.status === 'Active' ? 'bg-emerald-500/20 text-emerald-500' : 'bg-rose-500/20 text-rose-500'
                      }`}
                    >
                      {agent.status}
                    </span>
                  </div>
                  <div className="text-xs text-slate-500 font-mono">
                    {agent.type} • {agent.ownerTeam} • Quota: <span className="tabular-nums">{agent.actionsUsed}/{agent.actionLimit}</span>
                  </div>
                  <div className="text-xs text-slate-700 dark:text-slate-300 bg-white dark:bg-slate-900 p-2.5 rounded-lg border border-slate-200 dark:border-slate-800 font-mono">
                    <strong>Allowlist:</strong> {agent.allowlistedTools.join(', ')}
                  </div>
                  <div className="text-xs text-slate-500">
                    <strong>Last Action:</strong> {agent.lastAction}
                  </div>
                </div>

                <div className="pt-4 mt-4 border-t border-slate-200 dark:border-slate-900 space-y-2.5">
                  {user?.role !== 'Viewer' && agent.status === 'Active' && (
                    <div className="flex items-center space-x-2">
                      <input
                        type="text"
                        value={toolVal}
                        onChange={(e) => setToolInputs((prev) => ({ ...prev, [agent.id]: e.target.value }))}
                        placeholder="Tool name..."
                        className="flex-1 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono"
                      />
                      <button
                        type="button"
                        onClick={() => executeAgentTool(agent.id, toolVal)}
                        className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center space-x-1 whitespace-nowrap"
                      >
                        <Play className="w-3 h-3" />
                        <span>Run Tool</span>
                      </button>
                    </div>
                  )}

                  <div className="flex items-center justify-between">
                    <span className={`text-[10px] font-mono ${agent.canaryTriggered ? 'text-rose-500 font-bold' : 'text-slate-500'}`}>
                      {agent.canaryTriggered ? 'Canary Violation Flagged' : 'Canary Clear'}
                    </span>
                    {(user?.role === 'Owner' || user?.role === 'Admin') && (
                      <button
                        type="button"
                        onClick={() => revokeAgent(agent.id, agent.status === 'Active' ? 'Revoked' : 'Active')}
                        className="px-3 py-1.5 rounded-lg bg-white dark:bg-slate-900 hover:bg-slate-100 dark:hover:bg-slate-800 text-cyan-600 dark:text-cyan-400 text-xs font-semibold transition border border-slate-200 dark:border-slate-800"
                      >
                        {agent.status === 'Active' ? 'Revoke Authority' : 'Restore Agent'}
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
