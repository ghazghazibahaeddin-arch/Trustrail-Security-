'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Network, FolderGit2, Cloud, KeyRound, Database, Bot, Download } from 'lucide-react';

export function SecurityGraphView() {
  const { graphNodes, graphEdges, attackPaths } = useTrustrail();
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<string>('all');

  const assetTypes = ['all', ...Array.from(new Set(graphNodes.map((n) => n.assetType)))];
  const selectedNode = graphNodes.find((n) => n.id === selectedNodeId) || graphNodes[0] || null;
  const outboundEdges = graphEdges.filter((e) => e.sourceAssetId === selectedNode?.id);
  const inboundEdges = graphEdges.filter((e) => e.targetAssetId === selectedNode?.id);
  const nodeNameById = new Map(graphNodes.map((n) => [n.id, n.name]));

  const handleExport = () => {
    const payload = {
      exportedAt: new Date().toISOString(),
      nodes: graphNodes,
      edges: graphEdges,
      attackPaths,
    };
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'trustrail-security-graph.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Network className="w-5 h-5 text-cyan-500" />
              <span>Unified Security Intelligence Graph</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Asset relationships linking repositories, CI/CD pipelines, IAM roles, storage buckets, APIs, and databases.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            {assetTypes.map((type) => (
              <button
                type="button"
                key={type}
                onClick={() => setFilterType(type)}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                  filterType === type
                    ? 'bg-cyan-500/20 text-cyan-600 dark:text-cyan-400 border border-cyan-500/30'
                    : 'bg-slate-100 dark:bg-slate-950 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                {type === 'all' ? 'All Assets' : type}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Graph Grid */}
          <div className="lg:col-span-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-6 flex flex-col justify-between min-h-[420px]">
            <div className="text-xs font-mono text-slate-500 mb-4 flex items-center justify-between">
              <span className="tabular-nums">
                Graph Nodes: {graphNodes.length} • Edges: {graphEdges.length}
              </span>
              <span className="text-emerald-600 dark:text-emerald-400 tabular-nums">
                Active Paths: {attackPaths.length}
              </span>
            </div>

            {graphNodes.length === 0 ? (
              <div className="text-xs text-slate-500 text-center my-auto py-12">
                No graph assets registered yet. Create a project or run a scan to populate the Security Graph.
              </div>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 my-auto">
                {graphNodes
                  .filter((n) => filterType === 'all' || n.assetType === filterType)
                  .map((node) => (
                    <button
                      type="button"
                      key={node.id}
                      onClick={() => setSelectedNodeId(node.id)}
                      className={`text-left p-4 rounded-xl border transition flex items-center justify-between gap-2 ${
                        selectedNode?.id === node.id
                          ? 'bg-cyan-500/10 border-cyan-500/50'
                          : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-400'
                      }`}
                    >
                      <div className="flex items-center space-x-3 min-w-0">
                        <div
                          className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 ${
                            node.criticality === 'CRITICAL'
                              ? 'bg-rose-500/15 text-rose-500'
                              : node.criticality === 'HIGH'
                              ? 'bg-amber-500/15 text-amber-500'
                              : 'bg-cyan-500/15 text-cyan-500'
                          }`}
                        >
                          {node.assetType === 'Repository' ? (
                            <FolderGit2 className="w-4 h-4" />
                          ) : node.assetType === 'Cloud Storage' ? (
                            <Cloud className="w-4 h-4" />
                          ) : node.assetType === 'IAM Identity' ? (
                            <KeyRound className="w-4 h-4" />
                          ) : node.assetType === 'AI Agent / MCP' ? (
                            <Bot className="w-4 h-4" />
                          ) : (
                            <Database className="w-4 h-4" />
                          )}
                        </div>
                        <div className="min-w-0">
                          <div className="text-xs font-semibold text-slate-900 dark:text-white truncate">{node.name}</div>
                          <div className="text-[10px] text-slate-500 font-mono">
                            {node.assetType} • {node.openFindingsCount} open
                          </div>
                        </div>
                      </div>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold shrink-0 ${
                          node.criticality === 'CRITICAL'
                            ? 'bg-rose-500/20 text-rose-500'
                            : node.criticality === 'HIGH'
                            ? 'bg-amber-500/20 text-amber-500'
                            : 'bg-emerald-500/20 text-emerald-500'
                        }`}
                      >
                        {node.criticality}
                      </span>
                    </button>
                  ))}
              </div>
            )}

            <div className="text-[11px] text-slate-500 font-mono mt-4 pt-4 border-t border-slate-200 dark:border-slate-900 flex items-center justify-between">
              <span>Tenant-isolated graph traversal</span>
              <span>Click any asset node to inspect edges</span>
            </div>
          </div>

          {/* Node Inspector Panel */}
          <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-6 flex flex-col justify-between">
            <div>
              <div className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider mb-4 flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-500" />
                <span>Asset Inspector</span>
              </div>
              {selectedNode ? (
                <div className="space-y-4">
                  <div>
                    <div className="text-[10px] font-mono text-slate-500 uppercase">Asset Name</div>
                    <div className="text-xs font-mono text-cyan-600 dark:text-cyan-400 break-all">{selectedNode.name}</div>
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      Owner: {selectedNode.owner} • Exposed: {selectedNode.internetExposed ? 'Internet Facing' : 'Internal'}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] font-mono text-slate-500 uppercase">Outbound Dependencies</div>
                    <div className="space-y-1.5 mt-1">
                      {outboundEdges.length === 0 ? (
                        <div className="text-xs text-slate-500">No outbound edges</div>
                      ) : (
                        outboundEdges.map((edge) => (
                          <div
                            key={edge.id}
                            className="text-xs font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-2 rounded text-slate-700 dark:text-slate-300"
                          >
                            <div className="text-cyan-600 dark:text-cyan-400 font-bold">
                              {edge.relation} → {nodeNameById.get(edge.targetAssetId) || edge.targetAssetId}
                            </div>
                            <div className="text-[10px] text-slate-500 mt-0.5">{edge.evidence}</div>
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                  <div>
                    <div className="text-[10px] font-mono text-slate-500 uppercase">Inbound Trust Paths</div>
                    <div className="space-y-1.5 mt-1">
                      {inboundEdges.length === 0 ? (
                        <div className="text-xs text-slate-500">No inbound edges</div>
                      ) : (
                        inboundEdges.map((edge) => (
                          <div
                            key={edge.id}
                            className="text-xs font-mono bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 p-2 rounded text-slate-700 dark:text-slate-300"
                          >
                            {nodeNameById.get(edge.sourceAssetId) || edge.sourceAssetId} —[{edge.relation}]→
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-slate-500 text-center py-12">Select a node to inspect dependencies.</div>
              )}
            </div>
            <div className="mt-6 pt-4 border-t border-slate-200 dark:border-slate-900">
              <button
                type="button"
                onClick={handleExport}
                className="w-full py-2.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition flex items-center justify-center space-x-2"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export Graph Evidence (JSON)</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
