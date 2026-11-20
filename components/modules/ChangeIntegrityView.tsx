'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Lock, Plus, Play, ShieldAlert } from 'lucide-react';

export function ChangeIntegrityView() {
  const {
    changeContracts,
    createChangeContract,
    tamperChangeContract,
    approveChange,
    revokeApproval,
    executeChange,
    user,
  } = useTrustrail();

  const [showCreate, setShowCreate] = useState(false);
  const [title, setTitle] = useState('');
  const [project, setProject] = useState('terraform-aws-core');
  const [targetAsset, setTargetAsset] = useState('sg-0892a9128374');
  const [purpose, setPurpose] = useState('');
  const [payloadJson, setPayloadJson] = useState('{"ingress":[{"port":443,"cidr":"10.20.0.0/16"}]}');

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !purpose.trim()) return;
    let parsed: Record<string, unknown> = { raw: payloadJson };
    try {
      parsed = JSON.parse(payloadJson) as Record<string, unknown>;
    } catch {
      // keep raw
    }
    await createChangeContract({
      title,
      project,
      targetAsset,
      purpose,
      newStatePayload: parsed,
      riskLevel: 'Medium',
    });
    setTitle('');
    setPurpose('');
    setShowCreate(false);
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Lock className="w-5 h-5 text-cyan-500" />
              <span>Universal Change Passport & IntentLock</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Cryptographic SHA-256 intent binding: post-approval mutations automatically invalidate approval.
            </p>
          </div>
          {user?.role !== 'Viewer' && (
            <button
              type="button"
              onClick={() => setShowCreate(!showCreate)}
              className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition whitespace-nowrap shrink-0 self-start"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Change Contract</span>
            </button>
          )}
        </div>

        {showCreate && (
          <form
            onSubmit={handleCreate}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 mb-6 space-y-3"
          >
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <input
                type="text"
                required
                placeholder="Change Title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
              />
              <input
                type="text"
                required
                placeholder="Project"
                value={project}
                onChange={(e) => setProject(e.target.value)}
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
              />
              <input
                type="text"
                required
                placeholder="Target Asset ID"
                value={targetAsset}
                onChange={(e) => setTargetAsset(e.target.value)}
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
              />
            </div>
            <input
              type="text"
              required
              placeholder="Intended change purpose..."
              value={purpose}
              onChange={(e) => setPurpose(e.target.value)}
              className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs"
            />
            <textarea
              rows={2}
              value={payloadJson}
              onChange={(e) => setPayloadJson(e.target.value)}
              className="w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-2.5 text-xs font-mono"
            />
            <div className="flex justify-end">
              <button type="submit" className="px-4 py-2 rounded-lg bg-cyan-600 text-white text-xs font-semibold">
                Create & Seal Hash
              </button>
            </div>
          </form>
        )}

        <div className="space-y-4">
          {changeContracts.map((c) => (
            <div
              key={c.id}
              className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col lg:flex-row lg:items-center justify-between gap-4"
            >
              <div className="space-y-2 flex-1 min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      c.intentLockStatus === 'Approved' || c.intentLockStatus === 'Executed'
                        ? 'bg-emerald-500/20 text-emerald-500 border border-emerald-500/30'
                        : c.intentLockStatus === 'Modified_Revalidation_Required'
                        ? 'bg-rose-500/20 text-rose-500 border border-rose-500/30'
                        : 'bg-amber-500/20 text-amber-500 border border-amber-500/30'
                    }`}
                  >
                    IntentLock: {c.intentLockStatus}
                  </span>
                  <span className="text-[10px] font-mono text-cyan-600 dark:text-cyan-400">
                    {c.project} • {c.targetAsset}
                  </span>
                </div>
                <div className="text-sm font-bold text-slate-900 dark:text-white">{c.title}</div>
                <div className="text-xs text-slate-600 dark:text-slate-400">
                  <strong>Purpose:</strong> {c.purpose}
                </div>
                <div className="text-[11px] font-mono text-slate-500 break-all">
                  Current SHA-256: {c.newStateHash}
                </div>
                {c.intentLockReason && (
                  <div className="text-[11px] text-slate-500">{c.intentLockReason}</div>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2 shrink-0">
                {(user?.role === 'Owner' || user?.role === 'Admin') && c.intentLockStatus !== 'Approved' && c.intentLockStatus !== 'Executed' && (
                  <button
                    type="button"
                    onClick={() => approveChange(c.id)}
                    className="px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition whitespace-nowrap"
                  >
                    Approve Change
                  </button>
                )}

                {user?.role !== 'Viewer' && c.intentLockStatus === 'Approved' && (
                  <>
                    <button
                      type="button"
                      onClick={() => executeChange(c.id)}
                      className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition flex items-center space-x-1 whitespace-nowrap"
                    >
                      <Play className="w-3.5 h-3.5" />
                      <span>Execute</span>
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        tamperChangeContract(c.id, {
                          ...(c.newStatePayload || {}),
                          injectedBackdoorCidr: '0.0.0.0/0',
                          port: 22,
                        })
                      }
                      className="px-3 py-2 rounded-lg bg-amber-600/20 hover:bg-amber-600/30 text-amber-500 border border-amber-500/30 text-xs font-semibold transition flex items-center space-x-1 whitespace-nowrap"
                    >
                      <ShieldAlert className="w-3.5 h-3.5" />
                      <span>Simulate Drift</span>
                    </button>
                  </>
                )}

                {(user?.role === 'Owner' || user?.role === 'Admin') && c.intentLockStatus === 'Approved' && (
                  <button
                    type="button"
                    onClick={() => revokeApproval(c.id)}
                    className="px-3 py-2 rounded-lg bg-rose-500/15 hover:bg-rose-500/25 text-rose-500 text-xs font-semibold transition border border-rose-500/30 whitespace-nowrap"
                  >
                    Revoke
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
