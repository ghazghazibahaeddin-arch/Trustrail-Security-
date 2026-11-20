'use client';

import React from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Edition } from '@/lib/trustrail-store';
import { CreditCard, CheckCircle2 } from 'lucide-react';

export function BillingView() {
  const { org, updateOrgSettings, user } = useTrustrail();
  const isAdmin = user?.role === 'Owner' || user?.role === 'Admin';

  const plans: Array<{
    edition: Edition;
    name: string;
    price: string;
    desc: string;
    features: string[];
  }> = [
    {
      edition: 'developer',
      name: 'Developer Edition',
      price: 'Free',
      desc: 'For independent developers and personal repositories.',
      features: ['Up to 3 Repositories', 'SAST, Secret & SCA/SBOM Scanning', 'Trustrail CLI & MCP Access', 'Policy-as-Code Checks'],
    },
    {
      edition: 'smb',
      name: 'Teams & SMB Edition',
      price: '$199 / mo',
      desc: 'For growing startups and engineering teams.',
      features: ['Up to 25 Repositories', 'Unified Security Graph & Attack Paths', 'IntentLock Change Integrity', 'AI Remediation Assistant'],
    },
    {
      edition: 'enterprise',
      name: 'Enterprise Grid',
      price: '$799 / mo',
      desc: 'For mid-market and enterprise organizations.',
      features: ['Unlimited Repositories & Tenants', 'AI Agent & MCP Runtime Guard', 'Hash-Chained Audit Ledger & Compliance Export', 'Signed Trust Center Passports'],
    },
  ];

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <CreditCard className="w-5 h-5 text-cyan-500" />
              <span>Billing &amp; Subscription Editions</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Manage workspace edition tier for {org.name}.
            </p>
          </div>
          <span className="px-3 py-1 rounded-full text-xs font-mono font-bold bg-cyan-500/15 text-cyan-600 dark:text-cyan-300 border border-cyan-500/30 self-start">
            Current Tier: {org.tierName || org.edition}
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {plans.map((p) => {
            const isCurrent = org.edition === p.edition;
            return (
              <div
                key={p.edition}
                className={`bg-slate-50 dark:bg-slate-950 border rounded-xl p-6 flex flex-col justify-between ${
                  isCurrent ? 'border-cyan-500 shadow-lg shadow-cyan-500/10' : 'border-slate-200 dark:border-slate-800'
                }`}
              >
                <div>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-sm font-bold text-slate-900 dark:text-white">{p.name}</span>
                    {isCurrent && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-cyan-500 text-black">
                        ACTIVE
                      </span>
                    )}
                  </div>
                  <div className="text-2xl font-bold text-slate-900 dark:text-white font-mono mb-2">{p.price}</div>
                  <div className="text-xs text-slate-500 dark:text-slate-400 mb-6">{p.desc}</div>

                  <div className="space-y-2 mb-6">
                    {p.features.map((feat, i) => (
                      <div key={i} className="text-xs text-slate-700 dark:text-slate-300 flex items-center space-x-2">
                        <CheckCircle2 className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
                        <span>{feat}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <button
                  type="button"
                  disabled={isCurrent || !isAdmin}
                  onClick={() => updateOrgSettings({ edition: p.edition })}
                  className={`w-full py-2.5 rounded-lg text-xs font-semibold transition ${
                    isCurrent || !isAdmin
                      ? 'bg-slate-200 dark:bg-slate-900 text-slate-500 border border-slate-300 dark:border-slate-800 cursor-not-allowed'
                      : 'bg-cyan-600 hover:bg-cyan-500 text-white'
                  }`}
                >
                  {isCurrent ? 'Current Plan' : isAdmin ? 'Switch to Plan' : 'Admin Required'}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
