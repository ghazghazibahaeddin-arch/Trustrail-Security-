'use client';

import React from 'react';
import { useTrustrail, NavTab } from '@/lib/use-trustrail';
import {
  ShieldCheck,
  LayoutDashboard,
  Network,
  GitPullRequest,
  FolderGit2,
  AlertTriangle,
  PackageCheck,
  Workflow,
  Cloud,
  KeyRound,
  NetworkIcon,
  Bot,
  Lock,
  FileCode2,
  Wrench,
  Activity,
  Flame,
  LifeBuoy,
  Eye,
  FileCheck2,
  BadgeCheck,
  Plug,
  Users,
  CreditCard,
  Settings as SettingsIcon,
  Terminal,
  Sparkles,
  X,
} from 'lucide-react';

interface NavItem {
  id: NavTab;
  label: string;
  icon: React.ElementType;
  badge?: string;
}

interface NavGroup {
  group: string;
  items: NavItem[];
}

export function Sidebar({
  onOpenCli,
  onOpenAssistant,
  isOpenMobile,
  onCloseMobile,
}: {
  onOpenCli: () => void;
  onOpenAssistant: () => void;
  isOpenMobile: boolean;
  onCloseMobile: () => void;
}) {
  const { activeTab, setActiveTab, org, findings, attackPaths, aiAgents, connectors } = useTrustrail();

  const openFindingsCount = findings.filter((f) => f.status !== 'Resolved' && f.status !== 'False_Positive').length;
  const activeConnectorsCount = connectors.filter((c) => c.status === 'Connected').length;

  const groups: NavGroup[] = [
    {
      group: 'Intelligence & Graph',
      items: [
        { id: 'overview', label: 'Overview Dashboard', icon: LayoutDashboard },
        { id: 'graph', label: 'Security Intelligence Graph', icon: Network },
        {
          id: 'attack-paths',
          label: 'Attack Paths',
          icon: GitPullRequest,
          badge: attackPaths.length > 0 ? `${attackPaths.length} Active` : undefined,
        },
      ],
    },
    {
      group: 'Code & Supply Chain',
      items: [
        { id: 'projects', label: 'Projects & Repositories', icon: FolderGit2 },
        {
          id: 'vulnerabilities',
          label: 'Vulnerability Center',
          icon: AlertTriangle,
          badge: openFindingsCount > 0 ? String(openFindingsCount) : undefined,
        },
        { id: 'supply-chain', label: 'Supply Chain & SBOM', icon: PackageCheck },
        { id: 'cicd', label: 'CI/CD Security Guardian', icon: Workflow },
      ],
    },
    {
      group: 'Cloud & Access',
      items: [
        { id: 'cloud', label: 'Cloud Security (AWS)', icon: Cloud },
        { id: 'identity', label: 'Identity & Privilege', icon: KeyRound },
        { id: 'api', label: 'API & Exposure Security', icon: NetworkIcon },
        {
          id: 'ai-agents',
          label: 'AI Agents & MCP',
          icon: Bot,
          badge: aiAgents.length > 0 ? String(aiAgents.length) : undefined,
        },
      ],
    },
    {
      group: 'Change & Prevention',
      items: [
        { id: 'change-integrity', label: 'Change Integrity & IntentLock', icon: Lock },
        { id: 'policies', label: 'Security Policies (OPA)', icon: FileCode2 },
        { id: 'remediation', label: 'AI Remediation Autopilot', icon: Wrench },
      ],
    },
    {
      group: 'Runtime & Response',
      items: [
        { id: 'runtime', label: 'Runtime Threat Events', icon: Activity },
        { id: 'incidents', label: 'Incident Command Center', icon: Flame },
        { id: 'recovery', label: 'Recovery & Readiness', icon: LifeBuoy },
        { id: 'deception', label: 'Deception & Canaries', icon: Eye },
      ],
    },
    {
      group: 'Trust & Enterprise',
      items: [
        { id: 'compliance', label: 'Compliance & Evidence', icon: FileCheck2 },
        { id: 'trust-center', label: 'Customer Trust Center', icon: BadgeCheck },
        {
          id: 'integrations',
          label: 'Connector Framework',
          icon: Plug,
          badge: `${activeConnectorsCount}/${connectors.length}`,
        },
        { id: 'team', label: 'Team & RBAC', icon: Users },
        { id: 'billing', label: 'Billing & Editions', icon: CreditCard },
        { id: 'settings', label: 'Settings & Audit Logs', icon: SettingsIcon },
      ],
    },
  ];

  const handleNav = (id: NavTab) => {
    setActiveTab(id);
    onCloseMobile();
  };

  return (
    <>
      {isOpenMobile && (
        <div
          className="fixed inset-0 bg-black/60 z-40 lg:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      )}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-72 bg-white dark:bg-slate-900 border-r border-slate-200 dark:border-slate-800 flex flex-col h-screen lg:sticky lg:top-0 text-slate-700 dark:text-slate-300 select-none transition-transform duration-200 ${
          isOpenMobile ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand Header */}
        <div className="p-4 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between gap-2">
          <div className="flex items-center space-x-3 min-w-0">
            <div className="w-9 h-9 rounded-xl bg-cyan-600 flex items-center justify-center shrink-0">
              <ShieldCheck className="w-5 h-5 text-white" />
            </div>
            <div className="min-w-0">
              <div className="font-bold text-slate-900 dark:text-white tracking-wider text-sm flex items-center gap-1.5">
                <span>TRUSTRAIL</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/15 text-cyan-700 dark:text-cyan-400 font-mono">
                  CLOUD
                </span>
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400 truncate">{org.name}</div>
            </div>
          </div>
          <button
            type="button"
            onClick={onCloseMobile}
            className="lg:hidden p-1.5 rounded-lg text-slate-400 hover:text-slate-900 dark:hover:text-white"
            aria-label="Close navigation"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Quick Actions Bar */}
        <div className="p-3 border-b border-slate-200 dark:border-slate-800 grid grid-cols-2 gap-2 bg-slate-50 dark:bg-slate-950/40">
          <button
            type="button"
            onClick={() => {
              onOpenCli();
              onCloseMobile();
            }}
            className="flex items-center justify-center space-x-1.5 px-3 py-2 rounded-lg bg-white dark:bg-slate-800 hover:bg-slate-100 dark:hover:bg-slate-700 text-xs font-mono text-cyan-700 dark:text-cyan-400 transition border border-slate-200 dark:border-slate-700/60 whitespace-nowrap"
          >
            <Terminal className="w-3.5 h-3.5 shrink-0" />
            <span>CLI Scan</span>
          </button>
          <button
            type="button"
            onClick={() => {
              onOpenAssistant();
              onCloseMobile();
            }}
            className="flex items-center justify-center space-x-1.5 px-3 py-2 rounded-lg bg-cyan-600/10 hover:bg-cyan-600/20 text-xs font-medium text-cyan-800 dark:text-white transition border border-cyan-500/30 whitespace-nowrap"
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-300 shrink-0" />
            <span>AI Copilot</span>
          </button>
        </div>

        {/* Navigation Tree */}
        <nav className="flex-1 overflow-y-auto px-3 py-4 space-y-5">
          {groups.map((group) => (
            <div key={group.group}>
              <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500 px-3 mb-1.5">
                {group.group}
              </div>
              <div className="space-y-0.5">
                {group.items.map((item) => {
                  const Icon = item.icon;
                  const isActive = activeTab === item.id;
                  return (
                    <button
                      type="button"
                      key={item.id}
                      onClick={() => handleNav(item.id)}
                      className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-medium transition ${
                        isActive
                          ? 'bg-cyan-500/10 text-cyan-700 dark:text-cyan-400 border border-cyan-500/30'
                          : 'text-slate-600 dark:text-slate-400 hover:text-slate-950 dark:hover:text-slate-100 hover:bg-slate-100 dark:hover:bg-slate-800/60'
                      }`}
                    >
                      <div className="flex items-center space-x-2.5 min-w-0">
                        <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-cyan-600 dark:text-cyan-400' : 'text-slate-400'}`} />
                        <span className="truncate">{item.label}</span>
                      </div>
                      {item.badge && (
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded font-mono tabular-nums shrink-0 ${
                            item.badge.includes('Active')
                              ? 'bg-rose-500/15 text-rose-600 dark:text-rose-300 border border-rose-500/30'
                              : 'bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300'
                          }`}
                        >
                          {item.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Footer Version */}
        <div className="p-3 border-t border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950/80 flex items-center justify-between text-xs text-slate-500">
          <span className="font-mono text-[11px]">Unified Security Engine</span>
          <span className="text-[10px] font-mono tabular-nums">v4.2-PROD</span>
        </div>
      </aside>
    </>
  );
}
