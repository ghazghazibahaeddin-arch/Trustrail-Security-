'use client';

import React, { useState, useMemo } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import {
  Search,
  Bell,
  Play,
  Loader2,
  Menu,
  Sun,
  Moon,
  LogOut,
  Building2,
} from 'lucide-react';

export function Header({
  onOpenMobileNav,
}: {
  onOpenAssistant: () => void;
  onOpenMobileNav: () => void;
}) {
  const {
    user,
    org,
    memberships,
    switchOrganization,
    logout,
    runScan,
    isScanning,
    findings,
    projects,
    attackPaths,
    setActiveTab,
    globalSearch,
    setGlobalSearch,
    theme,
    toggleTheme,
  } = useTrustrail();

  const [showNotifications, setShowNotifications] = useState(false);
  const [showSearchDropdown, setShowSearchDropdown] = useState(false);

  const openAlerts = useMemo(
    () =>
      findings.filter(
        (f) => f.status !== 'Resolved' && f.status !== 'False_Positive' && (f.severity === 'CRITICAL' || f.severity === 'HIGH')
      ),
    [findings]
  );

  const searchResults = useMemo(() => {
    const q = globalSearch.trim().toLowerCase();
    if (!q) return [];
    const items: Array<{ label: string; sub: string; tab: 'vulnerabilities' | 'projects' | 'attack-paths' }> = [];

    for (const f of findings) {
      if (f.title.toLowerCase().includes(q) || f.assetName.toLowerCase().includes(q)) {
        items.push({ label: f.title, sub: `Finding (${f.severity}) • ${f.assetName}`, tab: 'vulnerabilities' });
      }
    }
    for (const p of projects) {
      if (p.name.toLowerCase().includes(q) || p.repoUrl.toLowerCase().includes(q)) {
        items.push({ label: p.name, sub: `Project • ${p.repoUrl}`, tab: 'projects' });
      }
    }
    for (const ap of attackPaths) {
      if (ap.title.toLowerCase().includes(q)) {
        items.push({ label: ap.title, sub: `Attack Path (${ap.riskScore}/100)`, tab: 'attack-paths' });
      }
    }
    return items.slice(0, 6);
  }, [globalSearch, findings, projects, attackPaths]);

  return (
    <header className="h-16 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 px-4 sm:px-6 flex items-center justify-between gap-3 sticky top-0 z-30">
      <div className="flex items-center space-x-3 flex-1 max-w-xl min-w-0">
        <button
          type="button"
          onClick={onOpenMobileNav}
          className="lg:hidden p-2 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300"
          aria-label="Open navigation menu"
        >
          <Menu className="w-4 h-4" />
        </button>

        {/* Live Global Search */}
        <div className="relative flex-1 min-w-0">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            type="text"
            placeholder="Search findings, repos, or attack paths..."
            value={globalSearch}
            onFocus={() => setShowSearchDropdown(true)}
            onBlur={() => setTimeout(() => setShowSearchDropdown(false), 180)}
            onChange={(e) => {
              setGlobalSearch(e.target.value);
              setShowSearchDropdown(true);
            }}
            className="w-full bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg pl-9 pr-4 py-2 text-xs text-slate-900 dark:text-slate-200 placeholder-slate-400 focus:outline-none focus:border-cyan-500 transition"
          />

          {showSearchDropdown && globalSearch.trim().length > 0 && (
            <div className="absolute left-0 right-0 mt-1.5 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-xl p-2 z-50 max-h-72 overflow-y-auto">
              {searchResults.length === 0 ? (
                <div className="text-xs text-slate-500 p-3 text-center">No matching security entities found.</div>
              ) : (
                searchResults.map((item, idx) => (
                  <button
                    type="button"
                    key={idx}
                    onMouseDown={() => {
                      setActiveTab(item.tab);
                      setShowSearchDropdown(false);
                    }}
                    className="w-full text-left px-3 py-2 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition"
                  >
                    <div className="text-xs font-semibold text-slate-900 dark:text-white truncate">{item.label}</div>
                    <div className="text-[10px] font-mono text-slate-500 truncate">{item.sub}</div>
                  </button>
                ))
              )}
            </div>
          )}
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center space-x-2 sm:space-x-3 shrink-0">
        {memberships.length > 1 && (
          <div className="hidden md:flex items-center space-x-1.5 bg-slate-100 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1.5">
            <Building2 className="w-3.5 h-3.5 text-cyan-500 shrink-0" />
            <select
              aria-label="Switch organization"
              value={org.id}
              onChange={(e) => switchOrganization(e.target.value)}
              className="bg-transparent text-xs font-medium text-slate-800 dark:text-slate-200 focus:outline-none"
            >
              {memberships.map((m) => (
                <option key={m.orgId} value={m.orgId} className="bg-slate-900 text-white">
                  {m.orgName} ({m.role})
                </option>
              ))}
            </select>
          </div>
        )}

        <button
          type="button"
          onClick={() => runScan()}
          disabled={isScanning || user?.role === 'Viewer'}
          title={user?.role === 'Viewer' ? 'Viewer role cannot trigger scans' : 'Run Unified Security Scan'}
          className="flex items-center space-x-1.5 px-3 sm:px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition disabled:opacity-50 whitespace-nowrap shrink-0"
        >
          {isScanning ? (
            <>
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              <span>Scanning...</span>
            </>
          ) : (
            <>
              <Play className="w-3.5 h-3.5 fill-white" />
              <span className="hidden sm:inline">Trustrail Scan</span>
            </>
          )}
        </button>

        {/* Theme Toggle */}
        <button
          type="button"
          onClick={toggleTheme}
          aria-label="Toggle color theme"
          className="p-2 rounded-lg bg-slate-100 dark:bg-slate-800/80 hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700/50 transition shrink-0"
        >
          {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>

        {/* Notifications */}
        <div className="relative shrink-0">
          <button
            type="button"
            onClick={() => setShowNotifications(!showNotifications)}
            aria-label="Security alerts"
            className="relative p-2 rounded-lg bg-slate-100 dark:bg-slate-800/80 hover:bg-slate-200 dark:hover:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700/50 transition"
          >
            <Bell className="w-4 h-4" />
            {openAlerts.length > 0 && (
              <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-500 text-[10px] font-bold text-white flex items-center justify-center tabular-nums">
                {openAlerts.length}
              </span>
            )}
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl shadow-2xl p-4 z-50">
              <div className="flex items-center justify-between pb-3 border-b border-slate-200 dark:border-slate-800 mb-3">
                <span className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">Security Alerts</span>
                <span className="text-[10px] font-mono text-cyan-600 dark:text-cyan-400 tabular-nums">{openAlerts.length} open</span>
              </div>
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {openAlerts.length === 0 ? (
                  <div className="text-xs text-slate-500 py-4 text-center">Zero critical or high open alerts.</div>
                ) : (
                  openAlerts.slice(0, 5).map((f) => (
                    <button
                      type="button"
                      key={f.id}
                      onClick={() => {
                        setActiveTab('vulnerabilities');
                        setShowNotifications(false);
                      }}
                      className="w-full text-left p-2.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-cyan-500/40 text-xs transition"
                    >
                      <div className="flex items-center justify-between mb-1">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                            f.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-500' : 'bg-amber-500/20 text-amber-500'
                          }`}
                        >
                          {f.severity}
                        </span>
                        <span className="text-[10px] text-slate-500 font-mono">{f.category}</span>
                      </div>
                      <div className="font-medium text-slate-900 dark:text-slate-200 truncate">{f.title}</div>
                      <div className="text-[10px] text-slate-500 truncate mt-0.5">Asset: {f.assetName}</div>
                    </button>
                  ))
                )}
              </div>
            </div>
          )}
        </div>

        {/* User Profile & Logout */}
        <div className="flex items-center space-x-2 pl-2.5 border-l border-slate-200 dark:border-slate-800 shrink-0">
          <button
            type="button"
            onClick={() => setActiveTab('settings')}
            title="Account & API Keys"
            className="flex items-center space-x-2 px-2 py-1 rounded-lg hover:bg-slate-100 dark:hover:bg-slate-800 transition text-left"
          >
            <div className="w-7 h-7 rounded-lg bg-indigo-600/20 border border-indigo-500/40 flex items-center justify-center text-indigo-600 dark:text-indigo-300 font-bold text-[11px] shrink-0">
              {(user?.name || 'TR').slice(0, 2).toUpperCase()}
            </div>
            <div className="hidden xl:block">
              <div className="text-xs font-semibold text-slate-900 dark:text-white leading-tight">{user?.name}</div>
              <div className="text-[10px] font-mono text-slate-500 dark:text-slate-400">
                {user?.role} • {org.slug}
              </div>
            </div>
          </button>
          <button
            type="button"
            onClick={logout}
            title="Sign out"
            aria-label="Sign out"
            className="inline-flex items-center space-x-1 px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700/70 text-xs font-medium text-slate-600 dark:text-slate-300 hover:text-rose-500 hover:border-rose-500/40 transition whitespace-nowrap shrink-0"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Sign Out</span>
          </button>
        </div>
      </div>
    </header>
  );
}
