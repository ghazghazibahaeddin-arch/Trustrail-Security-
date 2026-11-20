'use client';

import React, { useState } from 'react';
import { TrustrailProvider, useTrustrail } from '@/lib/use-trustrail';
import { AuthGate } from '@/components/layout/AuthGate';
import { Sidebar } from '@/components/layout/Sidebar';
import { Header } from '@/components/layout/Header';
import { CliModal } from '@/components/modules/CliModal';
import { AssistantModal } from '@/components/modules/AssistantModal';
import { CheckCircle2, AlertCircle, X, Loader2 } from 'lucide-react';

import { OverviewDashboard } from '@/components/modules/OverviewDashboard';
import { SecurityGraphView } from '@/components/modules/SecurityGraphView';
import { AttackPathsView } from '@/components/modules/AttackPathsView';
import { ProjectsView } from '@/components/modules/ProjectsView';
import { VulnerabilitiesView } from '@/components/modules/VulnerabilitiesView';
import { SupplyChainView } from '@/components/modules/SupplyChainView';
import { CicdSecurityView } from '@/components/modules/CicdSecurityView';
import { CloudSecurityView } from '@/components/modules/CloudSecurityView';
import { IdentityAccessView } from '@/components/modules/IdentityAccessView';
import { ApiSecurityView } from '@/components/modules/ApiSecurityView';
import { AiAgentsView } from '@/components/modules/AiAgentsView';
import { ChangeIntegrityView } from '@/components/modules/ChangeIntegrityView';
import { SecurityPoliciesView } from '@/components/modules/SecurityPoliciesView';
import { RemediationCenterView } from '@/components/modules/RemediationCenterView';
import { RuntimeEventsView } from '@/components/modules/RuntimeEventsView';
import { IncidentCommandView } from '@/components/modules/IncidentCommandView';
import { RecoveryView } from '@/components/modules/RecoveryView';
import { DeceptionView } from '@/components/modules/DeceptionView';
import { ComplianceView } from '@/components/modules/ComplianceView';
import { TrustCenterView } from '@/components/modules/TrustCenterView';
import { IntegrationsView } from '@/components/modules/IntegrationsView';
import { TeamAccessView } from '@/components/modules/TeamAccessView';
import { BillingView } from '@/components/modules/BillingView';
import { SettingsView } from '@/components/modules/SettingsView';

function TrustrailAppContent() {
  const { activeTab, user, isLoadingSession, notice, clearNotice } = useTrustrail();
  const [isCliOpen, setIsCliOpen] = useState(false);
  const [isAssistantOpen, setIsAssistantOpen] = useState(false);
  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false);

  if (isLoadingSession) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-200 flex items-center justify-center">
        <div className="flex items-center space-x-3 text-sm font-mono">
          <Loader2 className="w-5 h-5 animate-spin text-cyan-400" />
          <span>Initializing Trustrail Security Cloud...</span>
        </div>
      </div>
    );
  }

  if (!user) {
    return <AuthGate />;
  }

  const renderView = () => {
    switch (activeTab) {
      case 'overview':
        return <OverviewDashboard />;
      case 'graph':
        return <SecurityGraphView />;
      case 'attack-paths':
        return <AttackPathsView />;
      case 'projects':
        return <ProjectsView />;
      case 'vulnerabilities':
        return <VulnerabilitiesView />;
      case 'supply-chain':
        return <SupplyChainView />;
      case 'cicd':
        return <CicdSecurityView />;
      case 'cloud':
        return <CloudSecurityView />;
      case 'identity':
        return <IdentityAccessView />;
      case 'api':
        return <ApiSecurityView />;
      case 'ai-agents':
        return <AiAgentsView />;
      case 'change-integrity':
        return <ChangeIntegrityView />;
      case 'policies':
        return <SecurityPoliciesView />;
      case 'remediation':
        return <RemediationCenterView />;
      case 'runtime':
        return <RuntimeEventsView />;
      case 'incidents':
        return <IncidentCommandView />;
      case 'recovery':
        return <RecoveryView />;
      case 'deception':
        return <DeceptionView />;
      case 'compliance':
        return <ComplianceView />;
      case 'trust-center':
        return <TrustCenterView />;
      case 'integrations':
        return <IntegrationsView />;
      case 'team':
        return <TeamAccessView />;
      case 'billing':
        return <BillingView />;
      case 'settings':
        return <SettingsView />;
      default:
        return <OverviewDashboard />;
    }
  };

  return (
    <div className="flex h-screen bg-slate-50 dark:bg-slate-950 overflow-hidden text-slate-900 dark:text-slate-100">
      <Sidebar
        onOpenCli={() => setIsCliOpen(true)}
        onOpenAssistant={() => setIsAssistantOpen(true)}
        isOpenMobile={isMobileNavOpen}
        onCloseMobile={() => setIsMobileNavOpen(false)}
      />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header
          onOpenAssistant={() => setIsAssistantOpen(true)}
          onOpenMobileNav={() => setIsMobileNavOpen(true)}
        />
        {notice && (
          <div
            className={`px-4 sm:px-8 py-2.5 text-xs flex items-center justify-between border-b ${
              notice.type === 'error'
                ? 'bg-rose-500/15 border-rose-500/30 text-rose-700 dark:text-rose-200'
                : 'bg-emerald-500/15 border-emerald-500/30 text-emerald-700 dark:text-emerald-200'
            }`}
          >
            <div className="flex items-center space-x-2">
              {notice.type === 'error' ? (
                <AlertCircle className="w-4 h-4 shrink-0" />
              ) : (
                <CheckCircle2 className="w-4 h-4 shrink-0" />
              )}
              <span>{notice.message}</span>
            </div>
            <button type="button" onClick={clearNotice} aria-label="Dismiss message">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-slate-50 dark:bg-slate-950/50">
          <div className="max-w-7xl mx-auto">{renderView()}</div>
        </main>
      </div>

      <CliModal isOpen={isCliOpen} onClose={() => setIsCliOpen(false)} />
      <AssistantModal isOpen={isAssistantOpen} onClose={() => setIsAssistantOpen(false)} />
    </div>
  );
}

export default function Page() {
  return (
    <TrustrailProvider>
      <TrustrailAppContent />
    </TrustrailProvider>
  );
}
