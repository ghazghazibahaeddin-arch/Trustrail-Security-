'use client';

import React, { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { TrustrailProvider, useTrustrail } from '@/lib/use-trustrail';
import { AuthGate } from '@/components/layout/AuthGate';
import { Loader2 } from 'lucide-react';

function RegisterPageContent() {
  const router = useRouter();
  const { user, isLoadingSession } = useTrustrail();

  useEffect(() => {
    if (!isLoadingSession && user) {
      router.replace('/');
    }
  }, [isLoadingSession, user, router]);

  if (isLoadingSession || user) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-200 flex items-center justify-center">
        <div className="flex items-center space-x-3 text-xs font-mono">
          <Loader2 className="w-4 h-4 animate-spin text-cyan-400" />
          <span>{user ? 'Redirecting to Trustrail Console...' : 'Checking session...'}</span>
        </div>
      </div>
    );
  }

  return <AuthGate initialMode="register" onAuthenticated={() => router.replace('/')} />;
}

export default function RegisterPage() {
  return (
    <TrustrailProvider>
      <RegisterPageContent />
    </TrustrailProvider>
  );
}
