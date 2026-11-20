'use client';

import React from 'react';
import { AlertTriangle, RotateCcw } from 'lucide-react';

export default function ErrorBoundary({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div className="min-h-[400px] flex items-center justify-center p-6">
      <div className="max-w-md w-full bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-xl p-6 space-y-4">
        <div className="flex items-center space-x-2 text-rose-600 dark:text-rose-400">
          <AlertTriangle className="w-5 h-5" />
          <h2 className="text-sm font-bold">Something went wrong</h2>
        </div>
        <p className="text-xs text-slate-600 dark:text-slate-400">
          {error?.message || 'An unexpected error occurred while rendering this module.'}
        </p>
        <button
          onClick={() => reset()}
          className="inline-flex items-center space-x-2 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reload Module</span>
        </button>
      </div>
    </div>
  );
}
