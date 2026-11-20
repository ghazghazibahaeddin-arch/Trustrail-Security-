'use client';

import React from 'react';

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-slate-950 text-slate-100 min-h-screen flex items-center justify-center p-6">
        <div className="max-w-md w-full bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <h2 className="text-lg font-bold text-white">Application Error</h2>
          <p className="text-xs text-slate-400">
            {error?.message || 'An unexpected runtime error occurred.'}
          </p>
          <button
            onClick={() => reset()}
            className="px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition"
          >
            Try Again
          </button>
        </div>
      </body>
    </html>
  );
}
