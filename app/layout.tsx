import type { Metadata } from 'next';
import { Plus_Jakarta_Sans, JetBrains_Mono } from 'next/font/google';
import './globals.css';

const sans = Plus_Jakarta_Sans({
  subsets: ['latin'],
  variable: '--font-sans',
});

const mono = JetBrains_Mono({
  subsets: ['latin'],
  variable: '--font-mono',
});

export const metadata: Metadata = {
  title: 'Trustrail Security Cloud — Unified Cybersecurity & Attack Defense Platform',
  description:
    'Unified cybersecurity platform for developers, startups, SMBs, and enterprises. Attack surface discovery, attack path intelligence, vulnerability intelligence, AI remediation autopilot, and IntentLock change integrity.',
  openGraph: {
    title: 'Trustrail Security Cloud',
    description: 'Unified cybersecurity platform for developers, startups, SMBs, and enterprises.',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Trustrail Security Cloud',
    description: 'Unified cybersecurity platform for developers, startups, SMBs, and enterprises.',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`dark ${sans.variable} ${mono.variable}`} suppressHydrationWarning>
      <body
        suppressHydrationWarning
        className="font-sans bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-slate-100 min-h-screen antialiased selection:bg-cyan-500 selection:text-black"
      >
        {children}
      </body>
    </html>
  );
}
