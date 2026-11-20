'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Sparkles, X, Send, Bot, User, Loader2 } from 'lucide-react';

interface ChatMessage {
  sender: 'ai' | 'user';
  text: string;
  source?: string;
}

export function AssistantModal({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) {
  const { org, user, findings, attackPaths, projects } = useTrustrail();
  const [input, setInput] = useState('');
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      sender: 'ai',
      text: `Hello ${user?.name || 'Security Lead'}. I have access to your ${projects.length} projects, ${findings.length} findings, and ${attackPaths.length} active attack paths. Ask a question about your organization's security posture.`,
      source: 'Unified Security Intelligence Graph',
    },
  ]);
  const [isLoading, setIsLoading] = useState(false);

  if (!isOpen) return null;

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;

    const userText = input.trim();
    setInput('');
    setMessages((prev) => [...prev, { sender: 'user', text: userText }]);
    setIsLoading(true);

    try {
      const res = await fetch('/api/gemini', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt: userText,
          mode: 'assistant',
          context: {
            organization: { name: org.name, riskScore: org.riskScore, securityRating: org.securityRating },
            findingsCount: findings.length,
            criticalFindings: findings
              .filter((f) => f.severity === 'CRITICAL' && f.status !== 'Resolved')
              .map((f) => ({ id: f.id, title: f.title, asset: f.assetName, cvss: f.cvss })),
            attackPathsCount: attackPaths.length,
            projects: projects.map((p) => ({ name: p.name, status: p.status })),
          },
          systemInstruction:
            'You are Trustrail Security AI, an expert defensive cybersecurity assistant. Reference only verified organization context supplied as JSON data. Never fabricate credentials or claim vulnerabilities are fixed without verification.',
        }),
      });

      const data = await res.json();
      if (!res.ok || data.error) {
        throw new Error(data.error || `HTTP ${res.status}`);
      }

      setMessages((prev) => [
        ...prev,
        {
          sender: 'ai',
          text: data.text,
          source: `Gemini (${data.model || 'gemini-4-hydrogen'}) + Unified Graph`,
        },
      ]);
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          sender: 'ai',
          text: `AI Copilot unavailable: ${(err as Error).message}`,
          source: 'Server Verification Error',
        },
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const samplePrompts = [
    'What is our highest-priority security risk right now?',
    'Explain how our critical findings connect to active attack paths.',
    'Which remediation steps reduce our Risk Index fastest?',
  ];

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl flex flex-col h-[620px] max-h-[90vh] overflow-hidden">
        {/* Header */}
        <div className="bg-slate-950 px-6 py-4 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-xl bg-cyan-600 flex items-center justify-center">
              <Sparkles className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="font-bold text-white text-sm flex items-center gap-2">
                <span>Trustrail Intelligence Copilot</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-400 font-mono">
                  Gemini 4
                </span>
              </div>
              <div className="text-xs text-slate-400">Tenant-isolated security intelligence queries</div>
            </div>
          </div>
          <button type="button" onClick={onClose} className="text-slate-400 hover:text-white transition" aria-label="Close assistant">
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Chat Feed */}
        <div className="flex-1 p-6 overflow-y-auto space-y-4 bg-slate-900/50">
          {messages.map((msg, idx) => (
            <div
              key={idx}
              className={`flex items-start space-x-3 ${msg.sender === 'user' ? 'flex-row-reverse space-x-reverse' : ''}`}
            >
              <div
                className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 ${
                  msg.sender === 'ai'
                    ? 'bg-cyan-600/20 text-cyan-400 border border-cyan-500/30'
                    : 'bg-indigo-600/20 text-indigo-300 border border-indigo-500/30'
                }`}
              >
                {msg.sender === 'ai' ? <Bot className="w-4 h-4" /> : <User className="w-4 h-4" />}
              </div>
              <div
                className={`max-w-md rounded-xl p-4 text-xs leading-relaxed whitespace-pre-wrap ${
                  msg.sender === 'ai'
                    ? 'bg-slate-950 border border-slate-800 text-slate-200'
                    : 'bg-cyan-600 text-white'
                }`}
              >
                <div>{msg.text}</div>
                {msg.source && (
                  <div className="mt-2 text-[10px] font-mono text-cyan-400/80 border-t border-slate-800 pt-1.5">
                    Source: {msg.source}
                  </div>
                )}
              </div>
            </div>
          ))}
          {isLoading && (
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-lg bg-cyan-600/20 text-cyan-400 border border-cyan-500/30 flex items-center justify-center">
                <Loader2 className="w-4 h-4 animate-spin" />
              </div>
              <div className="bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs text-slate-400 font-mono">
                Querying Gemini security model...
              </div>
            </div>
          )}
        </div>

        {/* Quick Prompts */}
        <div className="px-6 py-2 bg-slate-950/60 border-t border-slate-800 flex items-center gap-2 overflow-x-auto">
          {samplePrompts.map((prompt, i) => (
            <button
              type="button"
              key={i}
              onClick={() => setInput(prompt)}
              className="text-[11px] whitespace-nowrap px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition border border-slate-700/50 shrink-0"
            >
              {prompt}
            </button>
          ))}
        </div>

        {/* Input Bar */}
        <form onSubmit={handleSend} className="bg-slate-950 p-4 border-t border-slate-800 flex items-center space-x-3">
          <input
            type="text"
            placeholder="Ask about vulnerabilities, attack paths, or compliance..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-4 py-2.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
          />
          <button
            type="submit"
            disabled={isLoading || !input.trim()}
            className="px-4 py-2.5 rounded-xl bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition disabled:opacity-50 flex items-center space-x-1.5 whitespace-nowrap shrink-0"
          >
            <span>Send</span>
            <Send className="w-3.5 h-3.5" />
          </button>
        </form>
      </div>
    </div>
  );
}
