'use client';

import React, { useState } from 'react';
import { useTrustrail } from '@/lib/use-trustrail';
import { Cloud, ArrowRight, PlusCircle } from 'lucide-react';

export function CloudSecurityView() {
  const { graphNodes, cloudResources, findings, connectors, org, setActiveTab, evaluateCloudPosture, user } = useTrustrail();
  const [provider, setProvider] = useState<'aws' | 'azure' | 'gcp'>('aws');
  const [accountId, setAccountId] = useState('928192831100');
  const [region, setRegion] = useState('us-east-1');
  const [resourceArn, setResourceArn] = useState('arn:aws:s3:::acme-prod-ledger-backup');
  const [resourceType, setResourceType] = useState('AWS::S3::Bucket');
  const [exposure, setExposure] = useState<'Public' | 'Internal' | 'Private'>('Public');
  const [encryptionEnabled, setEncryptionEnabled] = useState(false);

  const cloudNodes = graphNodes.filter((n) =>
    ['Cloud Storage', 'IAM Identity', 'Database', 'Secret', 'Kubernetes', 'Cloud Account'].includes(n.assetType)
  );
  const cloudFindings = findings.filter(
    (f) => (f.category === 'CLOUD' || f.category === 'IAC') && f.status !== 'Resolved'
  );
  const awsConnector = connectors.find((c) => c.providerKey === 'aws');

  const handleEvaluate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!accountId.trim() || !resourceArn.trim()) return;
    await evaluateCloudPosture({
      provider,
      accountId: accountId.trim(),
      region: region.trim(),
      resources: [
        {
          resourceType: resourceType.trim(),
          resourceArn: resourceArn.trim(),
          exposure,
          publicAccessBlock: exposure !== 'Public',
          encryptionEnabled,
        },
      ],
    });
  };

  return (
    <div className="space-y-6">
      <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl p-6 space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-slate-900 dark:text-white flex items-center gap-2">
              <Cloud className="w-5 h-5 text-cyan-500" />
              <span>Cloud Security Posture (AWS / Azure / GCP &amp; IaC)</span>
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-1">
              Discovered cloud &amp; data assets for {org.name} ({cloudNodes.length + cloudResources.length} resources, {cloudFindings.length} open cloud/IaC findings).
            </p>
          </div>
          <button
            type="button"
            onClick={() => setActiveTab('integrations')}
            className="px-3 py-1.5 rounded-full text-xs font-mono font-bold bg-cyan-500/15 text-cyan-600 dark:text-cyan-300 border border-cyan-500/30 flex items-center gap-1.5 self-start hover:bg-cyan-500/25"
          >
            <span>AWS Connector: {awsConnector?.status || 'Disconnected'}</span>
            <ArrowRight className="w-3 h-3" />
          </button>
        </div>

        {/* CSPM Resource Drift Evaluator */}
        {user?.role !== 'Viewer' && (
          <form
            onSubmit={handleEvaluate}
            className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 space-y-3"
          >
            <div className="text-xs font-bold text-slate-900 dark:text-white flex items-center gap-1.5">
              <PlusCircle className="w-4 h-4 text-cyan-500" />
              <span>Evaluate Cloud Resource Posture (CSPM)</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-5 gap-2.5">
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value as 'aws' | 'azure' | 'gcp')}
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono"
              >
                <option value="aws">AWS</option>
                <option value="azure">Azure</option>
                <option value="gcp">GCP</option>
              </select>
              <input
                type="text"
                required
                value={accountId}
                onChange={(e) => setAccountId(e.target.value)}
                placeholder="Account / Subscription / Project"
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono"
              />
              <input
                type="text"
                required
                value={resourceType}
                onChange={(e) => setResourceType(e.target.value)}
                placeholder="Resource Type"
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono"
              />
              <input
                type="text"
                required
                value={resourceArn}
                onChange={(e) => setResourceArn(e.target.value)}
                placeholder="Resource ARN / URI"
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono"
              />
              <select
                value={exposure}
                onChange={(e) => setExposure(e.target.value as 'Public' | 'Internal' | 'Private')}
                className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-3 py-2 text-xs font-mono"
              >
                <option value="Public">Public</option>
                <option value="Internal">Internal</option>
                <option value="Private">Private</option>
              </select>
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-4 text-xs">
                <input
                  type="text"
                  value={region}
                  onChange={(e) => setRegion(e.target.value)}
                  placeholder="Region"
                  className="w-32 bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg px-2.5 py-1 text-xs font-mono"
                />
                <label className="inline-flex items-center gap-1.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={encryptionEnabled}
                    onChange={(e) => setEncryptionEnabled(e.target.checked)}
                  />
                  <span>KMS At-Rest Encryption Enabled</span>
                </label>
              </div>
              <button
                type="submit"
                className="px-4 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold"
              >
                Evaluate Cloud Resource
              </button>
            </div>
          </form>
        )}

        {/* Evaluated CSPM Resources */}
        {cloudResources.length > 0 && (
          <div className="space-y-2">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono">
              CSPM Evaluated Cloud Resources ({cloudResources.length})
            </div>
            {cloudResources.map((r) => (
              <div
                key={r.id}
                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
              >
                <div className="min-w-0">
                  <div className="text-xs font-bold font-mono text-slate-900 dark:text-white truncate">
                    {r.resourceArn}
                  </div>
                  <div className="text-[11px] text-slate-500 font-mono">
                    {r.provider.toUpperCase()} • {r.resourceType} • {r.region} • {r.exposure}
                  </div>
                </div>
                <span
                  className={`px-2.5 py-1 rounded text-xs font-mono font-bold border self-start sm:self-center shrink-0 ${
                    r.compliant
                      ? 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                      : 'bg-rose-500/15 text-rose-500 border-rose-500/30'
                  }`}
                >
                  {r.compliant ? 'Compliant' : 'CSPM Drift Detected'}
                </span>
              </div>
            ))}
          </div>
        )}

        {cloudNodes.length === 0 && cloudResources.length === 0 ? (
          <div className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-8 text-center text-xs text-slate-500">
            No cloud infrastructure assets discovered yet for {org.name}. Run an IaC/Terraform scan, evaluate a cloud resource above, or configure cloud credentials in Connectors.
          </div>
        ) : (
          <div className="space-y-3">
            {cloudNodes.map((node) => {
              const hasRisk = node.openFindingsCount > 0 || node.internetExposed;
              return (
                <div
                  key={node.id}
                  className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                >
                  <div className="flex items-center space-x-3">
                    <div
                      className={`w-9 h-9 rounded-lg flex items-center justify-center shrink-0 border ${
                        hasRisk
                          ? 'bg-amber-500/10 text-amber-500 border-amber-500/30'
                          : 'bg-emerald-500/10 text-emerald-500 border-emerald-500/30'
                      }`}
                    >
                      <Cloud className="w-4 h-4" />
                    </div>
                    <div>
                      <div className="text-sm font-bold text-slate-900 dark:text-white font-mono">{node.name}</div>
                      <div className="text-xs text-slate-500">
                        Type: {node.assetType} • Owner: {node.owner} •{' '}
                        {node.internetExposed ? 'Internet Exposed' : 'Private Network'}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center space-x-3 shrink-0">
                    <span className="text-xs font-mono text-slate-500">
                      {node.openFindingsCount} open findings
                    </span>
                    <span
                      className={`px-2.5 py-1 rounded text-xs font-mono font-bold border ${
                        node.openFindingsCount > 0
                          ? 'bg-amber-500/15 text-amber-500 border-amber-500/30'
                          : 'bg-emerald-500/15 text-emerald-500 border-emerald-500/30'
                      }`}
                    >
                      {node.openFindingsCount > 0 ? `${node.criticality} Risk` : 'Compliant'}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
