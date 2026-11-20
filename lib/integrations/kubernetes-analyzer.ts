import crypto from 'node:crypto';
import type { NormalizedFindingInput } from '@/lib/engines/scanner-engine';

export interface KubernetesResourceSnapshot {
  kind: string;
  name: string;
  namespace?: string;
  privileged?: boolean;
  hostNetwork?: boolean;
  hostPID?: boolean;
  runAsNonRoot?: boolean;
  readOnlyRootFilesystem?: boolean;
  allowPrivilegeEscalation?: boolean;
  wildcardRbac?: boolean;
  clusterAdminBinding?: boolean;
  hasNetworkPolicy?: boolean;
}

export interface KubernetesAnalysisResult {
  resourcesAnalyzed: number;
  findings: NormalizedFindingInput[];
  discoveredAssets: Array<{ name: string; assetType: string; criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' }>;
}

export function analyzeKubernetesManifestOrSnapshot(input: {
  clusterName?: string;
  manifestContent?: string;
  resources?: KubernetesResourceSnapshot[];
}): KubernetesAnalysisResult {
  const cluster = input.clusterName || 'k8s-default';
  const findings: NormalizedFindingInput[] = [];
  const discoveredAssets: KubernetesAnalysisResult['discoveredAssets'] = [];
  let resourcesAnalyzed = 0;

  const pushFinding = (f: Omit<NormalizedFindingInput, 'fingerprint'> & { sig: string }) => {
    findings.push({
      ...f,
      fingerprint: crypto
        .createHash('sha256')
        .update(`K8S|${cluster}|${f.sig}`)
        .digest('hex')
        .slice(0, 16),
    });
  };

  if (input.resources && input.resources.length > 0) {
    for (const r of input.resources) {
      resourcesAnalyzed += 1;
      const ns = r.namespace || 'default';
      const assetLabel = `k8s://${cluster}/${ns}/${r.kind}/${r.name}`;
      discoveredAssets.push({
        name: assetLabel,
        assetType: 'Kubernetes',
        criticality: r.privileged || r.clusterAdminBinding ? 'CRITICAL' : 'HIGH',
      });

      if (r.privileged) {
        pushFinding({
          sig: `privileged:${ns}:${r.name}`,
          title: `Kubernetes Privileged Container Enabled (${r.kind}/${r.name})`,
          severity: 'CRITICAL',
          category: 'CONTAINER',
          scanner: 'trustrail-k8s-analyzer',
          filePath: assetLabel,
          cvss: 9.4,
          exploitability: 'High',
          evidence: `Workload ${ns}/${r.name} runs with securityContext.privileged=true, enabling host breakout.`,
          suggestedFix: 'Set securityContext.privileged: false and drop ALL Linux capabilities.',
          confidence: 0.98,
        });
      }

      if (r.hostNetwork || r.hostPID) {
        pushFinding({
          sig: `hostns:${ns}:${r.name}`,
          title: `Kubernetes Host Namespace Shared (${r.kind}/${r.name})`,
          severity: 'HIGH',
          category: 'CONTAINER',
          scanner: 'trustrail-k8s-analyzer',
          filePath: assetLabel,
          cvss: 8.2,
          exploitability: 'High',
          evidence: `Workload shares hostNetwork=${Boolean(r.hostNetwork)} / hostPID=${Boolean(r.hostPID)}.`,
          suggestedFix: 'Disable hostNetwork and hostPID unless running a verified CNI/node daemon.',
          confidence: 0.95,
        });
      }

      if (r.runAsNonRoot === false || r.allowPrivilegeEscalation === true) {
        pushFinding({
          sig: `podsec:${ns}:${r.name}`,
          title: `Insecure PodSecurity Context (${r.kind}/${r.name})`,
          severity: 'HIGH',
          category: 'CONTAINER',
          scanner: 'trustrail-k8s-analyzer',
          filePath: assetLabel,
          cvss: 7.6,
          exploitability: 'Medium',
          evidence: `Pod permits root execution (runAsNonRoot=${r.runAsNonRoot}) or privilege escalation.`,
          suggestedFix: 'Set runAsNonRoot: true, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true.',
          confidence: 0.92,
        });
      }

      if (r.wildcardRbac || r.clusterAdminBinding) {
        pushFinding({
          sig: `rbac:${ns}:${r.name}`,
          title: `Over-Privileged Kubernetes RBAC Binding (${r.name})`,
          severity: 'CRITICAL',
          category: 'CLOUD',
          scanner: 'trustrail-k8s-rbac-analyzer',
          filePath: assetLabel,
          cvss: 9.2,
          exploitability: 'High',
          evidence: `RBAC role/binding "${r.name}" grants wildcard verbs/resources or cluster-admin privileges.`,
          suggestedFix: 'Replace wildcard "*" permissions with explicit namespace-scoped verbs and resources.',
          confidence: 0.97,
        });
      }

      if (r.hasNetworkPolicy === false) {
        pushFinding({
          sig: `netpol:${ns}:${r.name}`,
          title: `Namespace "${ns}" Lacks Default-Deny NetworkPolicy`,
          severity: 'MEDIUM',
          category: 'IAC',
          scanner: 'trustrail-k8s-netpol-analyzer',
          filePath: assetLabel,
          cvss: 5.8,
          exploitability: 'Medium',
          evidence: `Unrestricted east-west pod traffic permitted inside namespace ${ns}.`,
          suggestedFix: 'Apply a Kubernetes NetworkPolicy enforcing default-deny ingress and egress.',
          confidence: 0.89,
        });
      }
    }
  }

  if (input.manifestContent && input.manifestContent.trim()) {
    const raw = input.manifestContent;
    resourcesAnalyzed += Math.max(1, (raw.match(/kind:\s*/gi) || []).length);
    discoveredAssets.push({
      name: `k8s://${cluster}/manifest`,
      assetType: 'Kubernetes',
      criticality: 'HIGH',
    });

    if (/privileged:\s*true/i.test(raw)) {
      pushFinding({
        sig: 'manifest:privileged',
        title: 'Kubernetes Manifest Enables Privileged SecurityContext',
        severity: 'CRITICAL',
        category: 'CONTAINER',
        scanner: 'trustrail-k8s-analyzer',
        filePath: 'k8s-manifest.yaml',
        cvss: 9.4,
        exploitability: 'High',
        evidence: 'Detected "privileged: true" inside Kubernetes Pod/Deployment specification.',
        suggestedFix: 'Set securityContext.privileged: false and enforce Restricted Pod Security Standards.',
        confidence: 0.98,
      });
    }

    if (/hostNetwork:\s*true|hostPID:\s*true|hostPath:/i.test(raw)) {
      pushFinding({
        sig: 'manifest:host-escape',
        title: 'Kubernetes Manifest Exposes Host Network, PID, or HostPath Mount',
        severity: 'HIGH',
        category: 'CONTAINER',
        scanner: 'trustrail-k8s-analyzer',
        filePath: 'k8s-manifest.yaml',
        cvss: 8.4,
        exploitability: 'High',
        evidence: 'Detected hostNetwork/hostPID/hostPath mounting sensitive node resources.',
        suggestedFix: 'Remove hostPath mounts and host namespace sharing from workload specification.',
        confidence: 0.94,
      });
    }

    if (/allowPrivilegeEscalation:\s*true/i.test(raw) || /runAsUser:\s*0\b/i.test(raw)) {
      pushFinding({
        sig: 'manifest:root-escalation',
        title: 'Kubernetes Container Runs as Root or Permits Privilege Escalation',
        severity: 'HIGH',
        category: 'CONTAINER',
        scanner: 'trustrail-k8s-analyzer',
        filePath: 'k8s-manifest.yaml',
        cvss: 7.8,
        exploitability: 'Medium',
        evidence: 'Detected allowPrivilegeEscalation: true or runAsUser: 0.',
        suggestedFix: 'Set runAsNonRoot: true, runAsUser: 10001, and allowPrivilegeEscalation: false.',
        confidence: 0.92,
      });
    }

    if (/cluster-admin/i.test(raw) || (/verbs:\s*\[[^\]]*["']\*["']/i.test(raw) && /resources:\s*\[[^\]]*["']\*["']/i.test(raw))) {
      pushFinding({
        sig: 'manifest:wildcard-rbac',
        title: 'Kubernetes Manifest Grants Cluster-Admin or Wildcard RBAC Verbs',
        severity: 'CRITICAL',
        category: 'CLOUD',
        scanner: 'trustrail-k8s-rbac-analyzer',
        filePath: 'k8s-rbac.yaml',
        cvss: 9.3,
        exploitability: 'High',
        evidence: 'ClusterRole/Binding grants cluster-admin or "*" verbs on "*" resources.',
        suggestedFix: 'Scope RBAC Role rules strictly to required resource names and read/write verbs.',
        confidence: 0.97,
      });
    }
  }

  return { resourcesAnalyzed, findings, discoveredAssets };
}
