import crypto from 'node:crypto';

export interface GraphAssetNode {
  id: string;
  orgId: string;
  name: string;
  assetType: string;
  owner: string;
  internetExposed: boolean;
  criticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export interface GraphEdge {
  id: string;
  orgId: string;
  sourceAssetId: string;
  targetAssetId: string;
  relation: string;
  evidence: string;
}

export interface FindingLink {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  assetId: string;
  assetName: string;
  status: string;
  cvss: number;
}

export interface ComputedAttackPathStep {
  order: number;
  title: string;
  assetType: string;
  assetId: string;
  assetName: string;
  description: string;
  evidence?: string;
}

export interface ComputedAttackPath {
  id: string;
  title: string;
  riskScore: number;
  severity: 'CRITICAL' | 'HIGH';
  likelihood: 'High' | 'Medium';
  impact: string;
  targetAsset: string;
  steps: ComputedAttackPathStep[];
  contributingFindingIds: string[];
  mitigation: string;
  status: 'Active' | 'Mitigated';
}

/**
 * Deterministic graph solver linking open entry-point vulnerabilities through asset edges
 * to crown-jewel targets (Databases, Cloud Storage, Production Services).
 * If contributing findings are resolved, the attack path automatically disappears or flips to Mitigated.
 */
export function synthesizeAttackPaths(
  assets: GraphAssetNode[],
  edges: GraphEdge[],
  findings: FindingLink[]
): ComputedAttackPath[] {
  const assetById = new Map(assets.map((a) => [a.id, a]));
  const adj = new Map<string, GraphEdge[]>();
  for (const e of edges) {
    const list = adj.get(e.sourceAssetId) || [];
    list.push(e);
    adj.set(e.sourceAssetId, list);
  }

  const openFindings = findings.filter(
    (f) => f.status !== 'Resolved' && f.status !== 'False_Positive' && (f.severity === 'CRITICAL' || f.severity === 'HIGH')
  );

  const paths: ComputedAttackPath[] = [];
  const seenSignatures = new Set<string>();

  for (const entryFinding of openFindings) {
    const startAsset = assetById.get(entryFinding.assetId);
    if (!startAsset) continue;

    // BFS to find reachable CRITICAL/HIGH target assets (Database, Cloud Storage, API, Production Service)
    const queue: Array<{ nodeId: string; chain: Array<{ asset: GraphAssetNode; viaEdge?: GraphEdge }> }> = [
      { nodeId: startAsset.id, chain: [{ asset: startAsset }] },
    ];
    const visited = new Set<string>([startAsset.id]);

    while (queue.length > 0) {
      const current = queue.shift()!;
      const currentAsset = assetById.get(current.nodeId);
      if (!currentAsset) continue;

      const isCrownJewel =
        current.chain.length >= 2 &&
        (currentAsset.assetType === 'Database' ||
          currentAsset.assetType === 'Cloud Storage' ||
          currentAsset.criticality === 'CRITICAL');

      if (isCrownJewel) {
        const sig = `${entryFinding.id}->${currentAsset.id}`;
        if (!seenSignatures.has(sig)) {
          seenSignatures.add(sig);
          const steps: ComputedAttackPathStep[] = current.chain.map((hop, idx) => ({
            order: idx + 1,
            title: idx === 0 ? `Initial Weakness (${entryFinding.category})` : hop.viaEdge?.relation || 'Lateral Pivot',
            assetType: hop.asset.assetType,
            assetId: hop.asset.id,
            assetName: hop.asset.name,
            description:
              idx === 0
                ? entryFinding.title
                : hop.viaEdge?.evidence || `Pivot via ${hop.viaEdge?.relation} to ${hop.asset.name}`,
          }));

          const riskScore = Math.min(99, Math.round(entryFinding.cvss * 9 + (currentAsset.criticality === 'CRITICAL' ? 10 : 4)));
          const idHash = crypto.createHash('sha256').update(sig).digest('hex').slice(0, 8);

          paths.push({
            id: `path-${idHash}`,
            title: `${entryFinding.title} → ${currentAsset.name}`,
            riskScore,
            severity: riskScore >= 88 ? 'CRITICAL' : 'HIGH',
            likelihood: entryFinding.severity === 'CRITICAL' ? 'High' : 'Medium',
            impact: `Unrestricted access or lateral compromise path reaching ${currentAsset.name} (${currentAsset.assetType}).`,
            targetAsset: currentAsset.name,
            steps,
            contributingFindingIds: [entryFinding.id],
            mitigation: `Resolve "${entryFinding.title}" on ${startAsset.name} to sever this attack chain.`,
            status: 'Active',
          });
        }
      }

      if (current.chain.length >= 5) continue;

      const outgoing = adj.get(current.nodeId) || [];
      for (const edge of outgoing) {
        if (!visited.has(edge.targetAssetId)) {
          const nextAsset = assetById.get(edge.targetAssetId);
          if (nextAsset) {
            visited.add(edge.targetAssetId);
            queue.push({
              nodeId: edge.targetAssetId,
              chain: [...current.chain, { asset: nextAsset, viaEdge: edge }],
            });
          }
        }
      }
    }
  }

  return paths.sort((a, b) => b.riskScore - a.riskScore);
}
