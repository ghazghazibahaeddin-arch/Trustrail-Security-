export interface RiskInput {
  cvss: number;
  exploitability: 'High' | 'Medium' | 'Low' | 'Proof-of-Concept';
  internetExposed: boolean;
  assetCriticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  inActiveAttackPath: boolean;
  fixAvailable: boolean;
}

export interface RiskEvaluation {
  score: number; // 0 - 100
  priorityTier: 'P0-IMMEDIATE' | 'P1-URGENT' | 'P2-ELEVATED' | 'P3-SCHEDULED';
  reasons: string[];
}

export function calculateRiskPriority(input: RiskInput): RiskEvaluation {
  const reasons: string[] = [];
  let score = Math.round(Math.min(10, Math.max(0, input.cvss)) * 6.0); // up to 60 pts from CVSS
  reasons.push(`Base CVSS ${input.cvss.toFixed(1)} (+${score} pts)`);

  const exploitPts =
    input.exploitability === 'High'
      ? 15
      : input.exploitability === 'Proof-of-Concept'
      ? 12
      : input.exploitability === 'Medium'
      ? 7
      : 2;
  score += exploitPts;
  reasons.push(`Exploitability=${input.exploitability} (+${exploitPts} pts)`);

  if (input.internetExposed) {
    score += 10;
    reasons.push('Asset is externally / internet exposed (+10 pts)');
  }

  const critPts =
    input.assetCriticality === 'CRITICAL'
      ? 10
      : input.assetCriticality === 'HIGH'
      ? 6
      : input.assetCriticality === 'MEDIUM'
      ? 3
      : 0;
  if (critPts > 0) {
    score += critPts;
    reasons.push(`Business criticality=${input.assetCriticality} (+${critPts} pts)`);
  }

  if (input.inActiveAttackPath) {
    score += 10;
    reasons.push('Part of a verified multi-step Attack Path (+10 pts)');
  }

  if (input.fixAvailable) {
    reasons.push('Actionable remediation / patch available (ready for immediate closure)');
  }

  const clamped = Math.min(100, Math.max(1, score));
  const priorityTier =
    clamped >= 85
      ? 'P0-IMMEDIATE'
      : clamped >= 70
      ? 'P1-URGENT'
      : clamped >= 45
      ? 'P2-ELEVATED'
      : 'P3-SCHEDULED';

  return { score: clamped, priorityTier, reasons };
}
