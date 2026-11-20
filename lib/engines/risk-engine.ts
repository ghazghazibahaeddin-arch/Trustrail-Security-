export interface RiskInput {
  cvss: number;
  exploitability: 'High' | 'Medium' | 'Low' | 'Proof-of-Concept';
  internetExposed: boolean;
  assetCriticality: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  inActiveAttackPath: boolean;
  fixAvailable: boolean;
  kevListed?: boolean;
  epssScore?: number | null;
}

export interface RiskEvaluation {
  score: number; // 0 - 100
  priorityTier: 'P0-IMMEDIATE' | 'P1-URGENT' | 'P2-ELEVATED' | 'P3-SCHEDULED';
  reasons: string[];
}

export function calculateRiskPriority(input: RiskInput): RiskEvaluation {
  const reasons: string[] = [];
  let score = Math.round(Math.min(10, Math.max(0, input.cvss)) * 5.5); // up to 55 pts from CVSS
  reasons.push(`Base CVSS ${input.cvss.toFixed(1)} (+${score} pts)`);

  const exploitPts =
    input.exploitability === 'High'
      ? 14
      : input.exploitability === 'Proof-of-Concept'
      ? 11
      : input.exploitability === 'Medium'
      ? 7
      : 2;
  score += exploitPts;
  reasons.push(`Exploitability=${input.exploitability} (+${exploitPts} pts)`);

  if (input.kevListed) {
    score += 15;
    reasons.push('CISA KEV Known Exploited Vulnerability (+15 pts)');
  }

  if (typeof input.epssScore === 'number' && input.epssScore >= 0.5) {
    const epssPts = input.epssScore >= 0.8 ? 10 : 6;
    score += epssPts;
    reasons.push(`FIRST EPSS probability ${(input.epssScore * 100).toFixed(1)}% (+${epssPts} pts)`);
  }

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
