const SEVERITY = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
};

const SEVERITY_WEIGHTS = {
  [SEVERITY.CRITICAL]: 25,
  [SEVERITY.HIGH]: 10,
  [SEVERITY.MEDIUM]: 3,
  [SEVERITY.LOW]: 1,
};

function computeScore(findings) {
  let penalty = 0;
  for (const finding of findings) {
    penalty += SEVERITY_WEIGHTS[finding.severity] || 0;
  }
  return Math.max(0, Math.min(100, 100 - penalty));
}

function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (counts[f.severity] !== undefined) {
      counts[f.severity]++;
    }
  }
  return counts;
}

module.exports = { SEVERITY, SEVERITY_WEIGHTS, computeScore, severityCounts };
