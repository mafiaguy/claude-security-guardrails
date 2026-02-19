function SecurityScore({ score }) {
  const radius = 72;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;
  const offset = circumference - progress;

  const getColor = (s) => {
    if (s >= 80) return '#22c55e';
    if (s >= 50) return '#eab308';
    return '#ef4444';
  };

  const color = getColor(score);

  return (
    <>
      <h3>Security Score</h3>
      <div className="score-gauge">
        <svg width="180" height="180" viewBox="0 0 180 180">
          <circle className="bg-ring" cx="90" cy="90" r={radius} />
          <circle
            className="score-ring"
            cx="90"
            cy="90"
            r={radius}
            stroke={color}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
          />
        </svg>
        <div className="score-value">
          <div className="number" style={{ color }}>{score}</div>
          <div className="label">out of 100</div>
        </div>
      </div>
    </>
  );
}

export default SecurityScore;
