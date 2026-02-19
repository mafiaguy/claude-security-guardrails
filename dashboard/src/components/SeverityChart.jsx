const SEVERITY_CONFIG = {
  critical: { color: '#ef4444', label: 'Critical' },
  high: { color: '#f97316', label: 'High' },
  medium: { color: '#eab308', label: 'Medium' },
  low: { color: '#6b7280', label: 'Low' },
};

function SeverityChart({ counts }) {
  const maxCount = Math.max(...Object.values(counts), 1);

  return (
    <>
      <h3>Severity Breakdown</h3>
      {Object.entries(SEVERITY_CONFIG).map(([key, config]) => {
        const count = counts[key] || 0;
        const width = (count / maxCount) * 100;
        return (
          <div key={key} className="severity-bar-group">
            <div className="severity-bar-label">
              <span className="name">{config.label}</span>
              <span>{count}</span>
            </div>
            <div className="severity-bar-track">
              <div
                className="severity-bar-fill"
                style={{
                  width: count > 0 ? `${Math.max(width, 3)}%` : '0%',
                  backgroundColor: config.color,
                }}
              />
            </div>
          </div>
        );
      })}
    </>
  );
}

export default SeverityChart;
