function Header({ lastScan, totalScans, totalFindings, blockedCount }) {
  const formatTime = (ts) => {
    if (!ts) return 'Never';
    const d = new Date(ts);
    return d.toLocaleString();
  };

  return (
    <header className="header">
      <div className="header-left">
        <h1>Security Guardrails</h1>
        <p>
          {lastScan
            ? `Last scan: ${formatTime(lastScan)}`
            : 'AI-powered security scanning for Claude Code'}
        </p>
      </div>
      {lastScan && (
        <div className="header-stats">
          <div className="header-stat">
            <div className="value">{totalScans}</div>
            <div className="label">Total Scans</div>
          </div>
          <div className="header-stat">
            <div className="value">{totalFindings}</div>
            <div className="label">Issues Found</div>
          </div>
          <div className="header-stat">
            <div className="value" style={{ color: blockedCount > 0 ? '#ef4444' : '#22c55e' }}>
              {blockedCount}
            </div>
            <div className="label">Blocked</div>
          </div>
        </div>
      )}
    </header>
  );
}

export default Header;
