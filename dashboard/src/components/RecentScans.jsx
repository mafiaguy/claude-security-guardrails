function RecentScans({ scans }) {
  const formatTime = (ts) => {
    const d = new Date(ts);
    return d.toLocaleString();
  };

  const scoreColor = (score) => {
    if (score >= 80) return '#22c55e';
    if (score >= 50) return '#eab308';
    return '#ef4444';
  };

  return (
    <>
      <h3>Recent Scans</h3>
      {scans.length === 0 ? (
        <div className="no-findings">No scan history yet</div>
      ) : (
        <table className="scans-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Target</th>
              <th>Files</th>
              <th>Score</th>
              <th>Critical</th>
              <th>High</th>
              <th>Medium</th>
              <th>Low</th>
              <th>Total</th>
            </tr>
          </thead>
          <tbody>
            {scans.map((scan) => (
              <tr key={scan.id}>
                <td>{formatTime(scan.timestamp)}</td>
                <td><code>{scan.targetPath}</code></td>
                <td>{scan.filesScanned}</td>
                <td style={{ color: scoreColor(scan.score), fontWeight: 600 }}>
                  {scan.score}
                </td>
                <td style={{ color: scan.severityCounts.critical > 0 ? '#ef4444' : 'inherit' }}>
                  {scan.severityCounts.critical}
                </td>
                <td style={{ color: scan.severityCounts.high > 0 ? '#f97316' : 'inherit' }}>
                  {scan.severityCounts.high}
                </td>
                <td>{scan.severityCounts.medium}</td>
                <td>{scan.severityCounts.low}</td>
                <td>{scan.totalFindings}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}

export default RecentScans;
