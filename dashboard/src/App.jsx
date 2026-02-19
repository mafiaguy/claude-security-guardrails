import { useState, useEffect } from 'react';
import Header from './components/Header';
import SecurityScore from './components/SecurityScore';
import SeverityChart from './components/SeverityChart';
import CategoryBreakdown from './components/CategoryBreakdown';
import RecentScans from './components/RecentScans';
import FindingsTable from './components/FindingsTable';
import ActivityLog from './components/ActivityLog';

function App() {
  const [results, setResults] = useState([]);
  const [activity, setActivity] = useState([]);
  const [activityStats, setActivityStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchData = async () => {
    try {
      const [resultsRes, activityRes, statsRes] = await Promise.all([
        fetch('/api/results'),
        fetch('/api/activity'),
        fetch('/api/activity/stats'),
      ]);

      if (!resultsRes.ok) throw new Error('Failed to fetch results');

      const [resultsData, activityData, statsData] = await Promise.all([
        resultsRes.json(),
        activityRes.ok ? activityRes.json() : [],
        statsRes.ok ? statsRes.json() : null,
      ]);

      setResults(resultsData);
      setActivity(activityData);
      setActivityStats(statsData);
      setError(null);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);
    return () => clearInterval(interval);
  }, []);

  const latest = results.length > 0 ? results[results.length - 1] : null;

  if (loading) {
    return (
      <div className="app">
        <Header />
        <div className="loading">Loading scan results...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="app">
        <Header />
        <div className="error">
          <h3>Connection Error</h3>
          <p>{error}</p>
          <p>Make sure the scanner API is running: <code>npm run server</code></p>
        </div>
      </div>
    );
  }

  if (!latest) {
    return (
      <div className="app">
        <Header />
        <div className="empty-state">
          <h3>No Scan Results Yet</h3>
          <p>Run a scan to see results: <code>npm run scan -- ./path/to/code</code></p>
        </div>
        {activity.length > 0 && (
          <div className="dashboard-row">
            <div className="card activity-card">
              <ActivityLog events={activity} stats={activityStats} />
            </div>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="app">
      <Header
        lastScan={latest.timestamp}
        totalScans={results.length}
        totalFindings={latest.totalFindings}
        blockedCount={activityStats?.blocked || 0}
      />
      <div className="dashboard-grid">
        <div className="card score-card">
          <SecurityScore score={latest.score} />
        </div>
        <div className="card severity-card">
          <SeverityChart counts={latest.severityCounts} />
        </div>
        <div className="card category-card">
          <CategoryBreakdown counts={latest.categoryCounts} />
        </div>
      </div>
      <div className="dashboard-row">
        <div className="card activity-card">
          <ActivityLog events={activity} stats={activityStats} />
        </div>
      </div>
      <div className="dashboard-row">
        <div className="card scans-card">
          <RecentScans scans={results.slice(-20).reverse()} />
        </div>
      </div>
      <div className="dashboard-row">
        <div className="card findings-card">
          <FindingsTable findings={latest.findings} />
        </div>
      </div>
    </div>
  );
}

export default App;
