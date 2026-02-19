const express = require('express');
const cors = require('cors');
const { readResults, getSummary } = require('./utils/store');
const { getRecentEvents, getStats } = require('./utils/activityLog');

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// Get all scan results
app.get('/api/results', (req, res) => {
  const results = readResults();
  res.json(results);
});

// Get latest scan result
app.get('/api/results/latest', (req, res) => {
  const results = readResults();
  if (results.length === 0) {
    return res.json(null);
  }
  res.json(results[results.length - 1]);
});

// Get aggregated summary
app.get('/api/summary', (req, res) => {
  const summary = getSummary();
  res.json(summary);
});

// Activity log - recent hook events
app.get('/api/activity', (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  const events = getRecentEvents(limit);
  res.json(events);
});

// Activity stats - blocked/allowed/warning counts
app.get('/api/activity/stats', (req, res) => {
  const stats = getStats();
  res.json(stats);
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Serve built dashboard in production (Docker)
const path = require('path');
const dashboardDist = path.join(__dirname, '..', 'dashboard', 'dist');
const fs = require('fs');
if (fs.existsSync(dashboardDist)) {
  app.use(express.static(dashboardDist));
  app.get('*', (req, res) => {
    if (!req.path.startsWith('/api')) {
      res.sendFile(path.join(dashboardDist, 'index.html'));
    }
  });
}

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Security scanner API running on http://localhost:${PORT}`);
});
