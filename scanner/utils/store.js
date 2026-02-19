const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const RESULTS_FILE = path.join(DATA_DIR, 'scan-results.json');
const MAX_RESULTS = 100;

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function readResults() {
  ensureDataDir();
  if (!fs.existsSync(RESULTS_FILE)) {
    return [];
  }
  try {
    const data = fs.readFileSync(RESULTS_FILE, 'utf-8');
    return JSON.parse(data);
  } catch {
    return [];
  }
}

function writeResults(results) {
  ensureDataDir();
  fs.writeFileSync(RESULTS_FILE, JSON.stringify(results, null, 2));
}

function appendResult(scanResult) {
  const results = readResults();
  results.push(scanResult);
  // Keep only the most recent results
  const trimmed = results.slice(-MAX_RESULTS);
  writeResults(trimmed);
  return trimmed;
}

function getLatestResult() {
  const results = readResults();
  return results.length > 0 ? results[results.length - 1] : null;
}

function getSummary() {
  const results = readResults();
  const latest = results.length > 0 ? results[results.length - 1] : null;
  return {
    totalScans: results.length,
    latestScore: latest ? latest.score : 100,
    latestFindings: latest ? latest.findings.length : 0,
    latestTimestamp: latest ? latest.timestamp : null,
    results,
  };
}

module.exports = { readResults, writeResults, appendResult, getLatestResult, getSummary, RESULTS_FILE };
