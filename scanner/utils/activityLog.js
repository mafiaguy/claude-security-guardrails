/**
 * Activity log for the dashboard.
 * Stores hook events (blocked, allowed, warnings, findings) in a JSON file
 * that the dashboard can read and display.
 */

const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const LOG_FILE = path.join(DATA_DIR, 'activity-log.json');
const MAX_ENTRIES = 200;

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function readLog() {
  ensureDataDir();
  if (!fs.existsSync(LOG_FILE)) {
    return [];
  }
  try {
    return JSON.parse(fs.readFileSync(LOG_FILE, 'utf-8'));
  } catch {
    return [];
  }
}

function writeLog(entries) {
  ensureDataDir();
  fs.writeFileSync(LOG_FILE, JSON.stringify(entries, null, 2));
}

/**
 * Append an activity event to the log.
 * @param {object} event
 * @param {'blocked'|'allowed'|'warning'|'findings'|'error'} event.action
 * @param {'PreToolUse'|'PostToolUse'} event.hook
 * @param {string} event.tool - Tool name (Write, Edit, Bash)
 * @param {string} event.target - File path or command
 * @param {string} [event.reason] - Why it was blocked/warned
 * @param {string} [event.severity] - critical, high, medium, low
 * @param {object[]} [event.findings] - Array of findings details
 * @param {number} [event.score] - Security score if applicable
 */
function appendEvent(event) {
  const entries = readLog();
  entries.push({
    id: `evt_${Date.now()}_${Math.random().toString(36).substring(2, 6)}`,
    timestamp: new Date().toISOString(),
    ...event,
  });
  const trimmed = entries.slice(-MAX_ENTRIES);
  writeLog(trimmed);
  return trimmed;
}

function getRecentEvents(limit = 50) {
  const entries = readLog();
  return entries.slice(-limit).reverse();
}

function getStats() {
  const entries = readLog();
  const stats = {
    total: entries.length,
    blocked: 0,
    allowed: 0,
    warnings: 0,
    byTool: {},
    byHook: {},
    recentBlocked: [],
  };

  for (const e of entries) {
    if (e.action === 'blocked') stats.blocked++;
    else if (e.action === 'allowed') stats.allowed++;
    else if (e.action === 'warning') stats.warnings++;

    stats.byTool[e.tool] = (stats.byTool[e.tool] || 0) + 1;
    stats.byHook[e.hook] = (stats.byHook[e.hook] || 0) + 1;
  }

  stats.recentBlocked = entries
    .filter(e => e.action === 'blocked')
    .slice(-10)
    .reverse();

  return stats;
}

module.exports = { readLog, appendEvent, getRecentEvents, getStats, LOG_FILE };
