#!/usr/bin/env node
/**
 * Sets up Claude Code hooks for automatic security scanning.
 * Installs both PreToolUse (blocking) and PostToolUse (reporting) hooks
 * into .claude/settings.json using the correct Claude Code hook API.
 */

const fs = require('fs');
const path = require('path');

const PROJECT_ROOT = path.resolve(__dirname, '..');
const SETTINGS_DIR = path.join(PROJECT_ROOT, '.claude');
const SETTINGS_FILE = path.join(SETTINGS_DIR, 'settings.json');
const PRE_HOOK_SCRIPT = path.join(PROJECT_ROOT, 'hooks', 'pre-tool-use.js');
const POST_HOOK_SCRIPT = path.join(PROJECT_ROOT, 'hooks', 'post-tool-use.js');

function setupHooks() {
  // Ensure .claude directory exists
  if (!fs.existsSync(SETTINGS_DIR)) {
    fs.mkdirSync(SETTINGS_DIR, { recursive: true });
  }

  // Read existing settings or create new
  let settings = {};
  if (fs.existsSync(SETTINGS_FILE)) {
    try {
      settings = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf-8'));
    } catch {
      console.warn('Warning: Could not parse existing settings.json, creating new one');
      settings = {};
    }
  }

  settings.hooks = settings.hooks || {};
  let installed = 0;

  // --- PreToolUse hook (BLOCKS writes with critical/high issues) ---
  settings.hooks.PreToolUse = settings.hooks.PreToolUse || [];
  const existingPre = settings.hooks.PreToolUse.find(h =>
    h.hooks && h.hooks.some(hh => hh.command && hh.command.includes('pre-tool-use.js'))
  );

  if (existingPre) {
    // Update existing hook
    const hookEntry = existingPre.hooks.find(hh => hh.command && hh.command.includes('pre-tool-use.js'));
    hookEntry.command = `node ${PRE_HOOK_SCRIPT}`;
    existingPre.matcher = 'Write|Edit|Bash';
    console.log('~ PreToolUse hook updated');
  } else {
    settings.hooks.PreToolUse.push({
      matcher: 'Write|Edit|Bash',
      hooks: [{
        type: 'command',
        command: `node ${PRE_HOOK_SCRIPT}`,
      }],
    });
    installed++;
    console.log('+ PreToolUse hook installed (BLOCKS writes with critical/high issues)');
  }

  // --- PostToolUse hook (reports findings + saves to dashboard) ---
  settings.hooks.PostToolUse = settings.hooks.PostToolUse || [];
  const existingPost = settings.hooks.PostToolUse.find(h =>
    h.hooks && h.hooks.some(hh => hh.command && hh.command.includes('post-tool-use.js'))
  );

  if (existingPost) {
    const hookEntry = existingPost.hooks.find(hh => hh.command && hh.command.includes('post-tool-use.js'));
    hookEntry.command = `node ${POST_HOOK_SCRIPT}`;
    existingPost.matcher = 'Write|Edit';
    console.log('~ PostToolUse hook updated');
  } else {
    settings.hooks.PostToolUse.push({
      matcher: 'Write|Edit',
      hooks: [{
        type: 'command',
        command: `node ${POST_HOOK_SCRIPT}`,
      }],
    });
    installed++;
    console.log('+ PostToolUse hook installed (reports findings + saves to dashboard)');
  }

  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2));

  console.log(`\nHook scripts:`);
  console.log(`  Pre:  ${PRE_HOOK_SCRIPT}`);
  console.log(`  Post: ${POST_HOOK_SCRIPT}`);
  console.log(`  Config: ${SETTINGS_FILE}`);

  console.log('\n── How it works ──────────────────────────────────');
  console.log('  PreToolUse  → Runs BEFORE Write/Edit/Bash');
  console.log('                🚫 BLOCKS dangerous commands (rm -rf, force push, etc.)');
  console.log('                🚫 BLOCKS code with secrets/vulnerabilities');
  console.log('                Outputs deny decision via stdout JSON');
  console.log('  PostToolUse → Runs AFTER Write/Edit');
  console.log('                📊 Scans file, saves results to dashboard');
  console.log('                Logs to ~/.claude/hooks-logs/');
  console.log('                All activity visible in dashboard');
  console.log('──────────────────────────────────────────────────');
}

setupHooks();
