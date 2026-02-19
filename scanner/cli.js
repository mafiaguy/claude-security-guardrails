#!/usr/bin/env node

const path = require('path');
const { scan } = require('./index');
const { getLatestResult, getSummary } = require('./utils/store');

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === '--help') {
    console.log(`
Security Scanner CLI

Usage:
  node scanner/cli.js scan <path>    Scan a file or directory
  node scanner/cli.js results        Show latest scan results
  node scanner/cli.js summary        Show scan summary

Options:
  --json     Output as JSON
  --dry-run  Scan without saving results
`);
    process.exit(0);
  }

  if (command === 'scan') {
    const targetPath = args[1] || '.';
    const resolvedPath = path.resolve(targetPath);
    const isJson = args.includes('--json');
    const isDryRun = args.includes('--dry-run');

    console.error(`Scanning: ${resolvedPath}`);

    try {
      const result = await scan(resolvedPath, { dryRun: isDryRun });

      if (isJson) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        printReport(result);
      }

      // Exit code 1 if critical issues found
      if (result.severityCounts.critical > 0) {
        process.exit(1);
      }
    } catch (err) {
      console.error(`Error: ${err.message}`);
      process.exit(2);
    }
  } else if (command === 'results') {
    const result = getLatestResult();
    if (!result) {
      console.log('No scan results found. Run a scan first.');
      process.exit(0);
    }
    console.log(JSON.stringify(result, null, 2));
  } else if (command === 'summary') {
    const summary = getSummary();
    console.log(JSON.stringify(summary, null, 2));
  } else {
    console.error(`Unknown command: ${command}`);
    process.exit(1);
  }
}

function printReport(result) {
  const { score, severityCounts: counts, totalFindings, filesScanned, findings } = result;

  console.log('\n' + '='.repeat(60));
  console.log('  SECURITY SCAN REPORT');
  console.log('='.repeat(60));
  console.log(`  Score:    ${scoreColor(score)}${score}/100\x1b[0m`);
  console.log(`  Files:    ${filesScanned} scanned`);
  console.log(`  Findings: ${totalFindings} total`);
  console.log('');
  console.log(`  \x1b[31mCritical: ${counts.critical}\x1b[0m`);
  console.log(`  \x1b[33mHigh:     ${counts.high}\x1b[0m`);
  console.log(`  \x1b[36mMedium:   ${counts.medium}\x1b[0m`);
  console.log(`  \x1b[37mLow:      ${counts.low}\x1b[0m`);
  console.log('='.repeat(60));

  if (findings.length > 0) {
    console.log('\nFindings:\n');
    for (const f of findings) {
      const sevColor = f.severity === 'critical' ? '\x1b[31m' :
                       f.severity === 'high' ? '\x1b[33m' :
                       f.severity === 'medium' ? '\x1b[36m' : '\x1b[37m';
      console.log(`  ${sevColor}[${f.severity.toUpperCase()}]\x1b[0m ${f.rule}`);
      console.log(`    File: ${f.file}:${f.line}`);
      console.log(`    ${f.description}`);
      console.log(`    > ${f.snippet}`);
      console.log('');
    }
  }
}

function scoreColor(score) {
  if (score >= 80) return '\x1b[32m'; // green
  if (score >= 50) return '\x1b[33m'; // yellow
  return '\x1b[31m'; // red
}

main();
