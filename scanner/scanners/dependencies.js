const { SEVERITY } = require('../utils/severity');

// Bundled advisory list of known vulnerable packages and versions
const KNOWN_VULNERABLE = {
  'lodash': { below: '4.17.21', severity: SEVERITY.HIGH, advisory: 'Prototype pollution' },
  'minimist': { below: '1.2.6', severity: SEVERITY.HIGH, advisory: 'Prototype pollution' },
  'node-fetch': { below: '2.6.7', severity: SEVERITY.MEDIUM, advisory: 'URL redirect vulnerability' },
  'express': { below: '4.17.3', severity: SEVERITY.MEDIUM, advisory: 'Open redirect vulnerability' },
  'axios': { below: '0.21.2', severity: SEVERITY.HIGH, advisory: 'SSRF vulnerability' },
  'tar': { below: '6.1.9', severity: SEVERITY.HIGH, advisory: 'Arbitrary file creation/overwrite' },
  'glob-parent': { below: '5.1.2', severity: SEVERITY.HIGH, advisory: 'Regular expression DoS' },
  'trim-newlines': { below: '3.0.1', severity: SEVERITY.MEDIUM, advisory: 'Regular expression DoS' },
  'json5': { below: '2.2.2', severity: SEVERITY.HIGH, advisory: 'Prototype pollution' },
  'semver': { below: '7.5.2', severity: SEVERITY.MEDIUM, advisory: 'Regular expression DoS' },
  'tough-cookie': { below: '4.1.3', severity: SEVERITY.MEDIUM, advisory: 'Prototype pollution' },
  'word-wrap': { below: '1.2.4', severity: SEVERITY.MEDIUM, advisory: 'Regular expression DoS' },
  'jsonwebtoken': { below: '9.0.0', severity: SEVERITY.CRITICAL, advisory: 'JWT verification bypass' },
  'qs': { below: '6.10.3', severity: SEVERITY.HIGH, advisory: 'Prototype pollution' },
  'shell-quote': { below: '1.7.3', severity: SEVERITY.CRITICAL, advisory: 'Command injection' },
  'moment': { below: '2.29.4', severity: SEVERITY.MEDIUM, advisory: 'Path traversal' },
};

function parseVersion(version) {
  const cleaned = version.replace(/^[^0-9]*/, '');
  const parts = cleaned.split('.').map(Number);
  return { major: parts[0] || 0, minor: parts[1] || 0, patch: parts[2] || 0 };
}

function isBelow(version, threshold) {
  const v = parseVersion(version);
  const t = parseVersion(threshold);
  if (v.major !== t.major) return v.major < t.major;
  if (v.minor !== t.minor) return v.minor < t.minor;
  return v.patch < t.patch;
}

function scanDependencies(content, filePath) {
  const findings = [];

  // Only scan package.json files
  if (!filePath.endsWith('package.json')) {
    return findings;
  }

  let pkg;
  try {
    pkg = JSON.parse(content);
  } catch {
    return findings;
  }

  const allDeps = {
    ...pkg.dependencies,
    ...pkg.devDependencies,
  };

  for (const [name, versionRange] of Object.entries(allDeps || {})) {
    // Check for wildcard versions
    if (versionRange === '*' || versionRange === 'latest') {
      findings.push({
        category: 'Dependencies',
        rule: 'Wildcard Version',
        severity: SEVERITY.MEDIUM,
        file: filePath,
        line: findDepLine(content, name),
        column: 1,
        description: `Package "${name}" uses wildcard version "${versionRange}" - pin to a specific version`,
        snippet: `"${name}": "${versionRange}"`,
      });
    }

    // Check for overly broad ranges
    if (versionRange.startsWith('>=') || versionRange.includes(' || ')) {
      findings.push({
        category: 'Dependencies',
        rule: 'Broad Version Range',
        severity: SEVERITY.LOW,
        file: filePath,
        line: findDepLine(content, name),
        column: 1,
        description: `Package "${name}" uses broad version range "${versionRange}"`,
        snippet: `"${name}": "${versionRange}"`,
      });
    }

    // Check known vulnerabilities
    if (KNOWN_VULNERABLE[name]) {
      const advisory = KNOWN_VULNERABLE[name];
      const version = versionRange.replace(/^[\^~>=<]*/, '');
      if (isBelow(version, advisory.below)) {
        findings.push({
          category: 'Dependencies',
          rule: 'Known Vulnerability',
          severity: advisory.severity,
          file: filePath,
          line: findDepLine(content, name),
          column: 1,
          description: `${name}@${versionRange} - ${advisory.advisory} (upgrade to >=${advisory.below})`,
          snippet: `"${name}": "${versionRange}"`,
        });
      }
    }
  }

  return findings;
}

function findDepLine(content, depName) {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].includes(`"${depName}"`)) {
      return i + 1;
    }
  }
  return 1;
}

module.exports = { scanDependencies, KNOWN_VULNERABLE };
