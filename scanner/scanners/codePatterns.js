const { SEVERITY } = require('../utils/severity');

const CODE_PATTERNS = [
  // Dangerous functions
  {
    name: 'eval() Usage',
    pattern: /\beval\s*\(/g,
    severity: SEVERITY.CRITICAL,
    description: 'eval() can execute arbitrary code - avoid using it',
  },
  {
    name: 'Function() Constructor',
    pattern: /new\s+Function\s*\(/g,
    severity: SEVERITY.HIGH,
    description: 'Function constructor can execute arbitrary code like eval()',
  },
  // Weak cryptography
  {
    name: 'Weak Hash - MD5',
    pattern: /(?:createHash|MD5|md5)\s*\(\s*['"]md5['"]/gi,
    severity: SEVERITY.HIGH,
    description: 'MD5 is cryptographically weak - use SHA-256 or bcrypt for passwords',
  },
  {
    name: 'Weak Hash - SHA1',
    pattern: /createHash\s*\(\s*['"]sha1['"]/g,
    severity: SEVERITY.MEDIUM,
    description: 'SHA-1 is deprecated for security purposes - use SHA-256+',
  },
  {
    name: 'Math.random() for Security',
    pattern: /Math\.random\s*\(\)/g,
    severity: SEVERITY.MEDIUM,
    description: 'Math.random() is not cryptographically secure - use crypto.randomBytes()',
    contextCheck: (line) => {
      const securityWords = /token|secret|key|password|salt|nonce|csrf|session|auth/i;
      return securityWords.test(line);
    },
  },
  // TLS/SSL issues
  {
    name: 'Disabled TLS Verification',
    pattern: /rejectUnauthorized\s*:\s*false/g,
    severity: SEVERITY.HIGH,
    description: 'TLS certificate verification is disabled - vulnerable to MITM attacks',
  },
  {
    name: 'NODE_TLS_REJECT_UNAUTHORIZED',
    pattern: /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/g,
    severity: SEVERITY.HIGH,
    description: 'TLS verification globally disabled via environment variable',
  },
  // Hardcoded values
  {
    name: 'Hardcoded IP Address',
    pattern: /['"](?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)['"]/g,
    severity: SEVERITY.LOW,
    description: 'Hardcoded IP address - consider using configuration/environment variables',
    exclude: /(?:127\.0\.0\.1|0\.0\.0\.0|localhost)/,
  },
  // Debug/logging issues
  {
    name: 'Sensitive Data Logging',
    pattern: /console\.log\s*\([^)]*(?:password|secret|token|apiKey|api_key|credential|ssn|credit_card)/gi,
    severity: SEVERITY.MEDIUM,
    description: 'Logging potentially sensitive data to console',
  },
  // Unsafe regex
  {
    name: 'Potential ReDoS',
    pattern: /new\s+RegExp\s*\(\s*(?:req\.|params\.|query\.|body\.|input|user)/g,
    severity: SEVERITY.MEDIUM,
    description: 'RegExp constructed from user input - possible ReDoS',
  },
  // Unsafe deserialization
  {
    name: 'Unsafe Deserialize',
    pattern: /(?:unserialize|deserialize|pickle\.loads|yaml\.load\s*\((?!.*Loader))/g,
    severity: SEVERITY.HIGH,
    description: 'Unsafe deserialization can lead to remote code execution',
  },
  // Process environment
  {
    name: 'Hardcoded Port',
    pattern: /\.listen\s*\(\s*\d{4,5}\s*[,)]/g,
    severity: SEVERITY.LOW,
    description: 'Hardcoded port number - consider using PORT env variable',
  },
];

function scanCodePatterns(content, filePath) {
  const findings = [];
  const lines = content.split('\n');

  // Skip scanning non-source files for code patterns
  if (filePath.endsWith('package.json') || filePath.endsWith('.json') ||
      filePath.endsWith('.md') || filePath.endsWith('.txt')) {
    return findings;
  }

  for (const rule of CODE_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      // Skip comments
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('#')) {
        continue;
      }

      rule.pattern.lastIndex = 0;
      let match;
      while ((match = rule.pattern.exec(line)) !== null) {
        // Check context if rule has contextCheck
        if (rule.contextCheck && !rule.contextCheck(line)) {
          continue;
        }

        // Check exclusion pattern
        if (rule.exclude && rule.exclude.test(match[0])) {
          continue;
        }

        findings.push({
          category: 'Code Patterns',
          rule: rule.name,
          severity: rule.severity,
          file: filePath,
          line: i + 1,
          column: match.index + 1,
          description: rule.description,
          snippet: line.trim().substring(0, 120),
        });
      }
    }
  }

  return findings;
}

module.exports = { scanCodePatterns, CODE_PATTERNS };
