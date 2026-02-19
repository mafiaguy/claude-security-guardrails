const { SEVERITY } = require('../utils/severity');

const SECRET_PATTERNS = [
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/g,
    severity: SEVERITY.CRITICAL,
    description: 'AWS Access Key ID detected',
  },
  {
    name: 'AWS Secret Key',
    pattern: /aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}/gi,
    severity: SEVERITY.CRITICAL,
    description: 'AWS Secret Access Key detected',
  },
  {
    name: 'GitHub Token',
    pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/g,
    severity: SEVERITY.CRITICAL,
    description: 'GitHub personal access token detected',
  },
  {
    name: 'Generic API Key',
    pattern: /(api[_-]?key|apikey)\s*[:=]\s*['"][A-Za-z0-9]{16,}['"]/gi,
    severity: SEVERITY.HIGH,
    description: 'Possible API key in code',
  },
  {
    name: 'Private Key',
    pattern: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/g,
    severity: SEVERITY.CRITICAL,
    description: 'Private key embedded in source code',
  },
  {
    name: 'JWT Token',
    pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+/g,
    severity: SEVERITY.HIGH,
    description: 'Hardcoded JWT token detected',
  },
  {
    name: 'Connection String',
    pattern: /(mongodb|postgres|mysql|redis):\/\/[^\s'"]+/gi,
    severity: SEVERITY.CRITICAL,
    description: 'Database connection string with possible credentials',
  },
  {
    name: 'Hardcoded Password',
    pattern: /(password|passwd|pwd)\s*[:=]\s*['"][^'"]{8,}['"]/gi,
    severity: SEVERITY.HIGH,
    description: 'Hardcoded password detected',
  },
  {
    name: 'Slack Token',
    pattern: /xox[baprs]-[0-9a-zA-Z-]{10,}/g,
    severity: SEVERITY.CRITICAL,
    description: 'Slack token detected',
  },
  {
    name: 'Generic Secret',
    pattern: /(secret|token|auth)\s*[:=]\s*['"][A-Za-z0-9+/=]{20,}['"]/gi,
    severity: SEVERITY.MEDIUM,
    description: 'Possible secret or token in code',
  },
];

function scanSecrets(content, filePath) {
  const findings = [];
  const lines = content.split('\n');

  for (const rule of SECRET_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      // Reset regex lastIndex for global patterns
      rule.pattern.lastIndex = 0;
      let match;
      while ((match = rule.pattern.exec(line)) !== null) {
        findings.push({
          category: 'Secrets',
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

module.exports = { scanSecrets, SECRET_PATTERNS };
