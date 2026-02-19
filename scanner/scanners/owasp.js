const { SEVERITY } = require('../utils/severity');

const OWASP_PATTERNS = [
  // SQL Injection
  {
    name: 'SQL Injection - String Concatenation',
    pattern: /(?:query|execute|raw)\s*\(\s*['"`].*?\s*\+\s*/g,
    severity: SEVERITY.CRITICAL,
    description: 'Possible SQL injection via string concatenation in query',
  },
  {
    name: 'SQL Injection - Template Literal',
    pattern: /(?:query|execute|raw)\s*\(\s*`[^`]*\$\{/g,
    severity: SEVERITY.CRITICAL,
    description: 'Possible SQL injection via template literal interpolation',
  },
  // XSS
  {
    name: 'XSS - innerHTML',
    pattern: /\.innerHTML\s*=/g,
    severity: SEVERITY.HIGH,
    description: 'Direct innerHTML assignment can lead to XSS',
  },
  {
    name: 'XSS - dangerouslySetInnerHTML',
    pattern: /dangerouslySetInnerHTML/g,
    severity: SEVERITY.HIGH,
    description: 'dangerouslySetInnerHTML can lead to XSS if input is unsanitized',
  },
  {
    name: 'XSS - document.write',
    pattern: /document\.write\s*\(/g,
    severity: SEVERITY.HIGH,
    description: 'document.write can lead to XSS',
  },
  {
    name: 'XSS - v-html',
    pattern: /v-html\s*=/g,
    severity: SEVERITY.HIGH,
    description: 'Vue v-html directive can lead to XSS',
  },
  // Command Injection
  {
    name: 'Command Injection - exec',
    pattern: /(?:child_process.*?|require\s*\(\s*['"]child_process['"]\s*\)).*?exec\s*\(/gs,
    severity: SEVERITY.CRITICAL,
    description: 'child_process.exec with potential unsanitized input',
  },
  {
    name: 'Command Injection - exec direct',
    pattern: /\bexec\s*\(\s*(?:`[^`]*\$\{|['"].*?\+)/g,
    severity: SEVERITY.CRITICAL,
    description: 'Command execution with string interpolation/concatenation',
  },
  // Path Traversal
  {
    name: 'Path Traversal',
    pattern: /(?:readFile|readFileSync|createReadStream|access|stat)\s*\([^)]*(?:req\.|params\.|query\.|body\.)/g,
    severity: SEVERITY.HIGH,
    description: 'File operation with user-controlled path - possible path traversal',
  },
  {
    name: 'Path Traversal - Join',
    pattern: /path\.join\s*\([^)]*(?:req\.|params\.|query\.|body\.)/g,
    severity: SEVERITY.MEDIUM,
    description: 'path.join with user input - verify path traversal protection',
  },
  // SSRF
  {
    name: 'SSRF - User-controlled URL',
    pattern: /(?:fetch|axios\.get|axios\.post|http\.get|request)\s*\(\s*(?:req\.|params\.|query\.|body\.|url)/g,
    severity: SEVERITY.HIGH,
    description: 'HTTP request with user-controlled URL - possible SSRF',
  },
  // Security Misconfiguration
  {
    name: 'CORS Wildcard',
    pattern: /cors\s*\(\s*\{[^}]*origin\s*:\s*['"]?\*/g,
    severity: SEVERITY.MEDIUM,
    description: 'CORS configured with wildcard origin',
  },
  {
    name: 'CORS Allow All',
    pattern: /Access-Control-Allow-Origin['"]\s*,\s*['"]\*/g,
    severity: SEVERITY.MEDIUM,
    description: 'CORS header set to allow all origins',
  },
  // Insecure Deserialization
  {
    name: 'Unsafe JSON Parse',
    pattern: /JSON\.parse\s*\(\s*(?:req\.|body\.|params\.|query\.|input)/g,
    severity: SEVERITY.MEDIUM,
    description: 'JSON.parse on user input without try/catch protection',
  },
];

function scanOwasp(content, filePath) {
  const findings = [];
  const lines = content.split('\n');

  for (const rule of OWASP_PATTERNS) {
    // For multiline patterns, scan the full content
    if (rule.pattern.flags.includes('s')) {
      rule.pattern.lastIndex = 0;
      let match;
      while ((match = rule.pattern.exec(content)) !== null) {
        const lineNum = content.substring(0, match.index).split('\n').length;
        findings.push({
          category: 'OWASP',
          rule: rule.name,
          severity: rule.severity,
          file: filePath,
          line: lineNum,
          column: 1,
          description: rule.description,
          snippet: match[0].trim().substring(0, 120),
        });
      }
      continue;
    }

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      rule.pattern.lastIndex = 0;
      let match;
      while ((match = rule.pattern.exec(line)) !== null) {
        findings.push({
          category: 'OWASP',
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

module.exports = { scanOwasp, OWASP_PATTERNS };
