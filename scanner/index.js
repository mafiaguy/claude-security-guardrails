const { getFiles, readFileContent, getRelativePath } = require('./utils/fileUtils');
const { computeScore, severityCounts } = require('./utils/severity');
const { appendResult } = require('./utils/store');
const { scanSecrets } = require('./scanners/secrets');
const { scanOwasp } = require('./scanners/owasp');
const { scanDependencies } = require('./scanners/dependencies');
const { scanCodePatterns } = require('./scanners/codePatterns');

async function scan(targetPath, options = {}) {
  const basePath = options.basePath || process.cwd();
  const files = await getFiles(targetPath);

  const allFindings = [];
  const filesScanned = [];

  for (const filePath of files) {
    const content = readFileContent(filePath);
    if (!content) continue;

    const relativePath = getRelativePath(filePath, basePath);
    filesScanned.push(relativePath);

    // Run all 4 scanners in parallel per file
    const [secrets, owasp, deps, patterns] = await Promise.all([
      Promise.resolve(scanSecrets(content, relativePath)),
      Promise.resolve(scanOwasp(content, relativePath)),
      Promise.resolve(scanDependencies(content, relativePath)),
      Promise.resolve(scanCodePatterns(content, relativePath)),
    ]);

    allFindings.push(...secrets, ...owasp, ...deps, ...patterns);
  }

  const score = computeScore(allFindings);
  const counts = severityCounts(allFindings);

  const scanResult = {
    id: generateId(),
    timestamp: new Date().toISOString(),
    targetPath: getRelativePath(targetPath, basePath),
    filesScanned: filesScanned.length,
    fileList: filesScanned,
    score,
    severityCounts: counts,
    totalFindings: allFindings.length,
    findings: allFindings,
    categoryCounts: getCategoryCounts(allFindings),
  };

  if (!options.dryRun) {
    appendResult(scanResult);
  }

  return scanResult;
}

function getCategoryCounts(findings) {
  const counts = {};
  for (const f of findings) {
    counts[f.category] = (counts[f.category] || 0) + 1;
  }
  return counts;
}

function generateId() {
  return `scan_${Date.now()}_${Math.random().toString(36).substring(2, 8)}`;
}

module.exports = { scan };
