const fs = require('fs');
const path = require('path');
const { glob } = require('glob');

const CODE_EXTENSIONS = [
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.py', '.rb', '.go', '.java', '.php',
  '.html', '.htm', '.vue', '.svelte',
  '.json', '.yml', '.yaml', '.toml', '.env',
  '.sh', '.bash', '.zsh',
];

const IGNORE_DIRS = [
  'node_modules', '.git', 'dist', 'build', '.next',
  'coverage', '.nyc_output', 'vendor', '__pycache__',
];

async function getFiles(targetPath) {
  const stat = fs.statSync(targetPath);

  if (stat.isFile()) {
    return [path.resolve(targetPath)];
  }

  const ignorePattern = IGNORE_DIRS.map(d => `**/${d}/**`);
  const extPattern = CODE_EXTENSIONS.map(e => `**/*${e}`);

  const files = await glob(extPattern, {
    cwd: targetPath,
    absolute: true,
    ignore: ignorePattern,
    nodir: true,
  });

  return files;
}

function readFileContent(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

function getRelativePath(filePath, basePath) {
  return path.relative(basePath || process.cwd(), filePath);
}

module.exports = { getFiles, readFileContent, getRelativePath, CODE_EXTENSIONS, IGNORE_DIRS };
