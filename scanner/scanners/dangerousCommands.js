/**
 * Dangerous Bash command detection
 * Blocks destructive, irreversible, or security-risky shell commands.
 *
 * Safety levels:
 *   critical - Catastrophic, unrecoverable (rm -rf /, fork bombs, dd to disk)
 *   high     - Significant risk (force push main, git reset --hard, secrets exposure)
 *   strict   - Cautionary (any force push, sudo rm, docker prune)
 */

const LEVELS = { critical: 1, high: 2, strict: 3 };

const DANGEROUS_PATTERNS = [
  // ── CRITICAL: Catastrophic, unrecoverable ──
  { level: 'critical', id: 'rm-root',           regex: /\brm\s+(-.+\s+)*\/(\*|\s|$|[;&|])/,                                  reason: 'rm targeting root filesystem' },
  { level: 'critical', id: 'rm-system',         regex: /\brm\s+(-.+\s+)*\/(etc|usr|var|bin|sbin|lib|boot|dev|proc|sys)(\/|\s|$)/, reason: 'rm targeting system directory' },
  { level: 'critical', id: 'rm-home',           regex: /\brm\s+(-.+\s+)*["']?~\/?["']?(\s|$|[;&|])/,                         reason: 'rm targeting home directory' },
  { level: 'critical', id: 'rm-home-var',       regex: /\brm\s+(-.+\s+)*["']?\$HOME["']?(\s|$|[;&|])/,                       reason: 'rm targeting $HOME' },
  { level: 'critical', id: 'rm-rf-cwd',         regex: /\brm\s+-rf\s+(\.\/?|\*|\.\/\*)(\s|$|[;&|])/,                         reason: 'rm -rf deleting current directory contents' },
  { level: 'critical', id: 'rm-rf-wildcard',    regex: /\brm\s+-rf\s+\/\*/,                                                   reason: 'rm -rf with wildcard on root' },
  { level: 'critical', id: 'dd-disk',           regex: /\bdd\b.+of=\/dev\/(sd[a-z]|nvme|hd[a-z]|vd[a-z]|xvd[a-z])/,         reason: 'dd writing to disk device — will destroy data' },
  { level: 'critical', id: 'mkfs',              regex: /\bmkfs(\.\w+)?\s+\/dev\/(sd[a-z]|nvme|hd[a-z]|vd[a-z])/,             reason: 'mkfs formatting disk — will destroy all data' },
  { level: 'critical', id: 'fork-bomb',         regex: /:\(\)\s*\{.*:\s*\|\s*:.*&/,                                           reason: 'Fork bomb detected — will crash system' },
  { level: 'critical', id: 'dev-null-redirect', regex: />\s*\/dev\/sd[a-z]/,                                                  reason: 'Redirecting output to disk device' },

  // ── HIGH: Significant risk, data loss, security ──
  { level: 'high', id: 'rm-rf-generic',    regex: /\brm\s+-r(f)?\s/,                                                         reason: 'Recursive rm — verify target carefully' },
  { level: 'high', id: 'curl-pipe-sh',     regex: /\b(curl|wget)\b.+\|\s*(ba)?sh\b/,                                         reason: 'Piping URL to shell — remote code execution risk' },
  { level: 'high', id: 'git-force-main',   regex: /\bgit\s+push\b(?!.+--force-with-lease).+(--force|-f)\b.+\b(main|master)\b/, reason: 'Force push to main/master — will rewrite shared history' },
  { level: 'high', id: 'git-reset-hard',   regex: /\bgit\s+reset\s+--hard/,                                                  reason: 'git reset --hard — loses all uncommitted work' },
  { level: 'high', id: 'git-clean-f',      regex: /\bgit\s+clean\s+(-\w*f|-f)/,                                              reason: 'git clean -f — permanently deletes untracked files' },
  { level: 'high', id: 'git-branch-D',     regex: /\bgit\s+branch\s+-D\b/,                                                   reason: 'git branch -D — force deletes branch regardless of merge status' },
  { level: 'high', id: 'chmod-777',        regex: /\bchmod\b.+\b777\b/,                                                      reason: 'chmod 777 — world-writable is a security risk' },
  { level: 'high', id: 'cat-env',          regex: /\b(cat|less|head|tail|more)\s+[^|;]*\.env\b/i,                             reason: 'Reading .env file — may expose secrets' },
  { level: 'high', id: 'cat-secrets',      regex: /\b(cat|less|head|tail|more)\b.+(credentials|secrets?|\.pem|\.key|id_rsa|id_ed25519)/i, reason: 'Reading secrets/key file' },
  { level: 'high', id: 'env-dump',         regex: /\bprintenv\b|(?:^|[;&|]\s*)env\s*(?:$|[;&|])/,                             reason: 'Environment dump may expose secrets' },
  { level: 'high', id: 'echo-secret',      regex: /\becho\b.+\$\w*(SECRET|KEY|TOKEN|PASSWORD|API_|PRIVATE)/i,                 reason: 'Echoing secret environment variable' },
  { level: 'high', id: 'docker-vol-rm',    regex: /\bdocker\s+volume\s+(rm|prune)/,                                           reason: 'Docker volume deletion — loses persistent data' },
  { level: 'high', id: 'rm-ssh',           regex: /\brm\b.+\.ssh\/(id_|authorized_keys|known_hosts)/,                         reason: 'Deleting SSH keys' },
  { level: 'high', id: 'drop-database',    regex: /DROP\s+(DATABASE|TABLE|SCHEMA)\b/i,                                        reason: 'SQL DROP — will permanently delete data' },
  { level: 'high', id: 'truncate-table',   regex: /TRUNCATE\s+TABLE\b/i,                                                     reason: 'SQL TRUNCATE — will delete all rows' },
  { level: 'high', id: 'kill-all',         regex: /\bkillall\b|\bkill\s+-9\s+-1\b|\bpkill\s+-9\b/,                            reason: 'Mass process kill' },
  { level: 'high', id: 'shutdown',         regex: /\b(shutdown|reboot|halt|poweroff)\b/,                                      reason: 'System shutdown/reboot command' },
  { level: 'high', id: 'iptables-flush',   regex: /\biptables\s+-F\b/,                                                       reason: 'Flushing firewall rules' },
  { level: 'high', id: 'passwd-change',    regex: /\bpasswd\b/,                                                               reason: 'Password change command' },
  { level: 'high', id: 'curl-upload-env',  regex: /\bcurl\b[^;|&]*(-d\s*@|-F\s*[^=]+=@|--data[^=]*=@)[^;|&]*(\.env|credentials|secrets|id_rsa|\.pem|\.key)/i, reason: 'Uploading secrets via curl' },
  { level: 'high', id: 'scp-secrets',      regex: /\bscp\b[^;|&]*(\.env|credentials|secrets|id_rsa|\.pem|\.key)[^;|&]+:/i,    reason: 'Copying secrets via scp' },

  // ── STRICT: Cautionary, context-dependent ──
  { level: 'strict', id: 'git-force-any',    regex: /\bgit\s+push\b(?!.+--force-with-lease).+(--force|-f)\b/,                 reason: 'Force push — use --force-with-lease instead' },
  { level: 'strict', id: 'git-checkout-dot', regex: /\bgit\s+checkout\s+\./,                                                  reason: 'git checkout . — discards all local changes' },
  { level: 'strict', id: 'sudo-rm',          regex: /\bsudo\s+rm\b/,                                                          reason: 'sudo rm — elevated privilege deletion' },
  { level: 'strict', id: 'docker-prune',     regex: /\bdocker\s+(system|image)\s+prune/,                                      reason: 'Docker prune — removes images/containers' },
  { level: 'strict', id: 'crontab-r',        regex: /\bcrontab\s+-r/,                                                         reason: 'Removes all cron jobs' },
  { level: 'strict', id: 'npm-cache-clean',  regex: /\bnpm\s+cache\s+clean\s+--force/,                                        reason: 'Force clearing npm cache' },
  { level: 'strict', id: 'pip-uninstall',    regex: /\bpip\s+uninstall\b.+-y\b/,                                              reason: 'Force uninstalling pip packages' },
];

function checkCommand(command, safetyLevel = 'high') {
  if (!command) return { blocked: false, pattern: null };

  const threshold = LEVELS[safetyLevel] || 2;

  for (const p of DANGEROUS_PATTERNS) {
    if (LEVELS[p.level] <= threshold && p.regex.test(command)) {
      return { blocked: true, pattern: p };
    }
  }

  return { blocked: false, pattern: null };
}

module.exports = { checkCommand, DANGEROUS_PATTERNS, LEVELS };
