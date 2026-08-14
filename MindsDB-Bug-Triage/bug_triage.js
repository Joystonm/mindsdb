#!/usr/bin/env node
/**
 * MindsDB Bug Triage
 *
 * Investigates MindsDB bugs using local diagnostics, log analysis, source-code
 * inspection and GitHub research, then creates a safe fix PR without touching
 * the original MindsDB checkout.
 *
 * Usage:
 *   node MindsDB-Bug-Triage/bug_triage.js [options]
 *
 * Options:
 *   --description <text>   Short description of the problem (required)
 *   --error <text>         Error message or stack trace fragment
 *   --component <name>     MindsDB component (e.g. api/http, integrations/handlers/mysql)
 *   --worktree-base <dir>  Parent directory for the temporary fix worktree (default: /tmp)
 *   --dry-run              Analysis only; skip issue/PR creation
 *   --help                 Show this message
 *
 * Safety guarantee:
 *   Every filesystem write is checked by isAllowedWritePath() before execution.
 *   Any path outside MindsDB-Bug-Triage/ or the current fix worktree is rejected.
 */

'use strict';

const fs   = require('fs');
const path = require('path');
const { execSync, spawnSync } = require('child_process');
const os   = require('os');

// ---------------------------------------------------------------------------
// 1. Paths and safety guard
// ---------------------------------------------------------------------------

/**
 * Locate the MindsDB repository root by walking up from this file's location.
 * Falls back to `git rev-parse --show-toplevel`.
 */
function getRepoRoot() {
  // This file lives at <repoRoot>/MindsDB-Bug-Triage/bug_triage.js
  const dirOfThisFile = path.dirname(path.resolve(__filename));
  const candidate = path.dirname(dirOfThisFile);
  if (fs.existsSync(path.join(candidate, 'mindsdb', '__about__.py'))) {
    return candidate;
  }
  // Fallback: ask git
  try {
    return run('git rev-parse --show-toplevel', { cwd: __dirname }).trim();
  } catch {
    throw new Error('Cannot determine MindsDB repository root.');
  }
}

const REPO_ROOT            = getRepoRoot();
const BUG_TRIAGE_DIR       = path.join(REPO_ROOT, 'MindsDB-Bug-Triage');
let   CURRENT_WORKTREE_DIR = null; // Set once the worktree is created

/**
 * Returns true only when `targetPath` is inside:
 *   - MindsDB-Bug-Triage/
 *   - the temporary fix worktree (if one exists for this session)
 *
 * Any other path is forbidden for writes.
 */
function isAllowedWritePath(targetPath) {
  const abs = path.resolve(targetPath);
  if (abs.startsWith(BUG_TRIAGE_DIR + path.sep) || abs === BUG_TRIAGE_DIR) {
    return true;
  }
  if (CURRENT_WORKTREE_DIR) {
    const wt = path.resolve(CURRENT_WORKTREE_DIR);
    if (abs.startsWith(wt + path.sep) || abs === wt) {
      return true;
    }
  }
  return false;
}

/**
 * Writes `content` to `filePath` after safety-checking the path.
 * Throws a descriptive error if the path is forbidden.
 */
function safeWriteFile(filePath, content) {
  if (!isAllowedWritePath(filePath)) {
    throw new Error(
      `\nERROR: Refusing to modify MindsDB source tree.\n` +
      `\nTarget:\n  ${filePath}\n` +
      `\nAllowed local implementation directory:\n  ${BUG_TRIAGE_DIR}\n` +
      (CURRENT_WORKTREE_DIR ? `\nAllowed fix worktree:\n  ${CURRENT_WORKTREE_DIR}\n` : '') +
      `\nUse a temporary Git worktree for source modifications.\n`
    );
  }
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, content, 'utf8');
}

// ---------------------------------------------------------------------------
// 2. Shell helpers
// ---------------------------------------------------------------------------

/**
 * Run a shell command synchronously.
 * Returns stdout as a string, or throws with the command and stderr.
 *
 * @param {string} command
 * @param {{ cwd?: string, allowFailure?: boolean }} [opts]
 */
function run(command, opts = {}) {
  const cwd = opts.cwd || REPO_ROOT;
  const result = spawnSync('bash', ['-c', command], {
    cwd,
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
  });
  if (result.status !== 0 && !opts.allowFailure) {
    const msg = (result.stderr || '').trim() || (result.stdout || '').trim();
    throw new Error(`Command failed (exit ${result.status}): ${command}\n${msg}`);
  }
  return (result.stdout || '').trim();
}

/**
 * Run a command in the fix worktree, not in the original repo.
 * CURRENT_WORKTREE_DIR must already be set.
 */
function runInWorktree(command) {
  if (!CURRENT_WORKTREE_DIR) throw new Error('No worktree available yet.');
  return run(command, { cwd: CURRENT_WORKTREE_DIR });
}

/**
 * Return stdout or a fallback string if the command fails.
 */
function tryRun(command, fallback = 'Unavailable', opts = {}) {
  try { return run(command, { ...opts, allowFailure: false }) || fallback; }
  catch { return fallback; }
}

// ---------------------------------------------------------------------------
// 3. Secret redaction
// ---------------------------------------------------------------------------

const SECRET_PATTERNS = [
  // key=value / key: value style  (passwords, tokens, secrets, api keys, …)
  /(?:password|passwd|secret|token|apikey|api_key|auth|bearer|credential|authorization|private_key|access_key|secret_key)\s*[=:]\s*\S+/gi,
  // Connection strings
  /(?:postgresql|mysql|mongodb|redis|amqp):\/\/[^@\s]+@[^\s"']+/gi,
  // JWTs  (three base64url segments)
  /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
  // AWS key IDs
  /(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}/g,
  // Generic 32-64 char hex secrets
  /\b[0-9a-fA-F]{32,64}\b/g,
];

/**
 * Redact sensitive values from a string before it is sent to GitHub or output.
 */
function redactSecrets(text) {
  if (typeof text !== 'string') return text;
  let out = text;
  for (const pattern of SECRET_PATTERNS) {
    out = out.replace(pattern, (match) => {
      // Keep the key name for context, replace the value
      const eqIdx = match.search(/[=:]/);
      if (eqIdx > -1) {
        return match.slice(0, eqIdx + 1) + ' [REDACTED]';
      }
      return '[REDACTED]';
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// 4. Stage 1 — Environment detection
// ---------------------------------------------------------------------------

/**
 * Collect environment information using only read-only commands.
 * Returns a plain object with all detected values.
 */
function detectEnvironment() {
  console.log('\n[Stage 1] Detecting environment…');

  const env = {
    os:           `${os.type()} ${os.release()} (${os.arch()})`,
    hostname:     os.hostname(),
    nodeVersion:  tryRun('node --version'),
    pythonVersion: tryRun('python3 --version') !== 'Unavailable'
                    ? tryRun('python3 --version')
                    : tryRun('python --version'),
    mindsdbVersion: tryRun(
      `python3 -c "import ast,sys; " \
       "src=open('${path.join(REPO_ROOT, 'mindsdb', '__about__.py')}').read(); " \
       "tree=ast.parse(src); " \
       "[print(n.value.s) for n in ast.walk(tree) " \
       "if isinstance(n, ast.Assign) and any(t.id=='__version__' for t in n.targets if isinstance(t, ast.Name))]"`,
      // Fast fallback: grep the file
    ) || tryRun(
      `grep '__version__' "${path.join(REPO_ROOT, 'mindsdb', '__about__.py')}" | head -1`
    ),
    gitCommit:    tryRun('git rev-parse HEAD'),
    gitBranch:    tryRun('git branch --show-current'),
    gitStatus:    tryRun('git status --short'),
    dockerVersion: tryRun('docker --version'),
    dockerComposeVersion: tryRun('docker compose version'),
    installMethod: detectInstallMethod(),
  };

  console.log(`  OS:             ${env.os}`);
  console.log(`  Python:         ${env.pythonVersion}`);
  console.log(`  MindsDB:        ${env.mindsdbVersion}`);
  console.log(`  Commit:         ${env.gitCommit.slice(0, 12)}`);
  console.log(`  Branch:         ${env.gitBranch}`);
  console.log(`  Docker:         ${env.dockerVersion}`);
  console.log(`  Install method: ${env.installMethod}`);

  return env;
}

function detectInstallMethod() {
  // Check for Docker first
  const dockerPsOut = tryRun('docker ps --filter name=mindsdb --format "{{.Names}}"', '');
  if (dockerPsOut) return 'Docker';

  const composePsOut = tryRun('docker compose ps --services 2>/dev/null', '');
  if (composePsOut.includes('mindsdb')) return 'Docker Compose';

  // Check if installed as a Python package in editable mode (dev install)
  const pipShow = tryRun('pip show mindsdb 2>/dev/null || pip3 show mindsdb 2>/dev/null', '');
  if (pipShow.includes('Location')) {
    if (pipShow.includes(REPO_ROOT)) return 'pip (editable/development)';
    return 'pip';
  }

  // Check for pyproject.toml / setup.py in repo root (source checkout)
  if (fs.existsSync(path.join(REPO_ROOT, 'pyproject.toml'))) {
    return 'source checkout';
  }

  return 'unknown';
}

// ---------------------------------------------------------------------------
// 5. Stage 2 — MindsDB runtime detection
// ---------------------------------------------------------------------------

/**
 * Determine how MindsDB is currently running (if at all).
 */
function detectRuntime() {
  console.log('\n[Stage 2] Detecting MindsDB runtime…');

  const runtime = { method: 'not detected', containers: [], processes: [] };

  // Docker containers named or labeled 'mindsdb'
  const dockerPs = tryRun(
    'docker ps --filter name=mindsdb --format "{{.ID}} {{.Names}} {{.Status}}"', ''
  );
  if (dockerPs) {
    runtime.method = 'Docker';
    runtime.containers = dockerPs.split('\n').filter(Boolean);
    console.log(`  Docker containers: ${runtime.containers.join(', ')}`);
    return runtime;
  }

  // Docker Compose services
  const composePs = tryRun('docker compose ps 2>/dev/null', '');
  if (composePs.includes('mindsdb')) {
    runtime.method = 'Docker Compose';
    runtime.containers = ['(see docker compose ps output)'];
    console.log('  Running via Docker Compose');
    return runtime;
  }

  // Look for Python processes running mindsdb
  const psOut = tryRun('ps aux 2>/dev/null || tasklist 2>/dev/null', '');
  const mindsdbProcs = psOut.split('\n').filter(
    l => l.toLowerCase().includes('mindsdb') && !l.includes('bug_triage')
  );
  if (mindsdbProcs.length > 0) {
    runtime.method = 'Python process';
    runtime.processes = mindsdbProcs.slice(0, 5);
    console.log(`  Python processes found: ${mindsdbProcs.length}`);
    return runtime;
  }

  console.log('  MindsDB does not appear to be running.');
  return runtime;
}

// ---------------------------------------------------------------------------
// 6. Stage 3 — Log collection
// ---------------------------------------------------------------------------

/**
 * Locate MindsDB log files and Docker logs.
 * Returns an object with log content (already redacted).
 *
 * @param {object} runtime  Result from detectRuntime()
 */
function collectLogs(runtime) {
  console.log('\n[Stage 3] Collecting logs…');

  const logs = {};
  const errorPattern = 'error|exception|traceback|failed|critical|warning';

  // --- Docker logs --------------------------------------------------------
  if (runtime.method === 'Docker' && runtime.containers.length > 0) {
    for (const containerLine of runtime.containers) {
      const containerId = containerLine.split(' ')[0];
      const raw = tryRun(`docker logs --tail 500 ${containerId} 2>&1`, '');
      const filtered = filterLogLines(raw, errorPattern);
      logs[`docker:${containerId}`] = redactSecrets(filtered);
      console.log(`  Docker container ${containerId}: ${filtered.split('\n').length} relevant lines`);
    }
    return logs;
  }

  // --- Docker Compose logs ------------------------------------------------
  if (runtime.method === 'Docker Compose') {
    const raw = tryRun('docker compose logs --tail 500 mindsdb 2>&1', '');
    logs['docker-compose:mindsdb'] = redactSecrets(filterLogLines(raw, errorPattern));
    console.log(`  Docker Compose mindsdb service: collected`);
    return logs;
  }

  // --- File-based logs ----------------------------------------------------
  // MindsDB writes logs to config.paths["log"] / mindsdb.log
  // Common locations:
  const candidateDirs = [
    '/root/mdb_storage/logs',
    path.join(os.homedir(), '.local', 'share', 'mindsdb', 'logs'),
    path.join(os.homedir(), 'mdb_storage', 'logs'),
    '/tmp/mindsdb/logs',
    // User-configured via MINDSDB_STORAGE_DIR env var
    process.env.MINDSDB_STORAGE_DIR ? path.join(process.env.MINDSDB_STORAGE_DIR, 'logs') : null,
  ].filter(Boolean);

  let foundAny = false;
  for (const dir of candidateDirs) {
    if (!fs.existsSync(dir)) continue;
    const logFiles = fs.readdirSync(dir)
      .filter(f => f.endsWith('.log'))
      .map(f => path.join(dir, f));

    for (const logFile of logFiles) {
      try {
        const raw = tryRun(`tail -n 1000 "${logFile}" 2>/dev/null`, '');
        const filtered = filterLogLines(raw, errorPattern);
        logs[logFile] = redactSecrets(filtered);
        foundAny = true;
        console.log(`  ${logFile}: ${filtered.split('\n').length} relevant lines`);
      } catch { /* skip unreadable */ }
    }
  }

  if (!foundAny) {
    console.log('  No log files found. Logs may only be on stdout/stderr of the running process.');
    logs['note'] = 'No log files found. Check stdout/stderr of the MindsDB process.';
  }

  return logs;
}

/**
 * Keep only lines matching the given grep pattern (case-insensitive).
 * Also keeps lines immediately following a match (for context).
 */
function filterLogLines(text, pattern) {
  const re = new RegExp(pattern, 'i');
  const lines = text.split('\n');
  const result = [];
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i])) {
      // Include 2 lines before for context
      if (i > 0 && !result.includes(lines[i - 1])) result.push(lines[i - 1]);
      result.push(lines[i]);
      // Include 3 lines after for stack-trace context
      for (let j = 1; j <= 3 && i + j < lines.length; j++) {
        result.push(lines[i + j]);
      }
    }
  }
  return result.join('\n');
}

// ---------------------------------------------------------------------------
// 7. Stage 4 — Reproduction
// ---------------------------------------------------------------------------

/**
 * Record reproduction information.
 * The agent/user must supply the actual command and expected/actual output.
 *
 * This function provides the structure; real reproduction happens interactively.
 *
 * @param {{ command: string, input: string, expected: string, actual: string, error: string }} info
 */
function recordReproduction(info) {
  console.log('\n[Stage 4] Recording reproduction information…');
  const repro = {
    reproduced: info.reproduced || 'UNKNOWN',  // YES / NO / PARTIAL / UNKNOWN
    command:    info.command   || '',
    input:      info.input     || '',
    expected:   info.expected  || '',
    actual:     info.actual    || '',
    error:      redactSecrets(info.error || ''),
  };
  console.log(`  Reproduced: ${repro.reproduced}`);
  if (repro.command)  console.log(`  Command: ${repro.command}`);
  if (repro.error)    console.log(`  Error fragment: ${repro.error.slice(0, 200)}…`);
  return repro;
}

// ---------------------------------------------------------------------------
// 8. Stage 5 — Source code analysis helpers
// ---------------------------------------------------------------------------

/**
 * Search MindsDB source (read-only) for a pattern using ripgrep or grep.
 * Returns matching lines.
 *
 * @param {string} pattern   Regex pattern
 * @param {string} [scope]   Subdirectory to search (relative to REPO_ROOT)
 */
function searchSource(pattern, scope) {
  const searchDir = scope
    ? path.join(REPO_ROOT, scope)
    : path.join(REPO_ROOT, 'mindsdb');

  // Prefer rg (ripgrep) for speed; fall back to grep
  const rgCmd = `rg --no-heading -n -i -l ${shellQuote(pattern)} "${searchDir}" 2>/dev/null | head -20`;
  const grepCmd = `grep -rl --include="*.py" -i ${shellQuote(pattern)} "${searchDir}" 2>/dev/null | head -20`;

  const files = tryRun(rgCmd, '') || tryRun(grepCmd, '');
  if (!files) return [];

  return files.split('\n').filter(Boolean);
}

/**
 * Return the git log for a specific file (read-only).
 */
function gitLogFile(relPath) {
  return tryRun(
    `git log --oneline -20 -- "${relPath}"`,
    'No git history found.'
  );
}

/**
 * Return git blame for a range of lines in a file (read-only).
 */
function gitBlame(relPath, startLine, endLine) {
  return tryRun(
    `git blame -L ${startLine},${endLine} -- "${relPath}"`,
    'git blame unavailable.'
  );
}

/**
 * Return the content of a source file (read-only).
 * Caller must not pass the result to any write operation.
 */
function readSourceFile(relPath) {
  const abs = path.join(REPO_ROOT, relPath);
  if (!fs.existsSync(abs)) return null;
  return fs.readFileSync(abs, 'utf8');
}

// ---------------------------------------------------------------------------
// 9. Stage 6 — GitHub research
// ---------------------------------------------------------------------------

/**
 * Search GitHub issues and PRs in the official mindsdb/mindsdb repository.
 *
 * Requires `gh` CLI to be authenticated.
 * Returns an array of issue/PR objects.
 *
 * @param {string[]} searchTerms
 */
function searchGitHub(searchTerms) {
  console.log('\n[Stage 6] Searching GitHub issues and PRs…');
  checkGhAuth();

  const results = [];
  for (const term of searchTerms) {
    const quoted = shellQuote(term);

    // Issues (open + closed)
    const issueJson = tryRun(
      `gh issue list --repo mindsdb/mindsdb --state all --search ${quoted} --limit 10 --json number,title,state,url,body`,
      '[]'
    );
    try {
      const issues = JSON.parse(issueJson);
      results.push(...issues.map(i => ({ type: 'issue', ...i })));
    } catch { /* ignore parse errors */ }

    // PRs
    const prJson = tryRun(
      `gh pr list --repo mindsdb/mindsdb --state all --search ${quoted} --limit 10 --json number,title,state,url,body`,
      '[]'
    );
    try {
      const prs = JSON.parse(prJson);
      results.push(...prs.map(p => ({ type: 'pr', ...p })));
    } catch { /* ignore parse errors */ }
  }

  // Deduplicate by number+type
  const seen = new Set();
  const unique = results.filter(r => {
    const key = `${r.type}:${r.number}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  console.log(`  Found ${unique.length} unique items across ${searchTerms.length} search term(s).`);
  return unique;
}

/**
 * Check whether the GitHub CLI is authenticated.
 * Throws with a clear message if not.
 */
function checkGhAuth() {
  const status = tryRun('gh auth status 2>&1', '');
  if (!status || status.toLowerCase().includes('not logged in')) {
    throw new Error(
      'GitHub CLI is not authenticated.\n' +
      'Run `gh auth login` to authenticate before using GitHub features.'
    );
  }
}

/**
 * Determine if any existing GitHub item is a duplicate of the current bug.
 * Simple heuristic: check for overlapping error message or title keywords.
 *
 * @param {object[]} githubResults
 * @param {string}   errorFragment
 * @returns {{ isDuplicate: boolean, item: object|null }}
 */
function detectDuplicate(githubResults, errorFragment) {
  if (!githubResults.length || !errorFragment) {
    return { isDuplicate: false, item: null };
  }
  const fragment = errorFragment.toLowerCase().slice(0, 100);
  for (const item of githubResults) {
    const combined = ((item.title || '') + ' ' + (item.body || '')).toLowerCase();
    // Overlap: at least 10 chars of the fragment appear in the issue
    const words = fragment.split(/\s+/).filter(w => w.length > 5);
    const matchCount = words.filter(w => combined.includes(w)).length;
    if (matchCount >= 2) {
      return { isDuplicate: true, item };
    }
  }
  return { isDuplicate: false, item: null };
}

// ---------------------------------------------------------------------------
// 10. Root cause assessment
// ---------------------------------------------------------------------------

/**
 * Assess confidence level.
 *
 * @param {{ exactSourcePath: boolean, reproduced: boolean, singleHypothesis: boolean }} evidence
 * @returns {'HIGH'|'MEDIUM'|'LOW'}
 */
function assessConfidence(evidence) {
  if (evidence.exactSourcePath && evidence.reproduced && evidence.singleHypothesis) {
    return 'HIGH';
  }
  if (evidence.reproduced || evidence.exactSourcePath) {
    return 'MEDIUM';
  }
  return 'LOW';
}

/**
 * Check all stop conditions before attempting a fix.
 * Returns an array of stop reasons; empty array means proceed.
 *
 * @param {{ confidence: string, reproduced: boolean, hypotheses: number, isUpstream: boolean, isArchitectural: boolean, hasSecurityRisk: boolean, hasDataLossRisk: boolean, testsKnown: boolean }} analysis
 */
function evaluateStopConditions(analysis) {
  const reasons = [];
  if (analysis.confidence === 'LOW')         reasons.push('Root cause confidence is LOW');
  if (!analysis.reproduced)                  reasons.push('Bug could not be reproduced');
  if (analysis.hypotheses > 1)               reasons.push('Multiple competing root-cause hypotheses remain');
  if (analysis.isUpstream)                   reasons.push('Problem is in an upstream dependency (not MindsDB)');
  if (analysis.isArchitectural)              reasons.push('Fix requires architectural changes');
  if (analysis.hasSecurityRisk)              reasons.push('Security implications are unclear');
  if (analysis.hasDataLossRisk)              reasons.push('Fix could cause data loss');
  if (!analysis.testsKnown)                  reasons.push('Relevant tests cannot be determined');
  return reasons;
}

// ---------------------------------------------------------------------------
// 11. GitHub issue creation
// ---------------------------------------------------------------------------

/**
 * Create a GitHub issue on the *official* mindsdb/mindsdb repository.
 * Returns the issue URL.
 *
 * @param {{ env, repro, rootCause, confidence, logs, proposedFix, component, testing }} issueData
 */
function createGitHubIssue(issueData) {
  console.log('\n[GitHub] Creating issue on mindsdb/mindsdb…');
  checkGhAuth();

  const body = buildIssueBody(issueData);
  const title = issueData.title || `[Bug]: ${issueData.rootCause.slice(0, 72)}`;
  const bodyFile = path.join(os.tmpdir(), `mdb_bug_triage_issue_${Date.now()}.md`);

  // Write body to a temp file (outside the repo) so gh can read it
  fs.writeFileSync(bodyFile, redactSecrets(body), 'utf8');

  let url;
  try {
    url = run(
      `gh issue create --repo mindsdb/mindsdb --title ${shellQuote(title)} --label bug --body-file ${shellQuote(bodyFile)}`,
      { cwd: os.tmpdir() }
    );
  } finally {
    try { fs.unlinkSync(bodyFile); } catch { /* best effort */ }
  }
  console.log(`  Issue created: ${url}`);
  return url.trim();
}

/**
 * Add a comment to an existing GitHub issue.
 */
function commentOnIssue(issueNumber, body) {
  console.log(`\n[GitHub] Adding comment to issue #${issueNumber}…`);
  checkGhAuth();

  const commentFile = path.join(os.tmpdir(), `mdb_bug_comment_${Date.now()}.md`);
  fs.writeFileSync(commentFile, redactSecrets(body), 'utf8');
  try {
    run(`gh issue comment ${issueNumber} --repo mindsdb/mindsdb --body-file ${shellQuote(commentFile)}`,
        { cwd: os.tmpdir() });
  } finally {
    try { fs.unlinkSync(commentFile); } catch { /* best effort */ }
  }
}

function buildIssueBody(data) {
  const env = data.env || {};
  const repro = data.repro || {};
  const logSnippet = Object.entries(data.logs || {})
    .map(([src, content]) => `**${src}**\n\`\`\`\n${(content || '').slice(0, 2000)}\n\`\`\``)
    .join('\n\n');

  return `## Bug

${data.description || data.rootCause || ''}

## Environment

- MindsDB version: ${env.mindsdbVersion || 'Unknown'}
- Commit: ${env.gitCommit || 'Unknown'}
- OS: ${env.os || 'Unknown'}
- Python: ${env.pythonVersion || 'Unknown'}
- Installation: ${env.installMethod || 'Unknown'}
- Component: ${data.component || 'Unknown'}

## Expected Behavior

${repro.expected || '(not specified)'}

## Actual Behavior

${repro.actual || '(not specified)'}

## Reproduction

\`\`\`
${repro.command || '(see description)'}
\`\`\`

## Error

\`\`\`
${redactSecrets(repro.error || '(none)')}
\`\`\`

## Logs

${logSnippet || '(none collected)'}

## Root Cause

${data.rootCause || 'Under investigation'}

## Confidence

${data.confidence || 'LOW'}

## Proposed Fix

${data.proposedFix || '(to be determined)'}

## Testing

${data.testing || '(to be determined)'}
`;
}

// ---------------------------------------------------------------------------
// 12. Fix worktree management
// ---------------------------------------------------------------------------

/**
 * Detect the user's fork remote and the upstream remote.
 * Returns { forkRemote, upstreamRemote, forkOwner, forkRepo }.
 */
function detectGitRemotes() {
  const remoteOutput = tryRun('git remote -v', '');
  const lines = remoteOutput.split('\n').filter(Boolean);

  const remotes = {};
  for (const line of lines) {
    const m = line.match(/^(\S+)\s+(\S+)\s+\((\w+)\)/);
    if (m) {
      const [, name, url, type] = m;
      if (!remotes[name]) remotes[name] = { url, fetch: null, push: null };
      remotes[name][type] = url;
    }
  }

  // Determine upstream (official mindsdb/mindsdb)
  let upstreamRemote = null;
  let forkRemote = null;

  for (const [name, info] of Object.entries(remotes)) {
    const url = info.url || '';
    if (url.includes('mindsdb/mindsdb')) {
      if (name === 'upstream') upstreamRemote = name;
      else if (name === 'origin') {
        // Could be the official repo or the fork
        // Check if it's the official repo (no fork owner mismatch)
        if (url.match(/github\.com[:/]mindsdb\/mindsdb/)) upstreamRemote = name;
        else forkRemote = name;
      } else {
        forkRemote = name;
      }
    } else if (url.includes('github.com')) {
      forkRemote = forkRemote || name;
    }
  }

  // If only origin exists and it's the official repo, warn about fork setup
  if (!forkRemote && upstreamRemote) {
    console.warn(
      '  WARNING: No fork remote detected. ' +
      'Please fork mindsdb/mindsdb and add your fork as a remote: ' +
      '`git remote add fork https://github.com/<your-username>/mindsdb.git`'
    );
  }

  // Parse owner from fork remote URL
  let forkOwner = null;
  if (forkRemote && remotes[forkRemote]) {
    const url = remotes[forkRemote].url || '';
    const m = url.match(/github\.com[:/]([^/]+)\//);
    if (m) forkOwner = m[1];
  }

  return {
    forkRemote:     forkRemote || 'origin',
    upstreamRemote: upstreamRemote || 'upstream',
    forkOwner,
    remotes,
  };
}

/**
 * Create a temporary Git worktree OUTSIDE the original checkout.
 *
 * @param {string} branchName   e.g. "fix/handle-null-result"
 * @param {string} baseBranch   e.g. "main"
 * @param {string} baseDir      Parent directory for the worktree (default /tmp)
 * @returns {string}            Absolute path to the new worktree
 */
function createFixWorktree(branchName, baseBranch, baseDir) {
  const worktreeName = `mindsdb-triage-${branchName.replace(/[^a-zA-Z0-9-]/g, '-')}-${Date.now()}`;
  const worktreePath = path.join(baseDir || os.tmpdir(), worktreeName);

  console.log(`\n[Fix] Creating worktree at: ${worktreePath}`);

  // Fetch upstream base branch first
  try {
    run(`git fetch origin ${baseBranch} 2>/dev/null || true`);
  } catch { /* best effort */ }

  run(`git worktree add "${worktreePath}" -b "${branchName}" "${baseBranch}"`);

  CURRENT_WORKTREE_DIR = worktreePath;
  console.log(`  Worktree created: ${worktreePath}`);
  console.log(`  Branch: ${branchName} (based on ${baseBranch})`);

  return worktreePath;
}

/**
 * Remove the temporary worktree after push (cleanup).
 * @param {string} worktreePath
 */
function removeWorktree(worktreePath) {
  console.log(`\n[Cleanup] Removing worktree: ${worktreePath}`);
  run(`git worktree remove --force "${worktreePath}"`, { allowFailure: true });
  try { fs.rmSync(worktreePath, { recursive: true, force: true }); } catch { /* best effort */ }
  if (CURRENT_WORKTREE_DIR === worktreePath) CURRENT_WORKTREE_DIR = null;
}

// ---------------------------------------------------------------------------
// 13. Apply fix in worktree
// ---------------------------------------------------------------------------

/**
 * Apply a patch (array of { file, oldContent, newContent }) inside the worktree.
 * Each file path is relative to the MindsDB repo root.
 * Safety guard is enforced for every write.
 *
 * @param {Array<{ file: string, newContent: string }>} patches
 */
function applyFix(patches) {
  if (!CURRENT_WORKTREE_DIR) throw new Error('No worktree. Call createFixWorktree() first.');

  console.log(`\n[Fix] Applying ${patches.length} file change(s) in worktree…`);

  for (const patch of patches) {
    const absPath = path.join(CURRENT_WORKTREE_DIR, patch.file);

    // Safety check: must be inside the worktree
    if (!isAllowedWritePath(absPath)) {
      throw new Error(
        `Safety guard violation: attempted to write outside worktree.\n` +
        `  Target: ${absPath}\n` +
        `  Allowed: ${CURRENT_WORKTREE_DIR}`
      );
    }

    console.log(`  Patching: ${patch.file}`);
    fs.mkdirSync(path.dirname(absPath), { recursive: true });
    fs.writeFileSync(absPath, patch.newContent, 'utf8');
  }
}

// ---------------------------------------------------------------------------
// 14. Test execution
// ---------------------------------------------------------------------------

/**
 * Run pytest in the fix worktree.
 *
 * @param {string[]} testPaths  e.g. ['tests/unit/executor/', 'tests/unit/various/']
 * @param {object}   opts
 * @param {boolean}  [opts.slow]   Include slow tests (--runslow)
 * @returns {{ executed: number, passed: number, failed: number, skipped: number, output: string }}
 */
function runTests(testPaths, opts = {}) {
  if (!CURRENT_WORKTREE_DIR) throw new Error('No worktree. Create one before running tests.');

  const testPathArgs = testPaths.map(p => shellQuote(p)).join(' ');
  const slowFlag = opts.slow ? '--runslow' : '';
  const cmd = [
    'python -m pytest',
    '-v -rs --disable-warnings',
    slowFlag,
    testPathArgs,
    '--tb=short',
    '2>&1',
  ].filter(Boolean).join(' ');

  console.log(`\n[Tests] Running: ${cmd}`);

  const output = tryRun(cmd, 'Test run failed.', { cwd: CURRENT_WORKTREE_DIR });

  // Parse pytest summary line: "X passed, Y failed, Z error, W warning in Ns"
  const summaryMatch = output.match(
    /(\d+)\s+passed(?:,\s*(\d+)\s+failed)?(?:,\s*(\d+)\s+error(?:s)?)?(?:,\s*(\d+)\s+skipped)?/i
  );

  const result = {
    executed: 0, passed: 0, failed: 0, skipped: 0,
    output: output.slice(-8000), // last 8 KB to avoid context overflow
  };

  if (summaryMatch) {
    result.passed  = parseInt(summaryMatch[1] || '0', 10);
    result.failed  = parseInt(summaryMatch[2] || '0', 10);
    result.skipped = parseInt(summaryMatch[4] || '0', 10);
    result.executed = result.passed + result.failed + result.skipped;
  }

  console.log(
    `  Tests — executed: ${result.executed}, passed: ${result.passed}, ` +
    `failed: ${result.failed}, skipped: ${result.skipped}`
  );

  if (result.failed > 0) {
    console.warn('  WARNING: Some tests failed. Review test output before pushing.');
  }

  return result;
}

// ---------------------------------------------------------------------------
// 15. Commit and push
// ---------------------------------------------------------------------------

/**
 * Stage all changes, create a conventional commit, and push to the fork.
 *
 * @param {string} message     Commit message (conventional commits style)
 * @param {string} forkRemote  Git remote name of the user's fork
 * @param {string} branch      Branch name to push
 */
function commitAndPush(message, forkRemote, branch) {
  if (!CURRENT_WORKTREE_DIR) throw new Error('No worktree.');

  console.log(`\n[Git] Staging and committing: "${message}"`);

  runInWorktree('git add -A');
  runInWorktree(`git commit -m ${shellQuote(message)}`);

  console.log(`[Git] Pushing branch "${branch}" to remote "${forkRemote}"…`);
  runInWorktree(`git push -u "${forkRemote}" "${branch}"`);

  console.log('  Push successful.');
}

// ---------------------------------------------------------------------------
// 16. Pull Request creation
// ---------------------------------------------------------------------------

/**
 * Create a Pull Request targeting the official upstream MindsDB repository.
 * The head branch originates from the user's fork.
 *
 * @param {{ title, body, branch, forkOwner, baseBranch, issueNumber }} prData
 * @returns {string}  PR URL
 */
function createPullRequest(prData) {
  console.log('\n[GitHub] Creating Pull Request…');
  checkGhAuth();

  const { title, body, branch, forkOwner, baseBranch, issueNumber } = prData;

  const prBody = buildPrBody({ ...prData, issueNumber });
  const bodyFile = path.join(os.tmpdir(), `mdb_pr_body_${Date.now()}.md`);
  fs.writeFileSync(bodyFile, redactSecrets(prBody), 'utf8');

  // head syntax: forkOwner:branch (for cross-repo PRs)
  const head = forkOwner ? `${forkOwner}:${branch}` : branch;

  let prUrl;
  try {
    prUrl = run(
      `gh pr create ` +
      `--repo mindsdb/mindsdb ` +
      `--base ${shellQuote(baseBranch || 'main')} ` +
      `--head ${shellQuote(head)} ` +
      `--title ${shellQuote(title)} ` +
      `--body-file ${shellQuote(bodyFile)}`,
      { cwd: os.tmpdir() }
    );
  } finally {
    try { fs.unlinkSync(bodyFile); } catch { /* best effort */ }
  }

  console.log(`  PR created: ${prUrl.trim()}`);
  return prUrl.trim();
}

function buildPrBody(data) {
  const testResult = data.testResult || {};
  return `## Summary

${data.summary || data.description || ''}

## Root Cause

${data.rootCause || '(see linked issue)'}

## Fix

${data.fixDescription || '(see diff)'}

## Reproduction

${data.reproductionSteps || '(see linked issue)'}

## Tests

Tests executed: ${testResult.executed || 0}
Tests passed:   ${testResult.passed   || 0}
Tests failed:   ${testResult.failed   || 0}
Tests skipped:  ${testResult.skipped  || 0}

## Related Issue

Fixes #${data.issueNumber || 'N/A'}
`;
}

// ---------------------------------------------------------------------------
// 17. Verify original checkout is unchanged
// ---------------------------------------------------------------------------

/**
 * Assert that the original MindsDB checkout has no uncommitted changes caused
 * by the triage tool.  Throws if unexpected modifications are found.
 *
 * @returns {{ clean: boolean, status: string }}
 */
function verifyOriginalCheckout() {
  console.log('\n[Safety] Verifying original MindsDB checkout is unchanged…');
  const status = run('git status --short', { cwd: REPO_ROOT });

  // Filter out the MindsDB-Bug-Triage/ directory — those changes are expected
  const unexpectedLines = status
    .split('\n')
    .filter(l => l.trim() && !l.includes('MindsDB-Bug-Triage/'));

  if (unexpectedLines.length > 0) {
    const detail = unexpectedLines.join('\n');
    throw new Error(
      `SAFETY VIOLATION: Original MindsDB source tree has unexpected modifications!\n\n` +
      `${detail}\n\n` +
      `Halting. Do NOT push until this is investigated.`
    );
  }

  console.log('  Original MindsDB checkout: UNCHANGED ✓');
  return { clean: true, status };
}

// ---------------------------------------------------------------------------
// 18. Final report
// ---------------------------------------------------------------------------

/**
 * Print the standardised final triage report.
 *
 * @param {{ env, repro, rootCause, confidence, issueUrl, fixDescription, testResult, prUrl, checkoutClean }} report
 */
function printFinalReport(report) {
  const r = report;
  const env = r.env || {};
  const testResult = r.testResult || {};

  const sep = '═'.repeat(54);
  console.log(`\nMindsDB Bug Triage`);
  console.log(sep);
  console.log(`\nRepository:        ${tryRun('git remote get-url origin', 'unknown')}`);
  console.log(`MindsDB version:   ${env.mindsdbVersion || 'unknown'}`);
  console.log(`Commit:            ${(env.gitCommit || 'unknown').slice(0, 12)}`);
  console.log(`Environment:       ${env.os || 'unknown'} / ${env.pythonVersion || 'unknown'} / ${env.installMethod || 'unknown'}`);
  console.log(`\nReproduced:        ${(r.repro && r.repro.reproduced) || 'UNKNOWN'}`);
  console.log(`\nRoot Cause:        ${r.rootCause || '(under investigation)'}`);
  console.log(`\nConfidence:        ${r.confidence || 'LOW'}`);
  console.log(`\nGitHub Issue:      ${r.issueUrl || 'none'}`);
  console.log(`\nFix:               ${r.fixDescription || 'none'}`);
  console.log(`\nTests:`);
  console.log(`  Executed:  ${testResult.executed || 0}`);
  console.log(`  Passed:    ${testResult.passed   || 0}`);
  console.log(`  Failed:    ${testResult.failed   || 0}`);
  console.log(`  Skipped:   ${testResult.skipped  || 0}`);
  console.log(`\nPull Request:      ${r.prUrl || 'none'}`);
  console.log(`\nOriginal MindsDB checkout: ${r.checkoutClean ? 'UNCHANGED' : 'ERROR — INVESTIGATE'}`);
  console.log(sep);
}

// ---------------------------------------------------------------------------
// 19. Utility
// ---------------------------------------------------------------------------

/**
 * Shell-quote a string to prevent injection.
 * Wraps value in single quotes and escapes embedded single quotes.
 */
function shellQuote(str) {
  return `'${String(str).replace(/'/g, "'\\''")}'`;
}

// ---------------------------------------------------------------------------
// 20. Top-level orchestrator
// ---------------------------------------------------------------------------

/**
 * Run the full triage workflow.
 * This is the main entry point called from the CLI below.
 *
 * @param {object} options
 * @param {string} options.description    Short description of the problem
 * @param {string} [options.error]        Error message fragment
 * @param {string} [options.component]    MindsDB component
 * @param {string} [options.worktreeBase] Parent dir for fix worktree
 * @param {boolean} [options.dryRun]      Skip GitHub & fix operations
 * @param {string} [options.baseBranch]   Git base branch (default: main)
 * @param {object} [options.repro]        Pre-filled reproduction info
 * @param {object} [options.analysis]     Pre-filled analysis results
 * @param {object} [options.patches]      File patches to apply
 */
async function runTriage(options) {
  const {
    description,
    error: errorFragment = '',
    component = 'unknown',
    worktreeBase = os.tmpdir(),
    dryRun = false,
    baseBranch = 'main',
    repro: reproInput = {},
    analysis: analysisInput = {},
    patches = [],
  } = options;

  if (!description) {
    throw new Error('--description is required.');
  }

  const report = {};

  // ---------- Stage 1: Environment ----------
  const env = detectEnvironment();
  report.env = env;

  // ---------- Stage 2: Runtime ----------
  const runtime = detectRuntime();

  // ---------- Stage 3: Logs ----------
  const logs = collectLogs(runtime);

  // ---------- Stage 4: Reproduction ----------
  const repro = recordReproduction({
    reproduced: reproInput.reproduced || 'UNKNOWN',
    command:    reproInput.command    || '',
    input:      reproInput.input      || '',
    expected:   reproInput.expected   || '',
    actual:     reproInput.actual     || '',
    error:      errorFragment         || reproInput.error || '',
  });
  report.repro = repro;

  // ---------- Stage 5: Source analysis (caller-supplied or placeholder) ----------
  const rootCause      = analysisInput.rootCause     || '(analysis pending — run source inspection)';
  const confidence     = analysisInput.confidence    || assessConfidence({
    exactSourcePath:  Boolean(analysisInput.exactSourcePath),
    reproduced:       repro.reproduced === 'YES',
    singleHypothesis: (analysisInput.hypotheses || 2) <= 1,
  });
  report.rootCause = rootCause;
  report.confidence = confidence;

  // ---------- Stage 6: GitHub research ----------
  let issueUrl = null;
  let existingIssueNumber = null;

  if (!dryRun) {
    let githubResults = [];
    try {
      const searchTerms = [
        errorFragment.slice(0, 80),
        component,
        description.slice(0, 60),
      ].filter(Boolean);
      githubResults = searchGitHub(searchTerms);
    } catch (e) {
      console.warn(`  GitHub search skipped: ${e.message}`);
    }

    const { isDuplicate, item } = detectDuplicate(githubResults, errorFragment || description);

    if (isDuplicate && item) {
      console.log(`\n[GitHub] Duplicate found: #${item.number} — ${item.title}`);
      console.log(`  URL: ${item.url}`);
      existingIssueNumber = item.number;
      issueUrl = item.url;

      // Add new evidence as a comment
      try {
        commentOnIssue(item.number,
          `**New evidence from automated triage**\n\n` +
          `- MindsDB version: ${env.mindsdbVersion}\n` +
          `- Commit: ${env.gitCommit}\n` +
          `- OS: ${env.os}\n` +
          `- Reproduced: ${repro.reproduced}\n\n` +
          `**Error fragment:**\n\`\`\`\n${redactSecrets(errorFragment)}\n\`\`\``
        );
      } catch (e) {
        console.warn(`  Could not add comment: ${e.message}`);
      }
    } else {
      // Create new issue
      try {
        issueUrl = createGitHubIssue({
          title:       `[Bug]: ${description.slice(0, 72)}`,
          description,
          env,
          repro,
          logs,
          rootCause,
          confidence,
          component,
          proposedFix: analysisInput.proposedFix || '(to be determined)',
          testing:     analysisInput.testing     || '(to be determined)',
        });
        const m = issueUrl.match(/\/issues\/(\d+)/);
        if (m) existingIssueNumber = parseInt(m[1], 10);
      } catch (e) {
        console.warn(`  Could not create issue: ${e.message}`);
      }
    }
  }

  report.issueUrl = issueUrl;

  // ---------- Stop condition check ----------
  const stopReasons = evaluateStopConditions({
    confidence,
    reproduced:        repro.reproduced === 'YES',
    hypotheses:        analysisInput.hypotheses    || 2,
    isUpstream:        analysisInput.isUpstream    || false,
    isArchitectural:   analysisInput.isArchitectural || false,
    hasSecurityRisk:   analysisInput.hasSecurityRisk || false,
    hasDataLossRisk:   analysisInput.hasDataLossRisk || false,
    testsKnown:        patches.length > 0 || Boolean(analysisInput.testPaths),
  });

  if (stopReasons.length > 0) {
    console.log('\n[Stop] Triage stopped before fix stage:');
    stopReasons.forEach(r => console.log(`  • ${r}`));
    report.fixDescription = `Stopped: ${stopReasons.join('; ')}`;
    report.prUrl = null;
    report.testResult = {};

    // Verify original checkout before exiting
    try {
      const { clean } = verifyOriginalCheckout();
      report.checkoutClean = clean;
    } catch (e) {
      report.checkoutClean = false;
      console.error(e.message);
    }

    printFinalReport(report);
    return report;
  }

  // ---------- Stage 7: Fix in worktree ----------
  let prUrl = null;
  let testResult = {};

  if (!dryRun && patches.length > 0) {
    const branchName = `fix/${slugify(description).slice(0, 40)}-${Date.now()}`;
    const remoteInfo = detectGitRemotes();

    let worktreePath;
    try {
      worktreePath = createFixWorktree(branchName, baseBranch, worktreeBase);
      applyFix(patches);

      // ---------- Stage 8: Tests ----------
      const testPaths = analysisInput.testPaths || ['tests/unit/'];
      testResult = runTests(testPaths);
      report.testResult = testResult;

      if (testResult.failed > 0) {
        console.warn('\n  Tests failed — not pushing. Review and fix test failures first.');
      } else {
        // ---------- Stage 9: Commit & push ----------
        const commitMsg = buildCommitMessage(analysisInput, description);
        commitAndPush(commitMsg, remoteInfo.forkRemote, branchName);

        // ---------- Stage 10: PR ----------
        prUrl = createPullRequest({
          title:              `fix: ${description.slice(0, 60)}`,
          summary:            description,
          rootCause,
          fixDescription:     analysisInput.proposedFix || 'See diff',
          reproductionSteps:  `\`${repro.command}\``,
          testResult,
          branch:             branchName,
          forkOwner:          remoteInfo.forkOwner,
          baseBranch,
          issueNumber:        existingIssueNumber,
        });
      }
    } finally {
      if (worktreePath) {
        removeWorktree(worktreePath);
      }
    }
  }

  report.prUrl = prUrl;
  report.fixDescription = patches.length > 0
    ? (analysisInput.proposedFix || 'Patch applied')
    : 'No patch provided (analysis only)';

  // ---------- Stage 11: Verify original checkout ----------
  try {
    const { clean } = verifyOriginalCheckout();
    report.checkoutClean = clean;
  } catch (e) {
    report.checkoutClean = false;
    console.error(e.message);
  }

  printFinalReport(report);
  return report;
}

// ---------------------------------------------------------------------------
// 21. Helpers
// ---------------------------------------------------------------------------

function slugify(text) {
  return text.toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

function buildCommitMessage(analysis, description) {
  const scope = analysis.scope || deriveScope(analysis.component || '');
  const summary = (analysis.commitSummary || description).slice(0, 60);
  return `fix${scope ? `(${scope})` : ''}: ${summary}`;
}

function deriveScope(component) {
  if (!component) return '';
  // e.g. "integrations/handlers/mysql_handler" → "mysql-handler"
  const parts = component.split('/');
  const last = parts[parts.length - 1];
  return last.replace(/_handler$/, '-handler').replace(/_/g, '-');
}

// ---------------------------------------------------------------------------
// 22. CLI entry point
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = {
    description:  '',
    error:        '',
    component:    '',
    worktreeBase: os.tmpdir(),
    dryRun:       false,
    baseBranch:   'main',
    help:         false,
  };

  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--description':   opts.description  = args[++i] || ''; break;
      case '--error':         opts.error         = args[++i] || ''; break;
      case '--component':     opts.component     = args[++i] || ''; break;
      case '--worktree-base': opts.worktreeBase  = args[++i] || os.tmpdir(); break;
      case '--base-branch':   opts.baseBranch    = args[++i] || 'main'; break;
      case '--dry-run':       opts.dryRun        = true; break;
      case '--help':          opts.help          = true; break;
    }
  }
  return opts;
}

function printHelp() {
  console.log(`
MindsDB Bug Triage
==================
Usage: node MindsDB-Bug-Triage/bug_triage.js [options]

Options:
  --description <text>     Problem description (required)
  --error <text>           Error message or stack trace fragment
  --component <name>       MindsDB component (e.g. api/http, integrations/handlers/mysql)
  --worktree-base <dir>    Parent directory for temporary fix worktree (default: ${os.tmpdir()})
  --base-branch <branch>   Base branch for fix (default: main)
  --dry-run                Analysis only; skip issue/PR creation
  --help                   Show this help

Programmatic usage (import):
  const t = require('./MindsDB-Bug-Triage/bug_triage.js');
  await t.runTriage({ description, error, component, analysis, patches });

Exported API:
  runTriage(options)           Full orchestrated workflow
  detectEnvironment()          Stage 1: environment info
  detectRuntime()              Stage 2: how MindsDB is running
  collectLogs(runtime)         Stage 3: log collection
  recordReproduction(info)     Stage 4: reproduction record
  searchSource(pattern, scope) Stage 5: read-only source search
  searchGitHub(terms)          Stage 6: GitHub issue/PR search
  detectDuplicate(items, err)  Duplicate detection
  assessConfidence(evidence)   Confidence level
  evaluateStopConditions(a)    Stop condition checker
  createGitHubIssue(data)      Create GitHub issue
  commentOnIssue(num, body)    Comment on existing issue
  createFixWorktree(b, base)   Create external git worktree
  applyFix(patches)            Apply patches in worktree
  runTests(paths, opts)        Run pytest in worktree
  commitAndPush(msg, remote, b) Commit and push fix branch
  createPullRequest(data)      Open PR against upstream
  verifyOriginalCheckout()     Assert original repo unchanged
  isAllowedWritePath(path)     Safety guard
  redactSecrets(text)          Secret redaction
  gitLogFile(relPath)          git log for a file (read-only)
  gitBlame(relPath, s, e)      git blame for line range (read-only)
  readSourceFile(relPath)      Read source file (read-only)
`);
}

// Run when executed directly
if (require.main === module) {
  const opts = parseArgs(process.argv);

  if (opts.help || !opts.description) {
    printHelp();
    process.exit(opts.description ? 0 : 1);
  }

  runTriage(opts)
    .then(() => process.exit(0))
    .catch(err => {
      console.error(`\nFATAL: ${err.message}`);
      process.exit(1);
    });
}

// ---------------------------------------------------------------------------
// 23. Exports (for programmatic use)
// ---------------------------------------------------------------------------

module.exports = {
  runTriage,
  detectEnvironment,
  detectRuntime,
  collectLogs,
  recordReproduction,
  searchSource,
  searchGitHub,
  detectDuplicate,
  assessConfidence,
  evaluateStopConditions,
  createGitHubIssue,
  commentOnIssue,
  createFixWorktree,
  applyFix,
  runTests,
  commitAndPush,
  createPullRequest,
  verifyOriginalCheckout,
  isAllowedWritePath,
  redactSecrets,
  gitLogFile,
  gitBlame,
  readSourceFile,
  detectGitRemotes,
  shellQuote,
  REPO_ROOT,
  BUG_TRIAGE_DIR,
};
