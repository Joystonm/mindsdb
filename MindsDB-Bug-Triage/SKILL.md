---
name: mindsdb-bug-triage
description: Investigate MindsDB bugs using local diagnostics, logs, source-code analysis and GitHub issue/PR research, then create safe fix pull requests without modifying the MindsDB checkout directly.
trigger: User reports a MindsDB bug, error, failure, regression, or asks to run bug triage.
---

# MindsDB Bug Triage Skill

## Safety Contract

> **The MindsDB repository is read-only. Never edit an existing MindsDB file.**
> **All local implementation files belong inside `MindsDB-Bug-Triage/`.**

The existing MindsDB source tree is the *subject being analyzed*, not code this tool modifies.
Every write operation is validated against the allowed-path guard before execution.
The original MindsDB checkout must be `UNCHANGED` at the end of every run.

---

## Allowed vs. Forbidden Operations

### Allowed (read-only inspection)
- `cat`, `less`, `head`, `tail`, `grep`, `rg`, `find`
- `git show`, `git log`, `git blame`, `git diff`, `git status --short`
- `git remote -v`
- `python --version`, `node --version`, `docker --version`
- `docker ps`, `docker logs <container>`, `docker compose ps`, `docker compose logs`
- `pytest` (running tests, never modifying source)
- `python -m mindsdb` (running MindsDB, never modifying source)
- `gh auth status`, `gh issue list`, `gh pr list`, `gh api`

### Forbidden (source modification)
- `git checkout -- <file>`, `git restore <file>`, `git reset --hard`
- `sed -i`, `perl -pi`, `awk` with in-place editing
- Any Python/Node script that writes to the original MindsDB source tree
- `echo ... > existing-file`, `mv existing-file`, `rm existing-file`
- Direct edits to `mindsdb/`, `tests/`, `docs/`, `requirements/`, `.github/`, `docker/`, `pyproject.toml`, `setup.py`, `README.md`, `docker-compose.yml`

---

## Repository Layout (reference)

```
MindsDB/
├── mindsdb/                    # Main Python package (READ ONLY)
│   ├── __about__.py            # Version string
│   ├── __main__.py             # CLI entry point: python -m mindsdb
│   ├── api/
│   │   ├── http/               # Flask REST API  — port 47334
│   │   ├── mysql/              # MySQL wire protocol — port 47335
│   │   ├── mongo/              # MongoDB wire protocol — port 47336
│   │   ├── mcp/                # Model Context Protocol — port 47337
│   │   └── a2a/                # Agent-to-Agent — port 47338
│   ├── interfaces/
│   │   ├── agents/             # Agent execution
│   │   ├── model/              # ML model lifecycle
│   │   ├── knowledge_base/     # Knowledge bases (RAG)
│   │   ├── skills/             # Skill definitions
│   │   ├── jobs/               # Scheduled jobs
│   │   └── storage/            # SQLAlchemy ORM + migrations
│   ├── integrations/
│   │   ├── handlers/           # Data + ML/LLM handlers (100+ integrations)
│   │   └── libs/               # Base classes for handlers
│   └── utilities/
│       ├── config.py           # Config singleton (merges config.json + env vars + CLI)
│       ├── log.py              # Logging: RotatingFileHandler + console
│       └── fs.py               # Filesystem helpers, storage paths
├── tests/
│   ├── unit/                   # pytest unit tests
│   └── integration/            # pytest integration tests
├── docker/
│   ├── mindsdb.Dockerfile
│   └── mindsdb_config.release.json   # Default: root /root/mdb_storage
├── docker-compose.yml
├── pyproject.toml              # ruff config, build system
├── Makefile                    # make unit_tests / make integration_tests
├── requirements/
│   ├── requirements.txt
│   ├── requirements-test.txt
│   └── requirements-dev.txt
└── MindsDB-Bug-Triage/         # THIS TOOL ONLY (READ/WRITE)
    ├── SKILL.md
    └── bug_triage.js
```

**Default log location (Python/Docker):** configured via `config.paths["log"]`, defaults to `/root/mdb_storage/logs/` or `~/.local/share/mindsdb/logs/` depending on `appdirs`.

**Default storage root:** `/root/mdb_storage` (Docker) or OS-appropriate user data dir (bare Python).

---

## Workflow

```
User reports MindsDB problem
         │
         ▼
Stage 1  Environment Detection
         │  OS, arch, Node, Python, MindsDB version, Git commit/branch,
         │  install method, Docker availability
         ▼
Stage 2  Runtime Detection
         │  Python process / Docker / Docker Compose / CLI / systemd
         ▼
Stage 3  Log Collection
         │  Locate logs → targeted search for errors/exceptions/tracebacks
         │  Redact secrets before saving/reporting
         ▼
Stage 4  Reproduction
         │  Record: command, input, expected, actual, error
         │  Prefer actual reproduction over speculation
         ▼
Stage 5  Source Code Analysis (READ ONLY)
         │  Trace execution path, identify failing function/component
         │  Use git log/blame for history context
         ▼
Stage 6  GitHub Research
         │  Search issues + PRs for duplicate / regression
         │  If duplicate found: enrich existing issue, stop
         ▼
Root Cause Assessment
         │  Confidence: HIGH / MEDIUM / LOW
         │  LOW → explain, stop, do not attempt fix
         ▼
Create / Update GitHub Issue
         ▼
Stage 7  Fix Preparation (only if HIGH or MEDIUM confidence)
         │  git worktree add <external-path> -b fix/<name> <base>
         │  Apply minimal fix in worktree (NEVER in original checkout)
         ▼
Stage 8  Test
         │  Run relevant pytest tests in worktree
         │  Report: executed / passed / failed / skipped
         ▼
Stage 9  Commit & Push
         │  Conventional commit message (no AI wording)
         │  Push to user fork
         ▼
Stage 10 Pull Request
         │  Target: upstream mindsdb/mindsdb
         │  Contains: summary, root cause, fix, reproduction, tests, issue ref
         ▼
Stage 11 Verify Original Checkout
         │  git status --short must show no changes to original MindsDB files
         ▼
Final Report
```

---

## Stop Conditions

Stop before fixing if any of the following apply:

- Root cause confidence is LOW
- Reproduction failed
- Multiple competing hypotheses remain
- The problem is in an upstream dependency
- The fix requires architectural changes
- Security implications are unclear
- The fix could cause data loss
- The required regression tests cannot be determined

Explain what evidence is missing and what would be needed to proceed.

---

## Root Cause Confidence Levels

| Level  | Meaning |
|--------|---------|
| HIGH   | Exact source path and mechanism confirmed |
| MEDIUM | Strong evidence; full confirmation unavailable |
| LOW    | Multiple hypotheses or reproduction unavailable |

Never attempt a fix at LOW confidence.

---

## Duplicate Issue Handling

If an existing GitHub issue matches the problem:

1. Compare MindsDB version, commit, OS, and reproduction steps.
2. If it is the same root cause: do **not** create a new issue.
3. Add a comment with new evidence (version, logs, reproduction — redacted).
4. Reference the existing issue in any eventual PR.

---

## Secret Redaction

Before writing anything to GitHub (issues, comments, PR descriptions):

- Passwords, API keys, tokens, JWTs
- Database connection strings
- Cloud credentials (AWS, GCP, Azure)
- Authorization / Bearer headers
- Private hostnames and URLs
- Any value matching `(?i)(password|secret|token|key|auth|bearer|credential)\s*[=:]\s*\S+`

Replace with `[REDACTED]`.

---

## GitHub Issue Template

```markdown
## Bug

<one-line summary>

## Environment

- MindsDB version:
- Commit:
- OS:
- Python:
- Installation: pip / Docker / Docker Compose / source
- Component: api/http | api/mysql | integrations/handlers/<name> | interfaces/<name> | other

## Expected Behavior

...

## Actual Behavior

...

## Reproduction

1.
2.
3.

## Error

```
<redacted stack trace>
```

## Root Cause

...

## Confidence

High / Medium / Low

## Proposed Fix

...

## Testing

...
```

---

## Pull Request Template

```markdown
## Summary

...

## Root Cause

...

## Fix

...

## Reproduction

...

## Tests

Tests executed:
Tests passed:
Tests failed:
Tests skipped:

## Related Issue

Fixes #<number>
```

---

## Final Report Format

```
MindsDB Bug Triage
══════════════════════════════════════════════════════

Repository:        <remote URL>
MindsDB version:   <version from mindsdb/__about__.py>
Commit:            <git rev-parse HEAD>
Environment:       <OS> / Python <ver> / <install method>

Reproduced:        YES / NO / PARTIAL

Root Cause:        <description>

Confidence:        HIGH / MEDIUM / LOW

GitHub Issue:      <URL or "none — duplicate of #N">

Fix:               <description or "none — stopped: <reason>">

Tests:
  Executed:  N
  Passed:    N
  Failed:    N
  Skipped:   N

Pull Request:      <URL or "none">

Original MindsDB checkout: UNCHANGED
```

The final line **`Original MindsDB checkout: UNCHANGED`** is mandatory and must be verified by running `git status --short` in the original checkout directory before it is printed.

---

## Implementation

The automation is in `MindsDB-Bug-Triage/bug_triage.js`.

Run with Node.js:

```bash
node MindsDB-Bug-Triage/bug_triage.js [options]
```

The script enforces the filesystem safety guard (`isAllowedWritePath`) before every write operation and refuses any path outside:

1. `<repo-root>/MindsDB-Bug-Triage/`
2. The temporary external worktree created for the current fix

See `bug_triage.js` for the full API.
