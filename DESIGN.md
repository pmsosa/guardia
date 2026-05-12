# guardia — Design Document

**Version:** 0.3  
**Status:** Draft  
**Author:** Pedro (concept), Claude (documentation)

---

## 1. Overview

`guardia` is a command-line security analysis tool that evaluates packages, repositories, and local directories for malicious or suspicious software before installation or execution. It combines antivirus scanning (ClamAV), static analysis heuristics, and AI-powered code review (Claude API) to produce a structured risk report.

The tool is designed for developers and security-conscious users who want a fast, repeatable, and opinionated second opinion before trusting third-party code.

---

## 2. Goals

- Provide a single command that performs multi-layered security analysis on any software source
- Integrate ClamAV for known malware signatures
- Use Claude for high-level code review and behavioral risk assessment
- Surface supply chain red flags (binary vs. source, dependency chains, metadata anomalies)
- Be fast for simple checks, thorough for deep ones
- Produce output that is readable by humans and parseable by machines

### Non-Goals (v0.1)

- Real-time monitoring or continuous scanning
- Windows support (macOS and Linux only initially)
- Package manager coverage beyond Homebrew (npm, pip, cargo extensions planned for later)
- Sandboxed execution / dynamic analysis

---

## 3. CLI Interface

### Usage

```
guardia [OPTIONS] TARGET
```

### Flags

| Flag | Description |
|---|---|
| `--brew <formula>` | Analyze a Homebrew formula by name (e.g. `ffmpeg`, `org/tap/formula`) |
| `--git <url>` | Clone and analyze a remote Git repository |
| `--local <path>` | Analyze a local directory or file |
| `--deep` | Run a thorough Claude review (more tokens, more time, higher cost) |
| `--output <format>` | Output format: `terminal` (default), `json`, `markdown` |
| `--no-clam` | Skip ClamAV scan (useful if not installed) |
| `--no-ai` | Skip Claude review (offline or API-key-free mode) |
| `--cache` | Use cached results for previously scanned targets (keyed by content hash) |
| `--force` | Ignore cache and re-run all checks |
| `--verbose` | Print detailed step-by-step progress |
| `--quiet` | Only print the final verdict |

### Examples

```bash
# Check a Homebrew formula
guardia --brew wyattjoh/claude-code-notification

# Check a GitHub repo
guardia --git https://github.com/wyattjoh/claude-code-notification

# Check a locally downloaded directory
guardia --local ~/Downloads/some-package

# Deep AI review, JSON output, no ClamAV
guardia --git https://github.com/example/tool --deep --no-clam --output json
```

---

## 4. Architecture

### 4.1 High-Level Pipeline

```
Input (--brew / --git / --local)
        │
        ▼
[1] Resolve & Fetch
        │
        ▼
[2] Metadata & Reputation Check
        │
        ▼
[3] ClamAV Antivirus Scan
        │
        ▼
[4] Static Analysis (Heuristics)
        │
        ▼
[5] Supply Chain Analysis
        │
        ▼
[6] Claude AI Code Review
        │
        ▼
[7] Report Generation
```

### 4.2 Module Breakdown

---

#### Module 1 — Resolve & Fetch

**Purpose:** Normalize the input into a local directory of source files for analysis.

**Brew input:**
- Run `brew cat <formula>` to retrieve the Ruby formula source
- Parse the formula to extract: source URL, SHA256, dependencies, install hooks, caveats
- Optionally download the source archive into a temp directory for deeper inspection

**Git input:**
- Shallow clone (`--depth=1`) into a temp directory
- Respect `.gitignore` but still flag hidden files or unusual directory structures

**Local input:**
- Use the provided path directly
- Recursively walk the directory; build a file manifest

**Output:** Temp working directory + normalized metadata object

---

#### Module 2 — Metadata & Reputation

**Purpose:** Build a risk profile from public signals before touching any code.

**Checks:**

| Signal | Data Source | Risk Implication |
|---|---|---|
| Repository age | GitHub API | Repos < 30 days old are higher risk |
| Star / fork count | GitHub API | Low engagement on claimed-popular tools is suspicious |
| Contributor count | GitHub API | Single-contributor with no history is higher risk |
| Commit recency | GitHub API | Abandoned repos with sudden new releases are suspicious |
| Domain match | Formula + GitHub org | Source URL domain should match the GitHub organization |
| License presence | Repo root | Missing LICENSE file is a minor flag |
| README presence | Repo root | Missing README is a minor flag |
| Binary vs. source | Formula analysis | Binary downloads carry higher risk than source compilation |

**Output:** Reputation score (Low / Medium / High risk) + flag list

---

#### Module 3 — ClamAV Antivirus Scan

**Purpose:** Detect known malware signatures in downloaded files.

**Requirements:**
- ClamAV installed (`brew install clamav`)
- Virus definitions up to date (`freshclam`)

**Behavior:**
- Run `clamscan -r --bell <temp_dir>` on the resolved source
- Parse stdout for infected file count and specific detections
- If ClamAV is not installed, warn the user and skip gracefully (do not fail)

**Output:** Clean / Infected + list of any flagged files

---

#### Module 4 — Static Analysis (Heuristics)

**Purpose:** Detect suspicious patterns in code without executing it.

**Pattern categories:**

| Category | Patterns to Flag |
|---|---|
| Shell execution | `eval`, `exec`, `system()`, backtick execution |
| Network calls | `curl`, `wget`, `fetch`, hardcoded IP addresses, non-HTTPS URLs |
| Obfuscation | Base64 decode chains, hex-encoded strings, `rot13`, unusual encoding |
| Exfiltration hints | Environment variable reads + outbound calls in same scope |
| Privilege escalation | `sudo`, `chmod 777`, `chown root`, setuid patterns |
| Install hooks | Homebrew `def install`, `post_install`, `caveats` — flag any shell commands within |
| Pipe to shell | `curl ... \| sh`, `wget ... \| bash` patterns |
| Hidden files/dirs | Files or dirs starting with `.` outside of expected config files |
| Unusual file types | Executables, `.dylib`, `.so` files embedded in source repos |

**Output:** List of flagged patterns with file path, line number, severity (Info / Warn / Critical)

---

#### Module 5 — Supply Chain Analysis

**Purpose:** Evaluate the trust chain beyond the immediate package.

**Checks:**

- **Dependency mapping:** List all declared dependencies (from formula or package manifest). Flag any dependency that is itself unverified or pulls from an unusual source.
- **Transitive depth:** Flag dependency trees deeper than 3 levels (difficult to audit manually)
- **Source URL integrity:** Verify that the download URL in the formula uses HTTPS and matches a known hosting domain (GitHub, GitLab, official project sites)
- **SHA256 verification:** Confirm the formula declares a checksum and that Homebrew's verification would pass
- **Fork detection:** Check if the repo is a fork — forks of popular tools with minor changes are a known attack vector
- **Release vs. commit:** Flag if the formula points to a raw commit SHA instead of a tagged release

**Output:** Supply chain risk summary + specific flags

---

#### Module 6 — Claude AI Code Review

**Purpose:** Use Claude to provide a high-level security assessment of the source code with reasoning.

**Backend detection (run at startup, in priority order):**

```
1. ANTHROPIC_API_KEY set in environment → use Anthropic SDK directly (API credits)
2. No API key, but `claude` binary found at /opt/homebrew/bin/claude or in PATH → use Claude Code CLI (-p mode)
3. Neither found → skip AI module gracefully, inform user
```

Detection logic (pseudocode):
```python
if os.environ.get("ANTHROPIC_API_KEY"):
    backend = "api"
elif shutil.which("claude"):
    backend = "cli"
else:
    backend = None  # AI review unavailable, warn and skip
```

The report should indicate which backend was used (e.g. `Claude: ✓ LOW RISK  [via claude CLI]`).

---

**Claude Code CLI backend (`claude -p`):**

The Claude Code CLI supports a non-interactive print mode ideal for scripting:

```bash
cat formula.rb | claude -p "Review this for security issues" --output-format json
```

The JSON response includes the result text, cost, duration, and session ID — cleaner to parse than interactive output.

⚠️ **Known issue:** `claude -p` can hang when invoked as a subprocess without a TTY. The developer must handle this explicitly. Recommended workaround on macOS:

```bash
script -q /dev/null claude -p "..." --output-format json
```

Alternatively, use a pseudo-TTY via Python's `pty` module when spawning the subprocess. Set a hard timeout (e.g. 60 seconds) and treat a hang as a skipped module rather than a crash.

---

**Anthropic SDK backend:**

Standard HTTP call to `/v1/messages` using the `anthropic` Python SDK. Preferred when an API key is available — more reliable, no TTY issues, structured output.

---

**Review depth:**

**Standard (default):**
- Send the formula source + top-level source files (up to ~8,000 tokens)
- Prompt focuses on: intent of the code, suspicious behaviors, unusual permissions, unexpected network activity, install hook analysis

**Deep (`--deep`):**
- Send all source files in batches using a sliding window strategy (configurable to file-by-file)
- Claude analyzes each batch and produces a consolidated risk report
- Significantly more thorough; appropriate for unknown or high-stakes packages

---

**Prompt design:**

```
You are a security-focused code reviewer. Your task is to analyze the following 
source code for malicious, suspicious, or unsafe behavior.

Focus on:
1. What does this code actually do? (behavioral summary)
2. Does it access the network? If so, where and why?
3. Does it read or write sensitive files or environment variables?
4. Are there any obfuscation techniques in use?
5. Do the install hooks do anything unexpected?
6. Are there any patterns consistent with malware, spyware, or supply chain attacks?

Respond with:
- RISK LEVEL: [Low / Medium / High / Critical]
- SUMMARY: (2-3 sentences)
- FLAGS: (bulleted list of specific concerns, each with file and line if applicable)
- VERDICT: (one sentence, plain language)
```

**Output:** Structured Claude response parsed into risk level, summary, flags, and verdict

---

#### Module 7 — Report Generation

**Purpose:** Aggregate all module outputs into a final, readable report.

**Terminal output (default):**

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  guardia report
  Target: wyattjoh/claude-code-notification (brew)
  Scanned: 2026-05-12 10:42:01
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [✓] Metadata & Reputation     LOW RISK
      Repo age: 2 years | Stars: 143 | Contributors: 4

  [✓] ClamAV Scan               CLEAN
      12 files scanned. No threats detected.

  [⚠] Static Analysis           WARN
      1 flag: curl call in install hook (non-critical, common pattern)

  [✓] Supply Chain              LOW RISK
      2 dependencies. Source URL matches GitHub org. SHA256 present.

  [✓] Claude Review             LOW RISK
      "This package adds desktop notifications for Claude Code events.
       It accesses no sensitive files and makes no unexpected network calls."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  OVERALL VERDICT: LOW RISK — Likely safe to install
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**JSON output (`--output json`):**

```json
{
  "target": "wyattjoh/claude-code-notification",
  "type": "brew",
  "timestamp": "2026-05-12T10:42:01Z",
  "overall_risk": "low",
  "modules": {
    "metadata": { "risk": "low", "flags": [] },
    "clamav": { "risk": "clean", "files_scanned": 12, "infected": [] },
    "static_analysis": { "risk": "warn", "flags": [...] },
    "supply_chain": { "risk": "low", "flags": [] },
    "claude_review": { "risk": "low", "summary": "...", "verdict": "..." }
  }
}
```

**Markdown output (`--output markdown`):** Full report suitable for saving to disk, sharing with a team, or including in a PR review.

---

## 5. Caching

- After a successful scan, hash the full source content (SHA256 of all files combined)
- Store result in `~/.guardia/cache/<hash>.json`
- On subsequent runs with `--cache`, check the hash first and return the cached report immediately
- Cache entries expire after 7 days by default
- `--force` bypasses cache entirely

---

## 6. Configuration

Store user config in `~/.guardia/config.toml`:

```toml
[api]
anthropic_key = ""          # or read from ANTHROPIC_API_KEY env var

[defaults]
output_format = "terminal"
use_cache = true
cache_ttl_days = 7
deep_review = false

[clam]
enabled = true
freshclam_on_run = false    # auto-update definitions before each scan

[thresholds]
repo_age_warn_days = 30
repo_stars_warn_below = 10
```

---

## 7. Dependencies

| Dependency | Purpose | Required |
|---|---|---|
| Python 3.10+ | Runtime | Yes |
| `click` | CLI framework | Yes |
| `requests` | HTTP (GitHub API) | Yes |
| `GitPython` | Git clone operations | Yes |
| `anthropic` | Claude API SDK (API backend) | No (used if API key present) |
| `toml` | Config file parsing | Yes |
| `clamav` (system) | Antivirus scanning | No (graceful skip) |
| `rich` | Terminal formatting | Recommended |
| `claude` CLI (system) | Claude Code CLI (CLI backend) | No (used if installed, no API key) |

---

## 8. Error Handling

| Scenario | Behavior |
|---|---|
| ClamAV not installed | Warn, offer to install via Homebrew, skip if declined |
| GitHub API rate limit hit | Warn, skip reputation module, continue |
| No API key and no `claude` CLI | Warn, skip AI module, continue with ClamAV + static analysis |
| `claude -p` hangs (no TTY) | Timeout after 60s, warn, skip AI module, continue |
| Claude API unavailable | Warn, skip AI module, continue |
| Invalid brew formula name | Exit with clear error message |
| Git clone failure | Exit with clear error message |
| Network unavailable | Skip all remote checks, analyze local files only if `--local` |

The tool should never hard-crash silently. Every failure path should produce a human-readable message explaining what was skipped and why.

---

## 9. Future Extensions (Post v0.1)

| Feature | Notes |
|---|---|
| `--npm <package>` | Extend to npm registry packages |
| `--pip <package>` | Extend to PyPI packages |
| `--cargo <crate>` | Extend to Rust crates |
| Dynamic analysis | Sandbox execution and observe system calls (significant scope increase) |
| CI/CD integration | GitHub Action or pre-commit hook that runs `guardia` automatically |
| Team shared cache | Shared cache server so a team doesn't re-scan the same packages |
| Web UI | Simple dashboard for viewing past scan reports |
| Diff mode | Compare two versions of the same package to surface what changed between releases |
| Webhook alerts | Post results to Slack/Teams when a scan exceeds a risk threshold |

---

## 10. Design Decisions (Resolved)

The following questions have been answered and should be treated as implementation requirements.

**1. API Key / Claude Backend**

guardia supports two backends for AI review, detected automatically at startup:

- **Anthropic API** (preferred): if `ANTHROPIC_API_KEY` is set in the environment, use the SDK directly. Prompt for the key on first run if absent and store in `~/.guardia/config.toml`.
- **Claude Code CLI** (fallback): if no API key is found but the `claude` binary is available (e.g. installed via `brew install --cask claude-code`), use `claude -p` print mode. This works with a Claude Pro or Max subscription — no separate API key required.
- **No AI**: if neither is available, skip the AI module entirely and inform the user. The tool remains fully functional with ClamAV + static analysis only.

The report should indicate which backend was used for transparency.

Config preference can be forced via `~/.guardia/config.toml`:
```toml
[api]
anthropic_key = ""           # leave blank to rely on env var
claude_backend = "auto"      # "auto" | "api" | "cli"
```

**2. ClamAV Auto-Install**

- On startup, check whether ClamAV is installed (`which clamscan`)
- If not found, prompt the user: *"ClamAV is not installed. Would you like guardia to install it via Homebrew? (y/n)"*
- If definitions are outdated (older than 24 hours), prompt: *"ClamAV definitions are X days old. Update now? (y/n)"*
- Never install or update silently — always ask first

**3. Token Chunking Strategy for Deep Mode**

- Default chunking strategy: **sliding window** (overlap between chunks to avoid missing context at boundaries)
- Allow user to override via config: `chunking_strategy = "sliding_window"` or `"file_by_file"`
- File-by-file available as `--chunking file-by-file` CLI flag for users who prefer it

**4. Risk Aggregation & Report Format**

- Overall verdict = highest risk level across all modules (if any module flags Critical, the overall is Critical)
- Final report output format (terminal):

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  guardia report
  Target: wyattjoh/claude-code-notification (brew)
  Scanned: 2026-05-12 10:42:01
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Status:  ✓ LOW RISK
  ClamAV:  ✓ CLEAN
  Claude:  ✓ LOW RISK

  Reason: This package installs a lightweight notification hook for Claude
          Code. It makes no unexpected network calls and accesses no
          sensitive system files.

  Issues:
    · install.rb:14  — curl call in install hook (common, non-critical)
    · formula.rb:8   — binary download (no source compilation)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

  The `Reason` field is a short AI-generated plain-language blurb (2-3 sentences max).
  The `Issues` field is a bulleted list with `file:linenumber` references where applicable.
  If no issues are found, the Issues section is omitted entirely.

**5. Telemetry**

- None. No data collection of any kind in v0.1.

---

## 11. Future Extensions (Post v0.1)

| Feature | Notes |
|---|---|
| `--npm <package>` | Extend to npm registry packages |
| `--pip <package>` | Extend to PyPI packages |
| `--cargo <crate>` | Extend to Rust crates |
| Dynamic analysis | Sandbox execution and observe system calls (significant scope increase) |
| CI/CD integration | GitHub Action or pre-commit hook that runs `guardia` automatically |
| Team shared cache | Shared cache server so a team doesn't re-scan the same packages |
| Web UI | Simple dashboard for viewing past scan reports |
| Diff mode | Compare two versions of the same package to surface what changed between releases |
| Webhook alerts | Post results to Slack/Teams when a scan exceeds a risk threshold |

---

*Document version 0.3 — dual-path AI backend added, ready for developer handoff.*