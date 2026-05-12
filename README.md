# guardia

<p align="center">
  <img src="guardia.jpg" alt="guardia"/>
</p>

<p align="center">
  <a href="https://github.com/pmsosa/guardia"><img src="https://badgen.net/badge/version/0.1.0/blue" alt="version"></a>
  <a href="https://github.com/pmsosa/guardia/blob/main/LICENSE"><img src="https://badgen.net/github/license/pmsosa/guardia" alt="license"></a>
  <a href="https://github.com/pmsosa/guardia"><img src="https://badgen.net/badge/python/3.10%2B/green" alt="python"></a>
  <a href="https://github.com/pmsosa/guardia/stargazers"><img src="https://badgen.net/github/stars/pmsosa/guardia" alt="stars"></a>
</p>

**Multi-layered security analysis for packages, repositories, and local directories.**

`guardia` combines antivirus scanning (ClamAV), static heuristic analysis, supply chain inspection, and AI-powered code review (Claude) to produce a structured risk report before you install or run third-party code.

---

## Features

- **Homebrew formula analysis** — fetches and inspects formula source + source archive
- **Git repository cloning** — shallow-clones and audits any public or private repo
- **Local directory scanning** — analyze code you've already downloaded
- **ClamAV integration** — known malware signature detection (optional, graceful skip)
- **Static analysis** — 30+ heuristic patterns across shell, Python, Ruby, JS, and more
- **Supply chain checks** — dependency URLs, SHA256 integrity, fork detection, binary vs. source
- **AI code review** — Claude-powered behavioral assessment via Anthropic API or Claude CLI
- **Deep mode** — sliding-window batch analysis for large codebases
- **Structured output** — terminal (rich), JSON, or Markdown

---

## Installation

### Prerequisites

- Python 3.10+
- [Optional] ClamAV: `brew install clamav`
- [Optional] Anthropic API key **or** Claude CLI: `brew install --cask claude`

### Install guardia

```bash
# From source
git clone https://github.com/pmsosa/guardia
cd guardia
pip install -e .

# With Anthropic SDK (for API-key-based AI review)
pip install -e ".[ai]"
```

---

## Usage

```
guardia [OPTIONS]

Target (one required):
  --brew FORMULA    Analyze a Homebrew formula
  --git URL         Clone and analyze a remote Git repository
  --local PATH      Analyze a local directory or file

Options:
  --deep                  Run thorough Claude review (more tokens, higher cost)
  --chunking [sliding-window|file-by-file]
                          Deep-review chunking strategy (default: sliding-window)
  -o, --output [terminal|json|markdown]
                          Output format (default: terminal)
  --no-clam               Skip ClamAV antivirus scan
  --no-ai                 Skip Claude AI code review
  --cache                 Return cached result if available
  --force                 Ignore cache and re-run all checks
  -v, --verbose           Print step-by-step progress
  -q, --quiet             Only print the final verdict
  -V, --version           Show version
  -h, --help              Show this message and exit
```

### Examples

```bash
# Check a Homebrew formula
guardia --brew wyattjoh/claude-code-notification

# Check a GitHub repo
guardia --git https://github.com/wyattjoh/claude-code-notification

# Check a local download
guardia --local ~/Downloads/some-package

# Deep AI review, JSON output, skip ClamAV
guardia --git https://github.com/example/tool --deep --no-clam --output json

# Quiet mode — just the verdict
guardia --brew ffmpeg --quiet

# Cache-aware re-scan
guardia --brew ffmpeg --cache
```

---

## AI Review Backends

guardia auto-detects which Claude backend to use at startup:

| Priority | Condition | Backend |
|---|---|---|
| 1 | `ANTHROPIC_API_KEY` set in environment | Anthropic SDK (direct API) |
| 2 | `claude` binary found in PATH | Claude Code CLI (`claude -p` mode) |
| 3 | Neither | AI review skipped gracefully |

You can override the preference in `~/.guardia/config.toml`:

```toml
[api]
anthropic_key = ""        # or set ANTHROPIC_API_KEY env var
claude_backend = "auto"   # "auto" | "api" | "cli"
```

---

## Configuration

Config is stored in `~/.guardia/config.toml` and created automatically on first run:

```toml
[api]
anthropic_key = ""
claude_backend = "auto"

[defaults]
output_format = "terminal"
use_cache = true
cache_ttl_days = 7
deep_review = false
chunking_strategy = "sliding_window"

[clam]
enabled = true
freshclam_on_run = false

[thresholds]
repo_age_warn_days = 30
repo_stars_warn_below = 10
```

---

## Sample Output

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  guardia report
  Target:  wyattjoh/claude-code-notification (brew)
  Scanned: 2026-05-12 10:42:01 UTC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  [✓] Metadata & Reputation     LOW
      Repo age: 2y | Stars: 143 | Contributors: 4

  [✓] ClamAV Scan               CLEAN
      12 file(s) scanned. No threats detected.

  [⚠] Static Analysis           MEDIUM
      18 file(s) scanned. 1 flag(s).

  [✓] Supply Chain              LOW
      2 dependencies. No flags.

  [✓] Claude AI Review          LOW  [via api]
      This package adds desktop notifications for Claude Code events.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ✓ OVERALL VERDICT: LOW — Likely safe to install
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean or Low risk |
| `1` | Medium risk or non-fatal error |
| `2` | High risk |
| `3` | Critical risk |

This makes guardia composable in shell scripts and CI pipelines:

```bash
guardia --brew some-tool --no-ai --output json && echo "safe to proceed"
```

---

## Caching

Results are cached in `~/.guardia/cache/` keyed by a SHA256 hash of all scanned files. Cache entries expire after 7 days (configurable). Use `--force` to bypass the cache entirely.

---

## Telemetry

None. guardia collects no telemetry or usage data of any kind.

---

## License

BSD 3-Clause — see [LICENSE](LICENSE).
