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

`guardia` combines antivirus scanning (ClamAV), static heuristic analysis, IP reputation lookup, VirusTotal hash checks, supply chain inspection, and AI-powered code review (Claude) to produce a structured risk report before you install or run third-party code.

---

## Features

- **Homebrew formula analysis** — fetches and inspects formula source + source archive
- **Git repository cloning** — shallow-clones and audits any public or private repo
- **Local directory scanning** — analyze code you've already downloaded
- **ClamAV integration** — known malware signature detection (optional, graceful skip)
- **Static analysis** — 30+ heuristic patterns across shell, Python, Ruby, JS, and more
- **IP reputation** — AbuseIPDB batch lookup for any hardcoded IPs found in code (single API call)
- **VirusTotal hash check** — looks up the artifact SHA256 against 70+ AV engines; no upload needed for known files
- **Supply chain checks** — dependency URLs, SHA256 integrity, fork detection, binary vs. source
- **AI code review** — Claude-powered behavioral assessment via Anthropic API or Claude CLI, guided by a static analysis pre-digest
- **Deep mode** — sliding-window batch analysis for large codebases
- **Structured output** — terminal (rich), JSON, or Markdown

---

## Installation

### Prerequisites

- Python 3.10+
- [Optional] ClamAV: `brew install clamav`
- [Optional] Anthropic API key **or** Claude CLI: `brew install --cask claude`
- [Optional] AbuseIPDB API key — [get one free](https://www.abuseipdb.com/register)
- [Optional] VirusTotal API key — [get one free](https://www.virustotal.com/gui/join-us)

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
  --vt-upload             Upload unknown binary artifacts to VirusTotal
                          (requires explicit consent — sends file to third party)
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

# Upload unknown binary to VirusTotal (confirms before sending)
guardia --brew some-cask --vt-upload
```

---

## Setup

Run the interactive setup wizard to configure all optional integrations:

```bash
guardia --setup
```

The wizard walks through four steps:

1. **ClamAV** — installs if missing, updates virus definitions
2. **AbuseIPDB** — paste your API key to enable IP reputation checks ([get key](https://www.abuseipdb.com/register))
3. **VirusTotal** — paste your API key to enable artifact hash lookups ([get key](https://www.virustotal.com/gui/join-us))
4. **AI backend** — configure Anthropic API key or Claude CLI for code review

All keys are saved to `~/.guardia/config.toml`. You can also set them via environment variables (`ABUSEIPDB_API_KEY`, `VT_API_KEY`, `ANTHROPIC_API_KEY`) without touching the config file.

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

The AI reviewer receives a **static analysis pre-digest** — a filtered summary of the highest-confidence flags (pipe-to-shell, obfuscation, sensitive file access, etc.) with code snippets — so it can focus on confirming or dismissing real issues rather than rediscovering noise.

---

## Configuration

Config is stored in `~/.guardia/config.toml` and created automatically on first run:

```toml
[api]
anthropic_key = ""        # or ANTHROPIC_API_KEY env var
claude_backend = "auto"   # "auto" | "api" | "cli"
abuseipdb_key = ""        # or ABUSEIPDB_API_KEY env var
virustotal_key = ""       # or VT_API_KEY env var

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

[abuseipdb]
enabled = true
max_age_days = 30       # how far back to look for abuse reports
min_score_warn = 11     # score threshold for a warning flag
min_score_critical = 51 # score threshold for a critical flag

[virustotal]
enabled = true
allow_upload = false    # must also pass --vt-upload at CLI to actually upload
```

---

## Sample Output

```
  ⛨  guardia  v0.1.0  ·  security analysis

  ╭──────────────────────────────────────────────────────────╮
  │  Target:   wyattjoh/claude-code-notification  (brew)     │
  │  Scanned:  2026-05-13 10:42 UTC                          │
  ╰──────────────────────────────────────────────────────────╯

  ─────────────────────── scan results ───────────────────────

  [✓] Metadata & Reputation          LOW
      Repo age: 2y | Stars: 143 | Contributors: 4
  [✓] ClamAV Scan                    CLEAN
      12 file(s) scanned. No threats detected.
  [⚠] Static Analysis                MEDIUM
      18 file(s) scanned. 1 flag(s).
  [✓] Supply Chain                   LOW
      2 dependencies. No flags.
  [–] IP Reputation (AbuseIPDB)      SKIPPED
      No hardcoded public IPs found
  [✓] VirusTotal                     LOW
      0/72 engines — clean
  [✓] Claude AI Review               LOW  [via api]
      This package adds desktop notifications for Claude Code events.

  ┏━━━━━━━━━━━━━━━━━━━━━━ verdict ━━━━━━━━━━━━━━━━━━━━━━━┓
  ┃  ✓  LOW  Likely safe to install                       ┃
  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

---

## VirusTotal Privacy Model

By default guardia does a **hash-only lookup** — it sends only the SHA256 of the artifact (already present in the Homebrew formula) to VirusTotal, never the file itself. This costs one API call and reveals nothing about the file's contents.

If the hash is unknown to VirusTotal (new or obscure package) and the target is a pre-built binary, you can opt into uploading:

```bash
guardia --brew some-cask --vt-upload
```

guardia will warn you and ask for confirmation before uploading. Source code archives (`.rb`, `.py`, `.sh`, `.tar.gz` containing text, etc.) are never uploaded — VirusTotal's AV engines don't meaningfully scan source.

For git/local targets without a known hash, VirusTotal is skipped automatically.

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
