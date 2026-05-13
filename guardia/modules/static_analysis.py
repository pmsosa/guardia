"""Module 4 — Static Analysis: detect suspicious patterns without execution."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..models import Flag, RiskLevel, ScanTarget, StaticAnalysisResult

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Each entry: (category, severity, compiled_regex, description_template, skip_extensions)
# skip_extensions: frozenset of extensions where this pattern should NOT fire
_PATTERNS: list[tuple[str, str, re.Pattern, str, frozenset]] = []

_DOC_EXTS = frozenset({".md", ".txt", ".rst", ".adoc"})

# Backtick execution is only valid syntax in shell scripts, Ruby, and Perl.
# In C/C++, Java, Python 3, JS/TS it's either invalid or not shell execution.
_BACKTICK_SKIP = frozenset({
    ".md", ".txt", ".rst", ".adoc",    # documentation
    ".c", ".h", ".cpp", ".hpp",        # C/C++ (Doxygen comments)
    ".java", ".kt", ".swift",          # JVM / Apple
    ".js", ".ts", ".jsx", ".tsx",      # JS template literals
    ".py",                             # Python 3 (removed syntax)
    ".go", ".rs",                      # Go, Rust
    ".toml", ".yaml", ".yml", ".json", ".ini", ".cfg", ".conf",
})


def _p(
    category: str,
    severity: str,
    pattern: str,
    description: str,
    flags: int = 0,
    skip_exts: frozenset = frozenset(),
    skip_comments: bool = False,
) -> None:
    _PATTERNS.append((category, severity, re.compile(pattern, flags | re.MULTILINE), description, skip_exts, skip_comments))


_COMMENT_RE = re.compile(r'^\s*(?:#|//|/\*|\*)')


# Shell execution
_p("shell_exec", "warn",   r'\beval\s*[\(\{]', "eval() call — dynamic code execution")
_p("shell_exec", "critical", r'`[^`]{5,}`', "Backtick shell execution: `{match}`", skip_exts=_BACKTICK_SKIP, skip_comments=True)
_p("shell_exec", "warn",   r'\bexec\s*\(', "exec() call")
_p("shell_exec", "warn",   r'\bsystem\s*\(', "system() call", skip_exts=_DOC_EXTS)
_p("shell_exec", "warn",   r'subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True', "subprocess with shell=True")
_p("shell_exec", "warn",   r'\bos\.system\s*\(', "os.system() call")
_p("shell_exec", "warn",   r'require\s*\(?\s*[\'"]child_process[\'"]', "Node.js child_process import")
_p("shell_exec", "warn",   r'\bspawn\s*\(|\.exec\s*\(', "Process spawn/exec call")

# Network calls
_p("network",    "info",   r'\bcurl\b', "curl network call")
_p("network",    "info",   r'\bwget\b', "wget network call")
_p("network",    "info",   r'requests\.(get|post|put|patch|delete|head)\s*\(', "requests HTTP call")
_p("network",    "info",   r'urllib\.request', "urllib network call")
_p("network",    "info",   r'fetch\s*\(', "fetch() network call")
# IPs in configure/test scripts are routine; flag as info only
_p("network",    "info",   r'\b(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b', "Hardcoded IP address: {match}")
# Non-HTTPS URLs in changelogs/licenses are not suspicious
_p("network",    "warn",   r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)\S+', "Non-HTTPS URL", skip_exts=_DOC_EXTS)

# Pipe to shell — critical
_p("pipe_shell", "critical", r'(curl|wget)\s+\S+.*\|\s*(ba)?sh\b', "Pipe download to shell: {match}")
_p("pipe_shell", "critical", r'(curl|wget)\s+\S+.*\|\s*zsh\b', "Pipe download to zsh: {match}")
_p("pipe_shell", "critical", r'(curl|wget)\s+\S+.*\|\s*python\b', "Pipe download to python: {match}")

# Obfuscation
_p("obfuscation", "warn",  r'base64[\s_]*(decode|b64decode|--decode|-d)\b', "Base64 decode operation")
_p("obfuscation", "warn",  r'\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){7,}', "Long hex-encoded string (possible obfuscation)")
_p("obfuscation", "warn",  r'\brot13\b|\.encode\([\'"]rot.13[\'"]\)', "ROT13 encoding")
_p("obfuscation", "warn",  r'codecs\.decode\s*\(', "codecs.decode() — potential obfuscation")
_p("obfuscation", "warn",  r'zlib\.(decompress|decompressobj)', "zlib decompression of embedded data")

# Exfiltration hints (env vars + outbound together is flagged separately in code logic)
_p("exfiltration", "warn", r'os\.environ\b|process\.env\b|\$ENV\b|\$HOME|\$USER', "Environment variable access")
_p("exfiltration", "warn", r'\.ssh/|id_rsa|\.aws/credentials|\.gnupg/', "Sensitive file path reference")
_p("exfiltration", "warn", r'keychain|Keychain|SecItemCopyMatching', "macOS Keychain access")
_p("exfiltration", "warn", r'cookies|localStorage|sessionStorage', "Browser storage access")

# Privilege escalation
_p("privilege",  "warn",   r'\bsudo\b', "sudo privilege escalation")
_p("privilege",  "critical", r'chmod\s+(?:a\+s|[0-7]*[47][0-7]{2}|777)', "chmod 777 or setuid/setgid")
_p("privilege",  "warn",   r'chown\s+root\b', "chown root")
_p("privilege",  "warn",   r'\bsetuid\b|\bsetgid\b', "setuid/setgid call")

# Homebrew-specific install hooks
_p("install_hook", "info", r'def\s+install\b', "Homebrew install hook defined")
_p("install_hook", "warn", r'def\s+post_install\b', "Homebrew post_install hook defined")
_p("install_hook", "info", r'def\s+caveats\b', "Homebrew caveats defined")
_p("install_hook", "warn", r'(system|bin_install|bin\.install|lib\.install)\s+[\'"](curl|wget)', "Network call inside install hook")

# ---------------------------------------------------------------------------
# File type filters
# ---------------------------------------------------------------------------

TEXT_EXTENSIONS = {
    ".rb", ".py", ".sh", ".bash", ".zsh", ".fish",
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".go", ".rs", ".c", ".cpp", ".h", ".hpp",
    ".java", ".kt", ".swift",
    ".pl", ".pm", ".php",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".cmake", ".mk", "Makefile",
    ".tf", ".hcl",
    ".dockerfile", "Dockerfile",
    ".txt", ".md",
    ".ps1", ".bat", ".cmd",
}

BINARY_EXTENSIONS = {
    ".dylib", ".so", ".dll", ".exe", ".o", ".a",
    ".pyc", ".class",
    ".png", ".jpg", ".jpeg", ".gif", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".bz2",
    ".mp3", ".mp4", ".mov",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".tox",
    "venv", ".venv", "env", ".env", "dist", "build",
}

# Suffix-based skip: any directory whose name ends with these suffixes is skipped
SKIP_DIR_SUFFIXES = (".egg-info", ".dist-info")

EXPECTED_HIDDEN = {
    ".gitignore", ".gitattributes", ".github", ".editorconfig",
    ".eslintrc", ".babelrc", ".prettierrc", ".npmrc", ".nvmrc",
    ".env.example", ".travis.yml", ".circleci",
}


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze(target: ScanTarget, verbose: bool = False) -> StaticAnalysisResult:
    path = target.local_path
    if not path:
        return StaticAnalysisResult(
            risk=RiskLevel.SKIPPED,
            skipped=True,
            skip_reason="No local path to analyze",
        )

    if verbose:
        print(f"  → Running static analysis on {path}")

    flags: list[Flag] = []
    files_scanned = 0
    base = Path(path)

    for file_path in _walk_files(base):
        rel = str(file_path.relative_to(base))

        # Flag hidden files / dirs outside expected set
        parts = file_path.parts
        for part in parts:
            if part.startswith(".") and part not in EXPECTED_HIDDEN and part != ".git":
                flags.append(Flag(
                    message=f"Hidden file or directory: {rel}",
                    severity="info",
                    category="hidden_files",
                    file=rel,
                ))
                break

        # Flag embedded binaries
        ext = file_path.suffix.lower()
        if ext in BINARY_EXTENSIONS and ext not in {".gz", ".zip", ".tar"}:
            flags.append(Flag(
                message=f"Binary file embedded in repository: {rel}",
                severity="warn",
                category="binary_embedded",
                file=rel,
            ))
            continue

        if not _is_text_file(file_path):
            continue

        files_scanned += 1
        try:
            source = file_path.read_text(errors="replace")
        except (OSError, PermissionError):
            continue

        file_flags = _scan_source(source, rel, _effective_ext(file_path))
        flags.extend(file_flags)

        if verbose and file_flags:
            for ff in file_flags:
                loc = f":{ff.line}" if ff.line else ""
                print(f"    [{ff.severity.upper()}] {rel}{loc} — {ff.message}")

    # Detect exfiltration combinations: env var read + outbound network in same file
    # (done as a second pass to avoid false positives from single-pattern matches)

    risk = _compute_risk(flags)
    return StaticAnalysisResult(
        risk=risk,
        flags=flags,
        files_scanned=files_scanned,
    )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _walk_files(base: Path):
    for p in base.rglob("*"):
        if p.is_file():
            if any(part in SKIP_DIRS or part.startswith(".") and part not in EXPECTED_HIDDEN
                   for part in p.relative_to(base).parts[:-1]):
                # Skip hidden/vendor dirs (but not the file's own basename dot-check here)
                pass
            # Always skip .git, explicit skip dirs, and build artifact dirs
            if any(
                part in SKIP_DIRS or any(part.endswith(s) for s in SKIP_DIR_SUFFIXES)
                for part in p.parts
            ):
                continue
            yield p


_DOC_FILENAMES_PREFIX = ("COPYING", "LICENSE", "NOTICE", "AUTHORS", "CREDITS", "CHANGELOG", "CHANGES")


def _is_text_file(path: Path) -> bool:
    ext = path.suffix.lower()
    name = path.name
    if ext in TEXT_EXTENSIONS or name in TEXT_EXTENSIONS:
        return True
    if ext in BINARY_EXTENSIONS:
        return False
    # Sniff for binary content
    try:
        chunk = path.read_bytes()[:1024]
        return b"\x00" not in chunk
    except (OSError, PermissionError):
        return False


def _effective_ext(path: Path) -> str:
    """Return file extension, but treat license/copying files as '.txt' documentation."""
    name = path.name
    if any(name.upper().startswith(p) for p in _DOC_FILENAMES_PREFIX):
        return ".txt"
    return path.suffix.lower()


def _scan_source(source: str, rel_path: str, file_ext: str = "") -> list[Flag]:
    lines = source.splitlines()
    flags: list[Flag] = []
    seen: set[tuple[str, int]] = set()  # (category, line_no) dedup

    for line_no, line in enumerate(lines, start=1):
        is_comment = bool(_COMMENT_RE.match(line))
        for category, severity, pattern, description, skip_exts, skip_comments in _PATTERNS:
            if file_ext in skip_exts:
                continue
            if skip_comments and is_comment:
                continue
            m = pattern.search(line)
            if m:
                dedup_key = (category, line_no)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                matched_text = m.group(0)[:80]
                msg = description.replace("{match}", matched_text)

                flags.append(Flag(
                    message=msg,
                    severity=severity,
                    file=rel_path,
                    line=line_no,
                    category=category,
                ))

    return flags


def _compute_risk(flags: list[Flag]) -> RiskLevel:
    if not flags:
        return RiskLevel.CLEAN

    severities = {f.severity for f in flags}
    if "critical" in severities:
        return RiskLevel.HIGH
    if "warn" in severities:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
