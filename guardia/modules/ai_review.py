"""Module 6 — Claude AI Code Review: API or CLI backend, with sliding-window deep mode."""

from __future__ import annotations

import json
import os
import re
import select
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

from ..models import AIReviewResult, Flag, RiskLevel, ScanTarget

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a security-focused code reviewer. Your task is to analyze source code for malicious, suspicious, or unsafe behavior.

Focus on:
1. What does this code actually do? (behavioral summary)
2. Does it access the network? If so, where and why?
3. Does it read or write sensitive files or environment variables?
4. Are there any obfuscation techniques in use?
5. Do the install hooks do anything unexpected?
6. Are there any patterns consistent with malware, spyware, or supply chain attacks?

Respond with EXACTLY this format (keep each section label on its own line):
RISK LEVEL: [Low / Medium / High / Critical]
SUMMARY: (2-3 sentences describing what this code does)
FLAGS:
- (specific concern with file:line if applicable, or "None" if no concerns)
VERDICT: (one sentence plain-language assessment)"""

# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------

def detect_backend(config: dict) -> Optional[str]:
    """Return 'api', 'cli', or None."""
    from ..config import get_anthropic_key
    preference = config.get("api", {}).get("claude_backend", "auto")

    if preference == "api":
        return "api" if get_anthropic_key(config) else None
    if preference == "cli":
        return "cli" if shutil.which("claude") else None

    # auto
    if get_anthropic_key(config):
        return "api"
    if shutil.which("claude"):
        return "cli"
    return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def review(
    target: ScanTarget,
    config: dict,
    deep: bool = False,
    chunking: str = "sliding_window",
    verbose: bool = False,
) -> AIReviewResult:
    backend = detect_backend(config)

    if backend is None:
        return AIReviewResult(
            risk=RiskLevel.SKIPPED,
            skipped=True,
            skip_reason=(
                "No AI backend available. Set ANTHROPIC_API_KEY or install the Claude CLI "
                "(brew install --cask claude). AI review skipped."
            ),
        )

    if verbose:
        print(f"  → Running AI code review [{backend}] ({'deep' if deep else 'standard'})")

    path = target.local_path
    if not path:
        return AIReviewResult(
            risk=RiskLevel.SKIPPED,
            skipped=True,
            skip_reason="No local path to analyze",
        )

    try:
        if deep:
            return _deep_review(path, target, backend, config, chunking, verbose)
        else:
            return _standard_review(path, target, backend, config, verbose)
    except Exception as exc:
        return AIReviewResult(
            risk=RiskLevel.ERROR,
            backend=backend,
            error=str(exc),
            skip_reason=f"AI review failed: {exc}",
        )


# ---------------------------------------------------------------------------
# Standard review (single call, up to ~8k tokens)
# ---------------------------------------------------------------------------

def _standard_review(
    path: str, target: ScanTarget, backend: str, config: dict, verbose: bool
) -> AIReviewResult:
    MAX_CHARS = 30_000  # ~7500 tokens

    content_parts: list[str] = []
    total_chars = 0
    base = Path(path)

    # Prioritize: formula source, then small source files
    candidates = _collect_files(base, MAX_CHARS)

    for rel, text in candidates:
        chunk = f"\n\n--- FILE: {rel} ---\n{text}"
        if total_chars + len(chunk) > MAX_CHARS:
            content_parts.append(f"\n\n[... remaining files truncated for token limit ...]")
            break
        content_parts.append(chunk)
        total_chars += len(chunk)

    if target.formula_source:
        formula_header = "--- HOMEBREW FORMULA (formula.rb) ---\n" + target.formula_source
        content_parts.insert(0, formula_header)

    code_content = "\n".join(content_parts)
    user_message = f"Please review the following code:\n\n{code_content}"

    raw = _call_backend(backend, user_message, config, timeout=120)
    return _parse_response(raw, backend)


# ---------------------------------------------------------------------------
# Deep review (sliding window, multiple calls)
# ---------------------------------------------------------------------------

def _deep_review(
    path: str, target: ScanTarget, backend: str, config: dict, chunking: str, verbose: bool
) -> AIReviewResult:
    CHUNK_CHARS = 24_000    # ~6000 tokens per chunk
    OVERLAP_CHARS = 2_000   # ~500 token overlap

    base = Path(path)
    all_files = _collect_files(base, max_chars=None)

    if chunking == "file_by_file":
        chunks = [(rel, content) for rel, content in all_files]
        chunk_texts = [f"--- FILE: {rel} ---\n{content}" for rel, content in chunks]
    else:
        # Sliding window over concatenated content
        full_text = "\n\n".join(
            f"--- FILE: {rel} ---\n{content}" for rel, content in all_files
        )
        chunk_texts = _sliding_window(full_text, CHUNK_CHARS, OVERLAP_CHARS)

    if verbose:
        print(f"  → Deep review: {len(chunk_texts)} chunk(s) to analyze")

    partial_results: list[AIReviewResult] = []
    for i, chunk in enumerate(chunk_texts, start=1):
        if verbose:
            print(f"  → Chunk {i}/{len(chunk_texts)} ...")
        user_message = f"Please review the following code (chunk {i} of {len(chunk_texts)}):\n\n{chunk}"
        try:
            raw = _call_backend(backend, user_message, config, timeout=180)
            partial_results.append(_parse_response(raw, backend))
        except Exception as exc:
            if verbose:
                print(f"  ⚠ Chunk {i} failed: {exc}")

    if not partial_results:
        return AIReviewResult(
            risk=RiskLevel.ERROR,
            backend=backend,
            error="All deep review chunks failed",
        )

    return _consolidate_results(partial_results, backend)


def _sliding_window(text: str, chunk_size: int, overlap: int) -> list[str]:
    chunks: list[str] = []
    pos = 0
    while pos < len(text):
        end = pos + chunk_size
        chunks.append(text[pos:end])
        if end >= len(text):
            break
        pos = end - overlap
    return chunks


def _consolidate_results(results: list[AIReviewResult], backend: str) -> AIReviewResult:
    from ..models import RISK_ORDER
    best = max(results, key=lambda r: RISK_ORDER.get(r.risk, 0))
    all_flags: list[Flag] = []
    for r in results:
        all_flags.extend(r.flags)
    return AIReviewResult(
        risk=best.risk,
        summary=best.summary,
        flags=all_flags,
        verdict=best.verdict,
        backend=backend,
    )


# ---------------------------------------------------------------------------
# File collection helpers
# ---------------------------------------------------------------------------

TEXT_EXTS = {
    ".rb", ".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".go", ".rs",
    ".c", ".cpp", ".h", ".java", ".yaml", ".yml", ".toml", ".json",
    ".txt", ".md", ".cmake", "Makefile", ".tf", ".hcl", "Dockerfile",
    ".pl", ".pm", ".php", ".swift", ".kt",
}

SKIP_DIRS = {".git", "node_modules", "__pycache__", ".tox", "venv", ".venv", "env", ".env", "dist", "build"}
SKIP_DIR_SUFFIXES = (".egg-info", ".dist-info")


def _collect_files(base: Path, max_chars: Optional[int]) -> list[tuple[str, str]]:
    results: list[tuple[str, str]] = []
    total = 0

    for f in sorted(base.rglob("*")):
        if f.is_file() and not any(
            p in SKIP_DIRS or any(p.endswith(s) for s in SKIP_DIR_SUFFIXES)
            for p in f.parts
        ):
            ext = f.suffix.lower()
            name = f.name
            if ext not in TEXT_EXTS and name not in TEXT_EXTS:
                continue
            try:
                text = f.read_text(errors="replace")
            except (OSError, PermissionError):
                continue
            rel = str(f.relative_to(base))
            results.append((rel, text))
            total += len(text)
            if max_chars and total >= max_chars:
                break

    return results


# ---------------------------------------------------------------------------
# Backend callers
# ---------------------------------------------------------------------------

def _call_backend(backend: str, user_message: str, config: dict, timeout: int) -> str:
    if backend == "api":
        return _call_api(user_message, config, timeout)
    else:
        return _call_cli(user_message, timeout)


def _call_api(user_message: str, config: dict, timeout: int) -> str:
    try:
        import anthropic
    except ImportError:
        raise RuntimeError(
            "anthropic SDK not installed. Run: pip install anthropic"
        )

    from ..config import get_anthropic_key
    api_key = get_anthropic_key(config)
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY not set")

    client = anthropic.Anthropic(api_key=api_key)

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": user_message}],
    )

    return response.content[0].text


def _call_cli(user_message: str, timeout: int) -> str:
    """Call claude CLI using a pseudo-TTY to avoid hanging."""
    # Write prompt to temp file to avoid shell escaping issues
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="guardia_prompt_"
    ) as fh:
        fh.write(SYSTEM_PROMPT + "\n\n" + user_message)
        prompt_file = fh.name

    try:
        return _run_claude_cli_with_pty(prompt_file, timeout)
    finally:
        try:
            os.unlink(prompt_file)
        except OSError:
            pass


def _run_claude_cli_with_pty(prompt_file: str, timeout: int) -> str:
    """Spawn claude -p with a pseudo-TTY to avoid the no-TTY hang."""
    import pty

    cmd = ["claude", "-p", f"@{prompt_file}", "--output-format", "json"]

    # macOS fallback: use `script -q /dev/null` to allocate a TTY
    if shutil.which("script"):
        # Build shell command safely — prompt_file path has no special chars (tempfile)
        shell_cmd = f"script -q /dev/null claude -p @{prompt_file} --output-format json"
        proc = subprocess.Popen(
            shell_cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            raw = stdout.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            proc.kill()
            raise TimeoutError("claude CLI timed out")
    else:
        # pty-based fallback
        master_fd, slave_fd = pty.openpty()
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
            )
            os.close(slave_fd)

            output_bytes = bytearray()
            deadline = time.monotonic() + timeout

            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    proc.kill()
                    raise TimeoutError("claude CLI timed out")
                if proc.poll() is not None:
                    # Drain remaining output
                    try:
                        while True:
                            r, _, _ = select.select([master_fd], [], [], 0.05)
                            if not r:
                                break
                            output_bytes.extend(os.read(master_fd, 4096))
                    except OSError:
                        pass
                    break
                r, _, _ = select.select([master_fd], [], [], 0.1)
                if r:
                    try:
                        output_bytes.extend(os.read(master_fd, 4096))
                    except OSError:
                        break

            raw = output_bytes.decode("utf-8", errors="replace")
        finally:
            try:
                os.close(master_fd)
            except OSError:
                pass

    # claude --output-format json wraps result in JSON
    raw = raw.strip()
    try:
        data = json.loads(raw)
        return data.get("result", raw)
    except (json.JSONDecodeError, KeyError):
        return raw


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------

def _parse_response(raw: str, backend: str) -> AIReviewResult:
    risk = _parse_risk_level(raw)
    summary = _extract_section(raw, "SUMMARY")
    verdict = _extract_section(raw, "VERDICT")
    flags = _parse_flags(raw)

    return AIReviewResult(
        risk=risk,
        summary=summary,
        flags=flags,
        verdict=verdict,
        backend=backend,
    )


def _parse_risk_level(text: str) -> RiskLevel:
    m = re.search(r'RISK\s+LEVEL\s*:\s*(\w+)', text, re.IGNORECASE)
    if not m:
        return RiskLevel.LOW

    level = m.group(1).lower()
    mapping = {
        "low": RiskLevel.LOW,
        "medium": RiskLevel.MEDIUM,
        "high": RiskLevel.HIGH,
        "critical": RiskLevel.CRITICAL,
    }
    return mapping.get(level, RiskLevel.LOW)


def _extract_section(text: str, section: str) -> str:
    pattern = rf'{section}\s*:\s*(.+?)(?=\n[A-Z ]+:|$)'
    m = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
    if m:
        return m.group(1).strip()
    return ""


def _parse_flags(text: str) -> list[Flag]:
    flags: list[Flag] = []
    # Find the FLAGS section
    m = re.search(r'FLAGS\s*:\s*\n(.*?)(?=\n[A-Z ]+:|$)', text, re.IGNORECASE | re.DOTALL)
    if not m:
        return flags

    section = m.group(1)
    for line in section.splitlines():
        line = line.strip().lstrip("-•*").strip()
        if not line or line.lower() == "none":
            continue

        # Try to extract file:line reference
        file_ref = None
        line_no = None
        ref_match = re.search(r'(\S+\.(?:rb|py|sh|js|ts|go|rs|c|cpp|java|yaml|yml|toml|json))\s*:?\s*(\d+)?', line)
        if ref_match:
            file_ref = ref_match.group(1)
            if ref_match.group(2):
                try:
                    line_no = int(ref_match.group(2))
                except ValueError:
                    pass

        # Severity inference
        lower = line.lower()
        if any(w in lower for w in ("critical", "malicious", "backdoor", "exfiltrat")):
            severity = "critical"
        elif any(w in lower for w in ("suspicious", "warning", "unusual", "unexpected", "obfuscat")):
            severity = "warn"
        else:
            severity = "info"

        flags.append(Flag(
            message=line,
            severity=severity,
            file=file_ref,
            line=line_no,
            category="ai_review",
        ))

    return flags
