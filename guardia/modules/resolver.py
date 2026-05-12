"""Module 1 — Resolve & Fetch: normalize any input into a local directory for analysis."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional

from ..models import ScanTarget


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def resolve(target_type: str, target_value: str, verbose: bool = False) -> ScanTarget:
    """Return a ScanTarget with local_path pointing to files ready for analysis."""
    if target_type == "brew":
        return _resolve_brew(target_value, verbose)
    elif target_type == "git":
        return _resolve_git(target_value, verbose)
    elif target_type == "local":
        return _resolve_local(target_value, verbose)
    else:
        raise ValueError(f"Unknown target type: {target_type!r}")


# ---------------------------------------------------------------------------
# Brew
# ---------------------------------------------------------------------------

def _resolve_brew(formula: str, verbose: bool) -> ScanTarget:
    if verbose:
        print(f"  → Fetching Homebrew formula: {formula}")

    result = subprocess.run(
        ["brew", "cat", formula],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise RuntimeError(
            f"Could not fetch formula '{formula}': {stderr or 'brew cat failed'}"
        )

    formula_source = result.stdout
    meta = _parse_brew_formula(formula_source)
    meta["formula_name"] = formula

    tmp_dir = tempfile.mkdtemp(prefix="guardia_brew_")

    # Save formula source for analysis
    formula_file = Path(tmp_dir) / "formula.rb"
    formula_file.write_text(formula_source)

    # Attempt to download and extract source archive when not a binary-only formula
    if meta.get("url") and not meta.get("is_binary_download"):
        src_path = _download_and_extract(meta["url"], meta.get("sha256"), tmp_dir, verbose)
        if src_path and verbose:
            print(f"  → Extracted source to {src_path}")

    return ScanTarget(
        type="brew",
        raw=formula,
        local_path=tmp_dir,
        formula_source=formula_source,
        metadata=meta,
        _cleanup=True,
    )


def _parse_brew_formula(source: str) -> dict:
    meta: dict = {}

    # URL and SHA256
    url_match = re.search(r'^\s*url\s+"([^"]+)"', source, re.MULTILINE)
    sha_match = re.search(r'^\s*sha256\s+"([a-fA-F0-9]+)"', source, re.MULTILINE)
    if url_match:
        meta["url"] = url_match.group(1)
    if sha_match:
        meta["sha256"] = sha_match.group(1)

    # Homepage
    homepage_match = re.search(r'^\s*homepage\s+"([^"]+)"', source, re.MULTILINE)
    if homepage_match:
        meta["homepage"] = homepage_match.group(1)

    # License
    license_match = re.search(r'^\s*license\s+"([^"]+)"', source, re.MULTILINE)
    if license_match:
        meta["license"] = license_match.group(1)

    # Dependencies
    deps = re.findall(r'depends_on\s+"([^"]+)"', source)
    meta["dependencies"] = deps

    # Binary download detection: bottle-only or no source URL
    if "bottle :unneeded" in source or "bottle do" in source:
        meta["has_bottle"] = True
    # Detect pre-built binary patterns (common in casks and some formulae)
    url = meta.get("url", "")
    binary_extensions = (".dmg", ".pkg", ".exe", ".zip", ".tar.gz", ".tgz")
    if any(url.lower().endswith(ext) for ext in (".dmg", ".pkg", ".exe")):
        meta["is_binary_download"] = True
    else:
        meta["is_binary_download"] = False

    # Head URL (for tools hosted on GitHub with source tarballs elsewhere)
    head_match = re.search(r'head\s+"(https://[^"]+)"', source, re.MULTILINE)
    meta["head_url"] = head_match.group(1) if head_match else ""

    # Extract GitHub org/repo from URL, head URL, or homepage
    github_url = (
        _extract_github_url(url)
        or _extract_github_url(meta.get("head_url", ""))
        or _extract_github_url(meta.get("homepage", ""))
    )
    if github_url:
        meta["github_url"] = github_url

    # Detect if formula references a raw commit hash instead of a tagged release
    commit_re = re.search(r'/(?:archive|commit)/([a-f0-9]{40})(?:\.tar\.gz)?', url)
    tag_re = re.search(r'/(?:archive|releases/download)/v?[\d.]+', url)
    if commit_re and not tag_re:
        meta["points_to_commit"] = True
    else:
        meta["points_to_commit"] = False

    # Detect install / post_install / caveats blocks (for static analysis)
    meta["has_post_install"] = bool(re.search(r'def post_install', source))
    meta["has_caveats"] = bool(re.search(r'def caveats', source))

    return meta


def _extract_github_url(url: str) -> Optional[str]:
    if not url:
        return None
    m = re.search(r'github\.com/([^/\s]+/[^/\s#?]+)', url)
    if m:
        repo = m.group(1).rstrip("/")
        repo = re.sub(r'\.git$', '', repo)
        # Strip any trailing path components beyond owner/repo
        parts = repo.split("/")
        if len(parts) >= 2:
            return f"https://github.com/{parts[0]}/{parts[1]}"
    return None


def _download_and_extract(url: str, expected_sha256: Optional[str], dest_dir: str, verbose: bool) -> Optional[str]:
    if not url.startswith(("https://", "http://")):
        return None
    try:
        if verbose:
            print(f"  → Downloading source archive: {url}")
        archive_path = Path(dest_dir) / "source_archive"
        req = urllib.request.Request(url, headers={"User-Agent": "guardia/0.1"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
        archive_path.write_bytes(data)

        if expected_sha256:
            import hashlib
            actual = hashlib.sha256(data).hexdigest()
            if actual.lower() != expected_sha256.lower():
                if verbose:
                    print(f"  ⚠ SHA256 mismatch: expected {expected_sha256}, got {actual}")
                return None

        extract_dir = Path(dest_dir) / "source"
        extract_dir.mkdir(exist_ok=True)

        url_lower = url.lower()
        if url_lower.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
            with tarfile.open(str(archive_path)) as tf:
                tf.extractall(str(extract_dir))
        elif url_lower.endswith(".zip"):
            with zipfile.ZipFile(str(archive_path)) as zf:
                zf.extractall(str(extract_dir))
        else:
            return None  # Unknown archive format

        archive_path.unlink(missing_ok=True)
        return str(extract_dir)
    except Exception as exc:
        if verbose:
            print(f"  ⚠ Could not download/extract source: {exc}")
        return None


# ---------------------------------------------------------------------------
# Git
# ---------------------------------------------------------------------------

def _resolve_git(url: str, verbose: bool) -> ScanTarget:
    if verbose:
        print(f"  → Cloning repository: {url}")

    tmp_dir = tempfile.mkdtemp(prefix="guardia_git_")

    try:
        subprocess.run(
            ["git", "clone", "--depth=1", "--quiet", url, tmp_dir],
            check=True,
            capture_output=not verbose,
        )
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError(f"Failed to clone repository '{url}': {exc}") from exc
    except FileNotFoundError:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise RuntimeError("git not found. Please install Git.")

    meta: dict = {}
    github_url = _extract_github_url(url)
    if github_url:
        meta["github_url"] = github_url

    meta["url"] = url
    meta["is_binary_download"] = False

    return ScanTarget(
        type="git",
        raw=url,
        local_path=tmp_dir,
        metadata=meta,
        _cleanup=True,
    )


# ---------------------------------------------------------------------------
# Local
# ---------------------------------------------------------------------------

def _resolve_local(path: str, verbose: bool) -> ScanTarget:
    p = Path(path).expanduser().resolve()
    if not p.exists():
        raise RuntimeError(f"Path does not exist: {path}")
    if not p.is_dir() and not p.is_file():
        raise RuntimeError(f"Path is not a file or directory: {path}")

    meta: dict = {"is_binary_download": False}

    if verbose:
        print(f"  → Analyzing local path: {p}")

    return ScanTarget(
        type="local",
        raw=str(p),
        local_path=str(p),
        metadata=meta,
        _cleanup=False,
    )


# ---------------------------------------------------------------------------
# Cleanup helper
# ---------------------------------------------------------------------------

def cleanup(target: ScanTarget) -> None:
    if target._cleanup and target.local_path:
        shutil.rmtree(target.local_path, ignore_errors=True)
