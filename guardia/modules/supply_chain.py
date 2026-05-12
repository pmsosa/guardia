"""Module 5 — Supply Chain Analysis: evaluate the trust chain beyond the immediate package."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from ..models import Flag, RiskLevel, ScanTarget, SupplyChainResult

KNOWN_GOOD_HOSTING = {
    "github.com", "gitlab.com", "bitbucket.org",
    "pypi.org", "rubygems.org", "npmjs.com",
    "crates.io", "pkg.go.dev",
    "sourceforge.net", "launchpad.net",
}


def analyze(target: ScanTarget, verbose: bool = False) -> SupplyChainResult:
    if verbose:
        print("  → Running supply chain analysis")

    flags: list[Flag] = []
    deps: list[str] = list(target.metadata.get("dependencies", []))

    if target.type == "brew":
        flags.extend(_analyze_brew(target))
    elif target.type in ("git", "local"):
        flags.extend(_analyze_generic(target))

    # Flag deep dependency trees
    if len(deps) > 10:
        flags.append(Flag(
            message=f"Large number of dependencies ({len(deps)}) — difficult to audit manually",
            severity="warn",
            category="supply_chain",
        ))

    risk = _compute_risk(flags)
    return SupplyChainResult(risk=risk, flags=flags, dependencies=deps)


# ---------------------------------------------------------------------------
# Brew-specific checks
# ---------------------------------------------------------------------------

def _analyze_brew(target: ScanTarget) -> list[Flag]:
    flags: list[Flag] = []
    meta = target.metadata
    formula_src = target.formula_source or ""

    url: str = meta.get("url", "")
    sha256: str = meta.get("sha256", "")

    # HTTPS check
    if url and not url.startswith("https://"):
        flags.append(Flag(
            message=f"Source URL does not use HTTPS: {url}",
            severity="warn",
            category="supply_chain",
        ))

    # SHA256 presence
    if url and not sha256:
        flags.append(Flag(
            message="Formula has no SHA256 checksum — integrity cannot be verified",
            severity="warn",
            category="supply_chain",
        ))

    # Known hosting domain
    if url:
        domain = _extract_domain(url)
        if domain and domain not in KNOWN_GOOD_HOSTING:
            flags.append(Flag(
                message=f"Source URL uses non-standard hosting domain: {domain}",
                severity="warn",
                category="supply_chain",
            ))

    # Binary download
    if meta.get("is_binary_download"):
        flags.append(Flag(
            message="Formula downloads a pre-built binary (no source compilation) — higher trust requirement",
            severity="warn",
            category="supply_chain",
        ))

    # Raw commit SHA instead of tagged release
    if meta.get("points_to_commit"):
        flags.append(Flag(
            message="Formula points to a raw commit SHA instead of a tagged release",
            severity="warn",
            category="supply_chain",
        ))

    # Post-install hook
    if meta.get("has_post_install"):
        flags.append(Flag(
            message="Formula defines a post_install hook — verify it does not perform unexpected actions",
            severity="info",
            category="supply_chain",
        ))

    # Dependency URLs that look unusual
    flags.extend(_check_formula_dep_sources(formula_src))

    return flags


def _check_formula_dep_sources(formula_src: str) -> list[Flag]:
    """Flag any dependency that pulls from a non-standard source."""
    flags: list[Flag] = []
    # resource blocks with unusual URLs
    for m in re.finditer(r'resource\s+"([^"]+)"\s+do.*?url\s+"([^"]+)"', formula_src, re.DOTALL):
        res_name, res_url = m.group(1), m.group(2)
        if res_url and not res_url.startswith("https://"):
            flags.append(Flag(
                message=f"Resource '{res_name}' URL is not HTTPS: {res_url}",
                severity="warn",
                category="supply_chain",
            ))
        domain = _extract_domain(res_url)
        if domain and domain not in KNOWN_GOOD_HOSTING:
            flags.append(Flag(
                message=f"Resource '{res_name}' hosted on non-standard domain: {domain}",
                severity="info",
                category="supply_chain",
            ))
    return flags


# ---------------------------------------------------------------------------
# Generic (git / local) checks
# ---------------------------------------------------------------------------

def _analyze_generic(target: ScanTarget) -> list[Flag]:
    flags: list[Flag] = []
    path = target.local_path
    if not path:
        return flags

    base = Path(path)

    # Look for package manifest files and check dependencies
    manifests = {
        "package.json": _check_npm_manifest,
        "requirements.txt": _check_requirements_txt,
        "Pipfile": _check_pipfile,
        "Cargo.toml": _check_cargo_toml,
        "go.mod": _check_go_mod,
        "Gemfile": _check_gemfile,
    }

    for filename, checker in manifests.items():
        matches = list(base.rglob(filename))
        for mfile in matches[:3]:  # limit to first 3 matches
            try:
                content = mfile.read_text(errors="replace")
                rel = str(mfile.relative_to(base))
                flags.extend(checker(content, rel))
            except (OSError, PermissionError):
                pass

    # Check for .git/config to detect if this is a fork
    git_config = base / ".git" / "config"
    if git_config.exists():
        try:
            git_cfg = git_config.read_text()
            if "forked from" in git_cfg.lower():
                flags.append(Flag(
                    message="Repository appears to be a fork",
                    severity="info",
                    category="supply_chain",
                ))
        except (OSError, PermissionError):
            pass

    return flags


def _check_npm_manifest(content: str, rel: str) -> list[Flag]:
    import json
    flags: list[Flag] = []
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return flags

    scripts = data.get("scripts", {})
    suspicious_scripts = ["preinstall", "postinstall", "install", "prepare"]
    for script_name in suspicious_scripts:
        if script_name in scripts:
            flags.append(Flag(
                message=f"npm {script_name} script: {scripts[script_name][:120]}",
                severity="warn",
                category="supply_chain",
                file=rel,
            ))

    # Check for non-registry dependencies
    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))

    for dep_name, dep_ver in all_deps.items():
        if isinstance(dep_ver, str) and (
            dep_ver.startswith("http") or
            dep_ver.startswith("git") or
            dep_ver.startswith("github:") or
            dep_ver.startswith("file:")
        ):
            flags.append(Flag(
                message=f"Dependency '{dep_name}' uses non-registry source: {dep_ver}",
                severity="warn",
                category="supply_chain",
                file=rel,
            ))

    return flags


def _check_requirements_txt(content: str, rel: str) -> list[Flag]:
    flags: list[Flag] = []
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("git+") or line.startswith("http"):
            flags.append(Flag(
                message=f"Non-PyPI dependency: {line[:120]}",
                severity="warn",
                category="supply_chain",
                file=rel,
            ))
    return flags


def _check_pipfile(content: str, rel: str) -> list[Flag]:
    return []  # TODO: parse TOML and check for VCS deps


def _check_cargo_toml(content: str, rel: str) -> list[Flag]:
    flags: list[Flag] = []
    # Flag git = "..." dependencies
    for m in re.finditer(r'^\s*\w+\s*=\s*\{[^}]*git\s*=\s*"([^"]+)"', content, re.MULTILINE):
        flags.append(Flag(
            message=f"Cargo dependency from Git: {m.group(1)}",
            severity="info",
            category="supply_chain",
            file=rel,
        ))
    return flags


def _check_go_mod(content: str, rel: str) -> list[Flag]:
    return []  # Go module replace directives could be flagged; skip for now


def _check_gemfile(content: str, rel: str) -> list[Flag]:
    flags: list[Flag] = []
    for m in re.finditer(r"gem\s+'([^']+)'.*:git\s*=>\s*'([^']+)'", content):
        flags.append(Flag(
            message=f"Gemfile git dependency '{m.group(1)}': {m.group(2)}",
            severity="info",
            category="supply_chain",
            file=rel,
        ))
    return flags


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> Optional[str]:
    m = re.search(r'https?://([^/\s]+)', url)
    if m:
        host = m.group(1).lower()
        # Strip port
        host = host.split(":")[0]
        # Return just the registered domain (last two parts)
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
    return None


def _compute_risk(flags: list[Flag]) -> RiskLevel:
    if not flags:
        return RiskLevel.LOW
    severities = {f.severity for f in flags}
    if "critical" in severities:
        return RiskLevel.HIGH
    if "warn" in severities:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
