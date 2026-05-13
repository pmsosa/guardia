"""Module 2 — Metadata & Reputation: build a risk profile from public signals."""

from __future__ import annotations

import datetime
import re
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import json

from ..models import Flag, MetadataResult, RiskLevel, ScanTarget


def analyze(target: ScanTarget, config: dict, verbose: bool = False) -> MetadataResult:
    github_url = target.metadata.get("github_url")

    if not github_url:
        return MetadataResult(
            risk=RiskLevel.SKIPPED,
            skipped=True,
            skip_reason="No GitHub URL found — metadata check skipped",
        )

    owner_repo = _extract_owner_repo(github_url)
    if not owner_repo:
        return MetadataResult(
            risk=RiskLevel.SKIPPED,
            skipped=True,
            skip_reason="Could not parse GitHub owner/repo",
        )

    if verbose:
        print(f"  → Checking GitHub metadata for {owner_repo}")

    try:
        return _check_github(owner_repo, target, config, verbose)
    except _RateLimitError:
        return MetadataResult(
            risk=RiskLevel.SKIPPED,
            skipped=True,
            skip_reason="GitHub API rate limit exceeded — reputation check skipped",
        )
    except Exception as exc:
        return MetadataResult(
            risk=RiskLevel.SKIPPED,
            skipped=True,
            skip_reason=f"GitHub API unavailable: {exc}",
        )


# ---------------------------------------------------------------------------
# GitHub checks
# ---------------------------------------------------------------------------

class _RateLimitError(Exception):
    pass


def _gh_get(path: str) -> dict | list:
    url = f"https://api.github.com{path}"
    req = Request(url, headers={
        "Accept": "application/vnd.github+json",
        "User-Agent": "guardia/0.1",
    })
    try:
        with urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except HTTPError as exc:
        if exc.code == 403:
            raise _RateLimitError("rate limited") from exc
        if exc.code == 404:
            raise RuntimeError(f"Not found: {url}") from exc
        raise RuntimeError(f"GitHub API error {exc.code}: {url}") from exc
    except URLError as exc:
        raise RuntimeError(f"Network error: {exc}") from exc


def _check_github(owner_repo: str, target: ScanTarget, config: dict, verbose: bool) -> MetadataResult:
    thresholds = config.get("thresholds", {})
    age_warn = thresholds.get("repo_age_warn_days", 30)
    stars_warn = thresholds.get("repo_stars_warn_below", 10)
    recent_push_warn = thresholds.get("recent_push_warn_days", 3)

    flags: list[Flag] = []

    repo_data = _gh_get(f"/repos/{owner_repo}")
    assert isinstance(repo_data, dict)

    now = datetime.datetime.now(datetime.timezone.utc)

    # Repo creation age
    created_at = repo_data.get("created_at", "")
    repo_age_days: Optional[int] = None
    if created_at:
        try:
            created_dt = datetime.datetime.fromisoformat(created_at.replace("Z", "+00:00"))
            repo_age_days = (now - created_dt).days
        except ValueError:
            pass

    if repo_age_days is not None and repo_age_days < age_warn:
        flags.append(Flag(
            message=f"Repository is only {repo_age_days} days old — newly created repos are higher risk",
            severity="warn",
            category="metadata",
        ))

    # Recent push check — very recent changes are a pipeline attack signal
    pushed_at = repo_data.get("pushed_at", "")
    last_push_days: Optional[int] = None
    if pushed_at:
        try:
            pushed_dt = datetime.datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
            last_push_days = (now - pushed_dt).days
        except ValueError:
            pass

    if last_push_days is not None and last_push_days < recent_push_warn:
        flags.append(Flag(
            message=f"Repository was last pushed {last_push_days} day(s) ago — very recent changes increase pipeline attack risk",
            severity="warn",
            category="metadata",
        ))

    # Stars / forks
    stars: int = repo_data.get("stargazers_count", 0)
    forks: int = repo_data.get("forks_count", 0)
    if stars < stars_warn:
        flags.append(Flag(
            message=f"Low star count ({stars}) for a package claiming to be widely used",
            severity="info",
            category="metadata",
        ))

    # Fork detection
    is_fork: bool = repo_data.get("fork", False)
    if is_fork:
        flags.append(Flag(
            message="Repository is a fork — forks of popular tools with minor changes are a known attack vector",
            severity="warn",
            category="metadata",
        ))

    # License check
    license_info = repo_data.get("license")
    if not license_info:
        flags.append(Flag(
            message="No LICENSE detected on the repository",
            severity="info",
            category="metadata",
        ))

    # Archived / disabled
    if repo_data.get("archived"):
        flags.append(Flag(
            message="Repository is archived — may indicate abandoned or orphaned project",
            severity="info",
            category="metadata",
        ))

    # Contributor count (separate API call)
    contributors: Optional[int] = None
    try:
        contrib_data = _gh_get(f"/repos/{owner_repo}/contributors?per_page=100&anon=0")
        if isinstance(contrib_data, list):
            contributors = len(contrib_data)
            if contributors == 1:
                flags.append(Flag(
                    message="Single contributor with no commit history from others",
                    severity="info",
                    category="metadata",
                ))
    except Exception:
        pass

    # Domain match for brew formulas
    if target.type == "brew":
        url = target.metadata.get("url", "")
        homepage = target.metadata.get("homepage", "")
        repo_html_url = repo_data.get("html_url", "")
        if url and repo_html_url:
            repo_owner = owner_repo.split("/")[0].lower()
            url_owner = _extract_owner_from_url(url)
            if url_owner and url_owner.lower() != repo_owner:
                flags.append(Flag(
                    message=f"Source URL owner '{url_owner}' does not match GitHub org '{repo_owner}'",
                    severity="warn",
                    category="metadata",
                ))

    # Compute reputation risk
    critical_flags = [f for f in flags if f.severity == "critical"]
    warn_flags = [f for f in flags if f.severity == "warn"]

    if critical_flags:
        risk = RiskLevel.CRITICAL
    elif len(warn_flags) >= 2:
        risk = RiskLevel.HIGH
    elif warn_flags:
        risk = RiskLevel.MEDIUM
    elif flags:
        risk = RiskLevel.LOW
    else:
        risk = RiskLevel.LOW

    return MetadataResult(
        risk=risk,
        flags=flags,
        repo_age_days=repo_age_days,
        last_push_days=last_push_days,
        stars=stars,
        forks=forks,
        contributors=contributors,
        is_fork=is_fork,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_owner_repo(github_url: str) -> Optional[str]:
    m = re.search(r'github\.com/([^/]+/[^/\s#?]+)', github_url)
    if m:
        parts = m.group(1).rstrip("/").split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
    return None


def _extract_owner_from_url(url: str) -> Optional[str]:
    m = re.search(r'github\.com/([^/]+)/', url)
    return m.group(1) if m else None
