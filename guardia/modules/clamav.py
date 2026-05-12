"""Module 3 — ClamAV Antivirus Scan."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from ..models import ClamAVResult, RiskLevel


def check_installed() -> bool:
    return shutil.which("clamscan") is not None


def definitions_age_days() -> Optional[int]:
    """Return how many days ago ClamAV definitions were last updated, or None."""
    # ClamAV stores defs in various platform-dependent locations
    candidate_dirs = [
        Path("/opt/homebrew/var/lib/clamav"),
        Path("/usr/local/var/lib/clamav"),
        Path("/var/lib/clamav"),
        Path("/usr/share/clamav"),
    ]
    import datetime
    import os

    for d in candidate_dirs:
        main_db = d / "main.cvd"
        daily_db = d / "daily.cvd"
        for db in (daily_db, main_db):
            if db.exists():
                mtime = db.stat().st_mtime
                age = (datetime.datetime.utcnow() - datetime.datetime.utcfromtimestamp(mtime)).days
                return age
    return None


def prompt_install() -> bool:
    try:
        answer = input("ClamAV is not installed. Install via Homebrew now? [y/N] ").strip().lower()
        return answer == "y"
    except (EOFError, KeyboardInterrupt):
        return False


def prompt_update_defs(age_days: int) -> bool:
    try:
        answer = input(
            f"ClamAV definitions are {age_days} day(s) old. Update now? [y/N] "
        ).strip().lower()
        return answer == "y"
    except (EOFError, KeyboardInterrupt):
        return False


def install_clamav() -> bool:
    result = subprocess.run(["brew", "install", "clamav"], capture_output=False)
    return result.returncode == 0


def update_definitions() -> bool:
    result = subprocess.run(["freshclam"], capture_output=False)
    return result.returncode == 0


def scan(path: str, verbose: bool = False) -> ClamAVResult:
    if not check_installed():
        return ClamAVResult(
            risk=RiskLevel.SKIPPED,
            skipped=True,
            skip_reason="ClamAV (clamscan) not found — antivirus scan skipped",
        )

    if verbose:
        print(f"  → Running clamscan on {path}")

    try:
        result = subprocess.run(
            ["clamscan", "-r", "--no-summary=no", path],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return ClamAVResult(
            risk=RiskLevel.ERROR,
            skipped=True,
            skip_reason="ClamAV scan timed out after 300 seconds",
        )
    except FileNotFoundError:
        return ClamAVResult(
            risk=RiskLevel.SKIPPED,
            skipped=True,
            skip_reason="clamscan not found",
        )

    output = result.stdout + result.stderr
    return _parse_clamscan_output(output, verbose)


def _parse_clamscan_output(output: str, verbose: bool) -> ClamAVResult:
    infected: list[str] = []
    files_scanned = 0

    for line in output.splitlines():
        # Infected file: "path: Malware.Name FOUND"
        if line.endswith("FOUND"):
            parts = line.rsplit(":", 1)
            if len(parts) == 2:
                infected.append(parts[0].strip())

        # Summary line: "Scanned files: N"
        m = re.search(r'Scanned files:\s*(\d+)', line)
        if m:
            files_scanned = int(m.group(1))

    if verbose and infected:
        for f in infected:
            print(f"  ✗ Infected: {f}")

    if infected:
        return ClamAVResult(
            risk=RiskLevel.CRITICAL,
            files_scanned=files_scanned,
            infected=infected,
        )

    return ClamAVResult(
        risk=RiskLevel.CLEAN,
        files_scanned=files_scanned,
    )
