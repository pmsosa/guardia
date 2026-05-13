"""Module: VirusTotal — hash-first binary reputation check with optional upload."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..models import Flag, RiskLevel, ScanTarget, VirusTotalResult

_VT_BASE = "https://www.virustotal.com/api/v3"

_SOURCE_EXTENSIONS = frozenset({
    ".rb", ".py", ".sh", ".bash", ".zsh", ".js", ".ts", ".go", ".rs",
    ".c", ".h", ".cpp", ".java", ".yaml", ".yml", ".toml", ".json",
    ".txt", ".md", ".pl", ".php", ".swift", ".kt",
})


def check(
    target: ScanTarget,
    config: dict,
    allow_upload: bool = False,
    verbose: bool = False,
) -> VirusTotalResult:
    cfg_vt = config.get("virustotal", {})
    if not cfg_vt.get("enabled", True):
        return VirusTotalResult(
            risk=RiskLevel.SKIPPED, skipped=True, skip_reason="VirusTotal disabled in config"
        )

    from ..config import get_virustotal_key
    api_key = get_virustotal_key(config)
    if not api_key:
        return VirusTotalResult(
            risk=RiskLevel.SKIPPED,
            skipped=True,
            skip_reason="No VirusTotal API key (run --setup to add one)",
        )

    sha256 = target.metadata.get("sha256", "")
    if not sha256:
        return VirusTotalResult(
            risk=RiskLevel.SKIPPED,
            skipped=True,
            skip_reason="No artifact hash available for VirusTotal lookup",
        )

    is_binary = bool(target.metadata.get("is_binary_download", False))

    if verbose:
        print(f"  → VirusTotal hash lookup for {sha256[:16]}…")

    return _hash_lookup(sha256, api_key, target, allow_upload, is_binary, config, verbose)


def _hash_lookup(
    sha256: str,
    api_key: str,
    target: ScanTarget,
    allow_upload: bool,
    is_binary: bool,
    config: dict,
    verbose: bool,
) -> VirusTotalResult:
    req = Request(
        f"{_VT_BASE}/files/{sha256}",
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        return _parse_file_report(data, sha256, uploaded=False)

    except HTTPError as exc:
        if exc.code == 404:
            if verbose:
                print("  → Hash not found in VirusTotal database")
            cfg_vt = config.get("virustotal", {})
            upload_allowed = allow_upload and cfg_vt.get("allow_upload", False)
            if not upload_allowed or not is_binary:
                note = " (use --vt-upload to submit binary for scanning)" if is_binary and not allow_upload else ""
                return VirusTotalResult(
                    risk=RiskLevel.SKIPPED, skipped=True,
                    skip_reason=f"Hash not in VirusTotal database{note}",
                    hash_checked=sha256,
                )
            return _upload_artifact(sha256, target, api_key, verbose)

        if exc.code == 401:
            return VirusTotalResult(
                risk=RiskLevel.SKIPPED, skipped=True,
                skip_reason="VirusTotal API key invalid (401)",
            )
        if exc.code == 429:
            return VirusTotalResult(
                risk=RiskLevel.SKIPPED, skipped=True,
                skip_reason="VirusTotal rate limit exceeded (free tier: 4 req/min)",
            )
        return VirusTotalResult(
            risk=RiskLevel.SKIPPED, skipped=True,
            skip_reason=f"VirusTotal API error: HTTP {exc.code}",
        )
    except (URLError, OSError) as exc:
        return VirusTotalResult(
            risk=RiskLevel.SKIPPED, skipped=True,
            skip_reason=f"VirusTotal network error: {exc}",
        )


def _parse_file_report(data: dict, sha256: str, uploaded: bool) -> VirusTotalResult:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values())
    detections = malicious + suspicious

    detection_names = [
        r.get("result")
        for r in results.values()
        if r.get("category") in ("malicious", "suspicious") and r.get("result")
    ][:10]

    sha_id = data.get("data", {}).get("id", sha256)
    permalink = f"https://www.virustotal.com/gui/file/{sha_id}"

    if detections == 0:
        msg = f"VirusTotal: 0/{total} engines — clean"
        severity = "info"
        risk = RiskLevel.LOW
    elif detections <= 2:
        names_str = ", ".join(detection_names[:3])
        msg = f"VirusTotal: {detections}/{total} engines flagged — {names_str} (possible false positive)"
        severity = "warn"
        risk = RiskLevel.MEDIUM
    else:
        names_str = ", ".join(detection_names[:3])
        msg = f"VirusTotal: {detections}/{total} engines flagged — {names_str}"
        severity = "critical"
        risk = RiskLevel.CRITICAL

    flags = [Flag(message=msg, severity=severity, category="virustotal")]

    return VirusTotalResult(
        risk=risk,
        hash_checked=sha256,
        detections=detections,
        total_engines=total,
        detection_names=detection_names,
        permalink=permalink,
        uploaded=uploaded,
        flags=flags,
    )


def _upload_artifact(
    sha256: str, target: ScanTarget, api_key: str, verbose: bool
) -> VirusTotalResult:
    import tempfile
    import urllib.request

    url = target.metadata.get("url", "")
    if not url:
        return VirusTotalResult(
            risk=RiskLevel.SKIPPED, skipped=True,
            skip_reason="No artifact URL available for upload",
            hash_checked=sha256,
        )

    ext = Path(url.split("?")[0]).suffix.lower()
    if ext in _SOURCE_EXTENSIONS:
        return VirusTotalResult(
            risk=RiskLevel.SKIPPED, skipped=True,
            skip_reason="Artifact is a source archive — VirusTotal upload skipped (only useful for binaries)",
            hash_checked=sha256,
        )

    if verbose:
        print("  → Downloading artifact for VirusTotal upload…")

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=ext or ".bin") as tmp:
            tmp_path = tmp.name
            with urllib.request.urlopen(url, timeout=120) as resp:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    tmp.write(chunk)
    except Exception as exc:
        return VirusTotalResult(
            risk=RiskLevel.SKIPPED, skipped=True,
            skip_reason=f"Failed to download artifact: {exc}",
            hash_checked=sha256,
        )

    actual = hashlib.sha256(Path(tmp_path).read_bytes()).hexdigest()
    if actual != sha256:
        Path(tmp_path).unlink(missing_ok=True)
        return VirusTotalResult(
            risk=RiskLevel.SKIPPED, skipped=True,
            skip_reason="Downloaded artifact SHA256 mismatch — possible tampering, upload aborted",
            hash_checked=sha256,
        )

    if verbose:
        print("  → Uploading to VirusTotal…")

    try:
        file_data = Path(tmp_path).read_bytes()
        boundary = b"guardia_vt_boundary"
        body = (
            b"--" + boundary + b"\r\n"
            b'Content-Disposition: form-data; name="file"; filename="artifact"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n"
            + file_data
            + b"\r\n--" + boundary + b"--\r\n"
        )
        req = Request(
            f"{_VT_BASE}/files",
            data=body,
            headers={
                "x-apikey": api_key,
                "Content-Type": f"multipart/form-data; boundary={boundary.decode()}",
            },
            method="POST",
        )
        with urlopen(req, timeout=120) as resp:
            upload_data = json.loads(resp.read())
    except Exception as exc:
        return VirusTotalResult(
            risk=RiskLevel.SKIPPED, skipped=True,
            skip_reason=f"VirusTotal upload failed: {exc}",
            hash_checked=sha256,
        )
    finally:
        Path(tmp_path).unlink(missing_ok=True)

    analysis_id = upload_data.get("data", {}).get("id", "")
    if not analysis_id:
        return VirusTotalResult(
            risk=RiskLevel.SKIPPED, skipped=True,
            skip_reason="Upload succeeded but no analysis ID returned",
            hash_checked=sha256,
            uploaded=True,
        )

    if verbose:
        print("  → Waiting for VirusTotal analysis to complete…")

    for _ in range(12):  # poll up to ~60 s
        time.sleep(5)
        try:
            req = Request(
                f"{_VT_BASE}/analyses/{analysis_id}",
                headers={"x-apikey": api_key, "Accept": "application/json"},
            )
            with urlopen(req, timeout=15) as resp:
                poll = json.loads(resp.read())
            if poll.get("data", {}).get("attributes", {}).get("status") == "completed":
                return _fetch_by_hash(sha256, api_key, uploaded=True)
        except Exception:
            pass

    return VirusTotalResult(
        risk=RiskLevel.SKIPPED, skipped=True,
        skip_reason="VirusTotal analysis timed out — check report manually",
        hash_checked=sha256,
        permalink=f"https://www.virustotal.com/gui/file/{sha256}",
        uploaded=True,
    )


def _fetch_by_hash(sha256: str, api_key: str, uploaded: bool = False) -> VirusTotalResult:
    req = Request(
        f"{_VT_BASE}/files/{sha256}",
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    try:
        with urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
        return _parse_file_report(data, sha256, uploaded=uploaded)
    except Exception as exc:
        return VirusTotalResult(
            risk=RiskLevel.SKIPPED, skipped=True,
            skip_reason=f"Could not fetch VirusTotal result after upload: {exc}",
            hash_checked=sha256,
            uploaded=uploaded,
        )
