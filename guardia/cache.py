from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from .config import CACHE_DIR

if TYPE_CHECKING:
    from .models import (
        MetadataResult, ClamAVResult, StaticAnalysisResult,
        SupplyChainResult, AIReviewResult, IPReputationResult, VirusTotalResult,
    )


# ---------------------------------------------------------------------------
# Module result serialization / deserialization
# ---------------------------------------------------------------------------

def _flags_to_list(flags) -> list[dict]:
    return [
        {"message": f.message, "severity": f.severity,
         "file": f.file, "line": f.line, "category": f.category}
        for f in (flags or [])
    ]


def _flags_from_list(lst: list[dict]):
    from .models import Flag
    return [Flag(**d) for d in (lst or [])]


def _base(m) -> dict:
    return {
        "risk": m.risk.value,
        "skipped": m.skipped,
        "skip_reason": getattr(m, "skip_reason", ""),
        "error": getattr(m, "error", None),
    }


def serialize_scan_results(meta, clam, static, supply, ai, ip_rep=None, vt=None) -> dict:
    def ser_meta(m):
        if m is None:
            return None
        d = _base(m)
        d.update(flags=_flags_to_list(m.flags), repo_age_days=m.repo_age_days,
                 stars=m.stars, forks=m.forks, contributors=m.contributors, is_fork=m.is_fork)
        return d

    def ser_clam(m):
        if m is None:
            return None
        d = _base(m)
        d.update(files_scanned=m.files_scanned, infected=m.infected)
        return d

    def ser_static(m):
        if m is None:
            return None
        d = _base(m)
        d.update(flags=_flags_to_list(m.flags), files_scanned=m.files_scanned)
        return d

    def ser_supply(m):
        if m is None:
            return None
        d = _base(m)
        d.update(flags=_flags_to_list(m.flags), dependencies=m.dependencies)
        return d

    def ser_ai(m):
        if m is None:
            return None
        d = _base(m)
        d.update(flags=_flags_to_list(m.flags), summary=m.summary,
                 verdict=m.verdict, backend=m.backend)
        return d

    def ser_ip_rep(m):
        if m is None:
            return None
        d = _base(m)
        d.update(flags=_flags_to_list(m.flags), ips_checked=m.ips_checked)
        return d

    def ser_vt(m):
        if m is None:
            return None
        d = _base(m)
        d.update(
            flags=_flags_to_list(m.flags),
            hash_checked=m.hash_checked,
            detections=m.detections,
            total_engines=m.total_engines,
            detection_names=m.detection_names,
            permalink=m.permalink,
            uploaded=m.uploaded,
        )
        return d

    return {
        "metadata": ser_meta(meta),
        "clamav": ser_clam(clam),
        "static_analysis": ser_static(static),
        "supply_chain": ser_supply(supply),
        "ai_review": ser_ai(ai),
        "ip_reputation": ser_ip_rep(ip_rep),
        "virustotal": ser_vt(vt),
    }


def deserialize_scan_results(data: dict):
    from .models import (
        MetadataResult, ClamAVResult, StaticAnalysisResult,
        SupplyChainResult, AIReviewResult, IPReputationResult, VirusTotalResult, RiskLevel,
    )

    def rl(s):
        return RiskLevel(s)

    def deser_meta(d) -> Optional[MetadataResult]:
        if d is None:
            return None
        return MetadataResult(
            risk=rl(d["risk"]), flags=_flags_from_list(d.get("flags")),
            repo_age_days=d.get("repo_age_days"), stars=d.get("stars"),
            forks=d.get("forks"), contributors=d.get("contributors"),
            is_fork=d.get("is_fork"), skipped=d.get("skipped", False),
            skip_reason=d.get("skip_reason", ""), error=d.get("error"),
        )

    def deser_clam(d) -> Optional[ClamAVResult]:
        if d is None:
            return None
        return ClamAVResult(
            risk=rl(d["risk"]), files_scanned=d.get("files_scanned", 0),
            infected=d.get("infected", []), skipped=d.get("skipped", False),
            skip_reason=d.get("skip_reason", ""), error=d.get("error"),
        )

    def deser_static(d) -> Optional[StaticAnalysisResult]:
        if d is None:
            return None
        return StaticAnalysisResult(
            risk=rl(d["risk"]), flags=_flags_from_list(d.get("flags")),
            files_scanned=d.get("files_scanned", 0), skipped=d.get("skipped", False),
            skip_reason=d.get("skip_reason", ""), error=d.get("error"),
        )

    def deser_supply(d) -> Optional[SupplyChainResult]:
        if d is None:
            return None
        return SupplyChainResult(
            risk=rl(d["risk"]), flags=_flags_from_list(d.get("flags")),
            dependencies=d.get("dependencies", []), skipped=d.get("skipped", False),
            skip_reason=d.get("skip_reason", ""), error=d.get("error"),
        )

    def deser_ai(d) -> Optional[AIReviewResult]:
        if d is None:
            return None
        return AIReviewResult(
            risk=rl(d["risk"]), flags=_flags_from_list(d.get("flags")),
            summary=d.get("summary", ""), verdict=d.get("verdict", ""),
            backend=d.get("backend"), skipped=d.get("skipped", False),
            skip_reason=d.get("skip_reason", ""), error=d.get("error"),
        )

    def deser_ip_rep(d) -> Optional[IPReputationResult]:
        if d is None:
            return None
        return IPReputationResult(
            risk=rl(d["risk"]), flags=_flags_from_list(d.get("flags")),
            ips_checked=d.get("ips_checked", 0), skipped=d.get("skipped", False),
            skip_reason=d.get("skip_reason", ""), error=d.get("error"),
        )

    def deser_vt(d) -> Optional[VirusTotalResult]:
        if d is None:
            return None
        return VirusTotalResult(
            risk=rl(d["risk"]), flags=_flags_from_list(d.get("flags")),
            hash_checked=d.get("hash_checked"), detections=d.get("detections"),
            total_engines=d.get("total_engines"), detection_names=d.get("detection_names", []),
            permalink=d.get("permalink"), uploaded=d.get("uploaded", False),
            skipped=d.get("skipped", False), skip_reason=d.get("skip_reason", ""),
            error=d.get("error"),
        )

    return (
        deser_meta(data.get("metadata")),
        deser_clam(data.get("clamav")),
        deser_static(data.get("static_analysis")),
        deser_supply(data.get("supply_chain")),
        deser_ai(data.get("ai_review")),
        deser_ip_rep(data.get("ip_reputation")),
        deser_vt(data.get("virustotal")),
    )


def compute_directory_hash(directory: str) -> str:
    h = hashlib.sha256()
    base = Path(directory)
    for f in sorted(base.rglob("*")):
        if f.is_file():
            try:
                h.update(str(f.relative_to(base)).encode())
                h.update(f.read_bytes())
            except (OSError, PermissionError):
                pass
    return h.hexdigest()


def compute_string_hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def _cache_path(content_hash: str) -> Path:
    return CACHE_DIR / f"{content_hash}.json"


def load_cache(content_hash: str, ttl_days: int = 7) -> Optional[dict]:
    path = _cache_path(content_hash)
    if not path.exists():
        return None

    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        path.unlink(missing_ok=True)
        return None

    cached_at_str = data.get("cached_at", "")
    if not cached_at_str:
        return None

    try:
        cached_at = datetime.datetime.fromisoformat(cached_at_str)
    except ValueError:
        return None

    age = datetime.datetime.utcnow() - cached_at
    if age.days >= ttl_days:
        path.unlink(missing_ok=True)
        return None

    return data


def save_cache(content_hash: str, report_data: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    payload = dict(report_data)
    payload["cached_at"] = datetime.datetime.utcnow().isoformat()
    _cache_path(content_hash).write_text(json.dumps(payload, indent=2, default=str))


def clear_expired(ttl_days: int = 7) -> int:
    removed = 0
    if not CACHE_DIR.exists():
        return 0
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=ttl_days)
    for f in CACHE_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text())
            ts = datetime.datetime.fromisoformat(data.get("cached_at", "2000-01-01"))
            if ts < cutoff:
                f.unlink()
                removed += 1
        except Exception:
            pass
    return removed
