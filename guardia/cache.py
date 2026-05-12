from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
from typing import Optional

from .config import CACHE_DIR


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
