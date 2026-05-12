from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[no-redef]
    except ImportError:
        tomllib = None  # type: ignore[assignment]

try:
    import tomli_w  # type: ignore
    _HAS_TOMLI_W = True
except ImportError:
    _HAS_TOMLI_W = False

CONFIG_DIR = Path.home() / ".guardia"
CONFIG_FILE = CONFIG_DIR / "config.toml"
CACHE_DIR = CONFIG_DIR / "cache"

DEFAULT_CONFIG: dict = {
    "api": {
        "anthropic_key": "",
        "claude_backend": "auto",  # "auto" | "api" | "cli"
    },
    "defaults": {
        "output_format": "terminal",
        "use_cache": True,
        "cache_ttl_days": 7,
        "deep_review": False,
        "chunking_strategy": "sliding_window",  # "sliding_window" | "file_by_file"
    },
    "clam": {
        "enabled": True,
        "freshclam_on_run": False,
    },
    "thresholds": {
        "repo_age_warn_days": 30,
        "repo_stars_warn_below": 10,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_config() -> dict:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if not CONFIG_FILE.exists():
        _write_default_config()
        return dict(DEFAULT_CONFIG)

    if tomllib is None:
        # Fall back to basic parsing when no TOML library is available
        return dict(DEFAULT_CONFIG)

    with CONFIG_FILE.open("rb") as fh:
        loaded = tomllib.load(fh)

    return _deep_merge(DEFAULT_CONFIG, loaded)


def _write_default_config() -> None:
    if _HAS_TOMLI_W:
        import tomli_w
        with CONFIG_FILE.open("wb") as fh:
            tomli_w.dump(DEFAULT_CONFIG, fh)
    else:
        # Write a minimal TOML by hand so we don't require a write library
        lines = [
            "[api]",
            'anthropic_key = ""',
            'claude_backend = "auto"',
            "",
            "[defaults]",
            'output_format = "terminal"',
            "use_cache = true",
            "cache_ttl_days = 7",
            "deep_review = false",
            'chunking_strategy = "sliding_window"',
            "",
            "[clam]",
            "enabled = true",
            "freshclam_on_run = false",
            "",
            "[thresholds]",
            "repo_age_warn_days = 30",
            "repo_stars_warn_below = 10",
        ]
        CONFIG_FILE.write_text("\n".join(lines) + "\n")


def save_config(config: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if _HAS_TOMLI_W:
        import tomli_w
        with CONFIG_FILE.open("wb") as fh:
            tomli_w.dump(config, fh)
    else:
        # Minimal update: rewrite key=value lines for the [api] section only
        lines = CONFIG_FILE.read_text().splitlines() if CONFIG_FILE.exists() else []
        new_lines: list[str] = []
        section = ""
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("["):
                section = stripped[1:stripped.index("]")]
                new_lines.append(line)
            elif "=" in stripped and section in config:
                key = stripped.split("=")[0].strip()
                if key in config[section]:
                    val = config[section][key]
                    if isinstance(val, str):
                        new_lines.append(f'{key} = "{val}"')
                    elif isinstance(val, bool):
                        new_lines.append(f'{key} = {"true" if val else "false"}')
                    else:
                        new_lines.append(f"{key} = {val}")
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        CONFIG_FILE.write_text("\n".join(new_lines) + "\n")


def get_anthropic_key(config: dict) -> Optional[str]:
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if key:
        return key
    stored = config.get("api", {}).get("anthropic_key", "")
    return stored or None
