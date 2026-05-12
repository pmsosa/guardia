from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskLevel(str, Enum):
    CLEAN = "clean"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    SKIPPED = "skipped"
    ERROR = "error"


# Ordering for aggregation — SKIPPED/ERROR don't contribute to overall risk
RISK_ORDER: dict[RiskLevel, int] = {
    RiskLevel.CLEAN: 0,
    RiskLevel.LOW: 1,
    RiskLevel.SKIPPED: -1,
    RiskLevel.ERROR: -1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}

RISK_COLORS: dict[RiskLevel, str] = {
    RiskLevel.CLEAN: "green",
    RiskLevel.LOW: "green",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
    RiskLevel.CRITICAL: "bright_red",
    RiskLevel.SKIPPED: "dim",
    RiskLevel.ERROR: "yellow",
}

RISK_ICONS: dict[RiskLevel, str] = {
    RiskLevel.CLEAN: "✓",
    RiskLevel.LOW: "✓",
    RiskLevel.MEDIUM: "⚠",
    RiskLevel.HIGH: "✗",
    RiskLevel.CRITICAL: "✗",
    RiskLevel.SKIPPED: "–",
    RiskLevel.ERROR: "?",
}

SEVERITY_ORDER = {"info": 0, "warn": 1, "critical": 2}


@dataclass
class Flag:
    message: str
    severity: str  # "info" | "warn" | "critical"
    file: Optional[str] = None
    line: Optional[int] = None
    category: Optional[str] = None

    def format_location(self) -> str:
        if self.file and self.line:
            return f"{self.file}:{self.line}"
        if self.file:
            return self.file
        return ""


@dataclass
class ScanTarget:
    type: str  # "brew" | "git" | "local"
    raw: str   # original user-supplied value
    local_path: Optional[str] = None
    formula_source: Optional[str] = None  # raw Ruby formula text (brew only)
    metadata: dict = field(default_factory=dict)  # parsed metadata (github_url, sha256, …)
    _cleanup: bool = False  # whether local_path is a temp dir to remove


@dataclass
class MetadataResult:
    risk: RiskLevel
    flags: list[Flag] = field(default_factory=list)
    repo_age_days: Optional[int] = None
    stars: Optional[int] = None
    forks: Optional[int] = None
    contributors: Optional[int] = None
    is_fork: Optional[bool] = None
    skipped: bool = False
    skip_reason: str = ""
    error: Optional[str] = None


@dataclass
class ClamAVResult:
    risk: RiskLevel
    files_scanned: int = 0
    infected: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    error: Optional[str] = None


@dataclass
class StaticAnalysisResult:
    risk: RiskLevel
    flags: list[Flag] = field(default_factory=list)
    files_scanned: int = 0
    skipped: bool = False
    skip_reason: str = ""
    error: Optional[str] = None


@dataclass
class SupplyChainResult:
    risk: RiskLevel
    flags: list[Flag] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""
    error: Optional[str] = None


@dataclass
class AIReviewResult:
    risk: RiskLevel
    summary: str = ""
    flags: list[Flag] = field(default_factory=list)
    verdict: str = ""
    backend: Optional[str] = None  # "api" | "cli"
    skipped: bool = False
    skip_reason: str = ""
    error: Optional[str] = None


@dataclass
class GuardiaReport:
    target: ScanTarget
    timestamp: datetime.datetime
    overall_risk: RiskLevel
    metadata: Optional[MetadataResult] = None
    clamav: Optional[ClamAVResult] = None
    static_analysis: Optional[StaticAnalysisResult] = None
    supply_chain: Optional[SupplyChainResult] = None
    ai_review: Optional[AIReviewResult] = None


def aggregate_risk(levels: list[RiskLevel]) -> RiskLevel:
    """Return the highest risk level, ignoring SKIPPED and ERROR."""
    effective = [l for l in levels if RISK_ORDER.get(l, -1) >= 0]
    if not effective:
        return RiskLevel.LOW
    return max(effective, key=lambda l: RISK_ORDER[l])
