"""Module: IP Reputation — AbuseIPDB batch lookup for hardcoded IPs found in static analysis."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from ..models import Flag, IPReputationResult, RiskLevel, StaticAnalysisResult

_IP_IN_MSG_RE = re.compile(
    r'\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.'
    r'(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b'
)

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]


def _is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _extract_public_ips(static: StaticAnalysisResult) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for flag in static.flags:
        if flag.category != "network":
            continue
        if "Hardcoded IP" not in flag.message:
            continue
        for ip in _IP_IN_MSG_RE.findall(flag.message):
            if ip not in seen and not _is_private(ip):
                seen.add(ip)
                result.append(ip)
    return result


def analyze(
    static: StaticAnalysisResult,
    config: dict,
    verbose: bool = False,
) -> IPReputationResult:
    cfg_ip = config.get("abuseipdb", {})
    if not cfg_ip.get("enabled", True):
        return IPReputationResult(
            risk=RiskLevel.SKIPPED, skipped=True, skip_reason="AbuseIPDB disabled in config"
        )

    ips = _extract_public_ips(static)
    if not ips:
        return IPReputationResult(
            risk=RiskLevel.SKIPPED, skipped=True, skip_reason="No hardcoded public IPs found"
        )

    from ..config import get_abuseipdb_key
    api_key = get_abuseipdb_key(config)
    if not api_key:
        return IPReputationResult(
            risk=RiskLevel.SKIPPED,
            skipped=True,
            skip_reason=f"{len(ips)} hardcoded IP(s) found but no AbuseIPDB key — run --setup to add one",
        )

    if verbose:
        print(f"  → AbuseIPDB batch lookup for {len(ips)} IP(s): {', '.join(ips)}")

    return _check_abuseipdb(ips, api_key, config, verbose)


def _check_abuseipdb(
    ips: list[str], api_key: str, config: dict, verbose: bool
) -> IPReputationResult:
    cfg = config.get("abuseipdb", {})
    max_age = cfg.get("max_age_days", 30)
    warn_threshold = cfg.get("min_score_warn", 11)
    critical_threshold = cfg.get("min_score_critical", 51)

    # AbuseIPDB has no bulk-check endpoint — check each IP individually via GET.
    batch = ips[:20]  # cap to avoid burning rate limit on large scans
    flags: list[Flag] = []
    checked = 0

    for ip in batch:
        params = urlencode({"ipAddress": ip, "maxAgeInDays": max_age})
        req = Request(
            f"https://api.abuseipdb.com/api/v2/check?{params}",
            headers={"Key": api_key, "Accept": "application/json"},
        )
        try:
            with urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
        except HTTPError as exc:
            if exc.code == 401:
                return IPReputationResult(
                    risk=RiskLevel.SKIPPED, skipped=True,
                    skip_reason="AbuseIPDB API key invalid (401)",
                )
            if exc.code == 429:
                skip_msg = f"AbuseIPDB rate limit hit after {checked} IP(s)"
                if checked == 0:
                    return IPReputationResult(risk=RiskLevel.SKIPPED, skipped=True, skip_reason=skip_msg)
                break
            return IPReputationResult(
                risk=RiskLevel.SKIPPED, skipped=True,
                skip_reason=f"AbuseIPDB API error: HTTP {exc.code}",
            )
        except (URLError, OSError) as exc:
            return IPReputationResult(
                risk=RiskLevel.SKIPPED, skipped=True,
                skip_reason=f"AbuseIPDB network error: {exc}",
            )

        checked += 1
        entry = data.get("data", {})
        score = entry.get("abuseConfidenceScore", 0)
        isp = entry.get("isp", "unknown ISP")
        country = entry.get("countryCode", "??")
        total_reports = entry.get("totalReports", 0)
        usage = entry.get("usageType", "")

        ctx_parts = [f"score {score}/100", f"ISP: {isp}", f"country: {country}"]
        if total_reports:
            ctx_parts.append(f"{total_reports} reports")
        if usage:
            ctx_parts.append(usage)
        ctx = ", ".join(ctx_parts)

        if score >= critical_threshold:
            flags.append(Flag(
                message=f"Malicious IP {ip} — AbuseIPDB confidence {score}/100 ({ctx})",
                severity="critical",
                category="ip_reputation",
            ))
        elif score >= warn_threshold:
            flags.append(Flag(
                message=f"Suspicious IP {ip} — AbuseIPDB confidence {score}/100 ({ctx})",
                severity="warn",
                category="ip_reputation",
            ))
        elif verbose:
            flags.append(Flag(
                message=f"IP {ip} — clean reputation ({ctx})",
                severity="info",
                category="ip_reputation",
            ))

    risk = _compute_risk(flags)
    return IPReputationResult(risk=risk, ips_checked=checked, flags=flags)


def _compute_risk(flags: list[Flag]) -> RiskLevel:
    if not flags:
        return RiskLevel.LOW
    severities = {f.severity for f in flags}
    if "critical" in severities:
        return RiskLevel.CRITICAL
    if "warn" in severities:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
