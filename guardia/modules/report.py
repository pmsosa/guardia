"""Module 7 — Report Generation: terminal, JSON, and Markdown output."""

from __future__ import annotations

import datetime
import json
from dataclasses import asdict
from typing import Optional

from ..models import (
    AIReviewResult,
    ClamAVResult,
    Flag,
    GuardiaReport,
    IPReputationResult,
    MetadataResult,
    RiskLevel,
    RISK_COLORS,
    RISK_ICONS,
    StaticAnalysisResult,
    SupplyChainResult,
    VirusTotalResult,
    aggregate_risk,
)


def build_report(
    target,
    metadata: Optional[MetadataResult],
    clamav: Optional[ClamAVResult],
    static: Optional[StaticAnalysisResult],
    supply: Optional[SupplyChainResult],
    ai: Optional[AIReviewResult],
    ip_reputation: Optional[IPReputationResult] = None,
    virustotal: Optional[VirusTotalResult] = None,
) -> GuardiaReport:
    # Static analysis is broad and noisy by design. When the AI review and
    # ClamAV both clear a package, cap static's contribution to MEDIUM so
    # pattern noise doesn't dominate the verdict. CRITICAL (pipe-to-shell) is
    # never capped — that pattern is almost never a false positive.
    ai_clear = ai is not None and not ai.skipped and ai.risk in (RiskLevel.LOW, RiskLevel.CLEAN)
    clamav_no_threat = clamav is None or clamav.skipped or clamav.risk == RiskLevel.CLEAN
    effective_static_risk = static.risk if static else None
    if effective_static_risk == RiskLevel.HIGH and ai_clear and clamav_no_threat:
        effective_static_risk = RiskLevel.MEDIUM

    active_risks = [
        r.risk for r in [metadata, clamav, supply, ai, ip_reputation, virustotal]
        if r is not None
    ]
    if effective_static_risk is not None:
        active_risks.append(effective_static_risk)
    overall = aggregate_risk(active_risks)

    return GuardiaReport(
        target=target,
        timestamp=datetime.datetime.utcnow(),
        overall_risk=overall,
        metadata=metadata,
        clamav=clamav,
        static_analysis=static,
        supply_chain=supply,
        ai_review=ai,
        ip_reputation=ip_reputation,
        virustotal=virustotal,
    )


# ---------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------

def render(report: GuardiaReport, fmt: str, quiet: bool = False) -> str:
    if fmt == "json":
        return _render_json(report)
    if fmt == "markdown":
        return _render_markdown(report)
    return _render_terminal(report, quiet)


# ---------------------------------------------------------------------------
# Terminal output (rich)
# ---------------------------------------------------------------------------

def _render_terminal(report: GuardiaReport, quiet: bool) -> str:
    try:
        import io
        import sys
        from rich.console import Console
        buf = io.StringIO()
        console = Console(file=buf, highlight=False, markup=True, force_terminal=sys.stdout.isatty())
        _rich_report(console, report, quiet)
        return buf.getvalue()
    except ImportError:
        return _render_plain(report, quiet)


def _rich_report(console, report: GuardiaReport, quiet: bool) -> None:
    from rich.panel import Panel
    from rich.rule import Rule
    from rich import box

    ts = report.timestamp.strftime("%Y-%m-%d %H:%M UTC")
    target_label = f"[bold]{report.target.raw}[/bold]  [dim]({report.target.type})[/dim]"

    if not quiet:
        console.print(Panel(
            f"  [bold]Target:[/bold]   {target_label}\n"
            f"  [bold]Scanned:[/bold]  [dim]{ts}[/dim]",
            title="[bold blue]⛨  guardia[/bold blue]",
            box=box.ROUNDED,
            border_style="blue",
            expand=False,
            padding=(0, 2),
        ))
        console.print()
        console.print(Rule("[dim]scan results[/dim]", style="dim"))
        console.print()
        _print_module_row(console, "Metadata & Reputation", report.metadata)
        _print_module_row(console, "ClamAV Scan", report.clamav)
        _print_module_row(console, "Static Analysis", report.static_analysis)
        _print_module_row(console, "Supply Chain", report.supply_chain)
        _print_module_row(console, "IP Reputation (AbuseIPDB)", report.ip_reputation)
        _print_vt_row(console, report.virustotal)
        _print_ai_row(console, report.ai_review)
        console.print()

    risk_color = RISK_COLORS.get(report.overall_risk, "white")
    icon = RISK_ICONS.get(report.overall_risk, "?")
    verdict_text = _overall_verdict_text(report)

    console.print(Panel(
        f"  [{risk_color}][bold]{icon}  {report.overall_risk.upper()}[/bold]  {verdict_text}[/{risk_color}]",
        title="[bold]verdict[/bold]",
        box=box.HEAVY,
        border_style=risk_color,
        expand=False,
        padding=(0, 1),
    ))

    if not quiet:
        _print_issues(console, report)


def _print_module_row(console, label: str, result) -> None:
    if result is None:
        return
    risk = result.risk
    color = RISK_COLORS.get(risk, "white")
    icon = RISK_ICONS.get(risk, "?")
    risk_label = "SKIPPED" if result.skipped else risk.upper()

    detail = _module_detail(result)
    console.print(
        f"  [{color}][{icon}] {label:<30} [bold]{risk_label}[/bold][/{color}]"
    )
    if detail:
        console.print(f"      [dim]{detail}[/dim]")


def _print_vt_row(console, result: Optional[VirusTotalResult]) -> None:
    if result is None:
        return
    risk = result.risk
    color = RISK_COLORS.get(risk, "white")
    icon = RISK_ICONS.get(risk, "?")
    risk_label = "SKIPPED" if result.skipped else risk.upper()
    console.print(
        f"  [{color}][{icon}] {'VirusTotal':<30} [bold]{risk_label}[/bold][/{color}]"
    )
    if result.skipped and result.skip_reason:
        console.print(f"      [dim]{result.skip_reason}[/dim]")
    elif result.detections is not None:
        det = f"{result.detections}/{result.total_engines} engines"
        uploaded_note = " (uploaded)" if result.uploaded else ""
        link = f"  [dim link={result.permalink}]{result.permalink}[/dim link]" if result.permalink else ""
        console.print(f"      [dim]{det}{uploaded_note}{link}[/dim]")


def _print_ai_row(console, result: Optional[AIReviewResult]) -> None:
    if result is None:
        return
    risk = result.risk
    color = RISK_COLORS.get(risk, "white")
    icon = RISK_ICONS.get(risk, "?")
    risk_label = "SKIPPED" if result.skipped else risk.upper()

    backend_tag = f"  [dim][via {result.backend}][/dim]" if result.backend else ""
    console.print(
        f"  [{color}][{icon}] {'Claude AI Review':<30} [bold]{risk_label}[/bold][/{color}]{backend_tag}"
    )

    if result.skipped and result.skip_reason:
        console.print(f"      [dim]{result.skip_reason}[/dim]")
    else:
        files_note = f"{result.files_checked} file(s) reviewed. " if result.files_checked is not None else ""
        blurb = result.verdict or result.summary or ""
        console.print(f"      [dim]{files_note}{blurb[:120]}[/dim]")


def _print_issues(console, report: GuardiaReport) -> None:
    all_flags: list[Flag] = []
    for module in [
        report.metadata, report.static_analysis, report.supply_chain,
        report.ip_reputation, report.virustotal, report.ai_review,
    ]:
        if module and hasattr(module, "flags"):
            all_flags.extend(module.flags)

    warn_flags = [f for f in all_flags if f.severity in ("warn", "critical")]
    if not warn_flags:
        console.print("  [green dim]✓  No issues flagged[/green dim]")
        return

    console.print()
    console.print("  [bold]Issues[/bold]")
    for f in warn_flags[:20]:
        loc = f"  [dim]{f.format_location()}[/dim]" if f.format_location() else ""
        sev_color = "bright_red" if f.severity == "critical" else "yellow"
        console.print(f"    [{sev_color}]▸[/{sev_color}]{loc}  {f.message}")

    if len(warn_flags) > 20:
        console.print(f"    [dim]… and {len(warn_flags) - 20} more  (use --output json for full list)[/dim]")


def _module_detail(result) -> str:
    if result.skipped and hasattr(result, "skip_reason") and result.skip_reason:
        return result.skip_reason[:100]
    if isinstance(result, ClamAVResult):
        if result.infected:
            return f"{len(result.infected)} infected file(s) detected!"
        return f"{result.files_scanned} file(s) scanned. No threats detected."
    if isinstance(result, MetadataResult):
        parts = []
        if result.repo_age_days is not None:
            age = f"{result.repo_age_days // 365}y" if result.repo_age_days >= 365 else f"{result.repo_age_days}d"
            parts.append(f"Repo age: {age}")
        if result.stars is not None:
            parts.append(f"Stars: {result.stars}")
        if result.contributors is not None:
            parts.append(f"Contributors: {result.contributors}")
        if result.is_fork:
            parts.append("FORK")
        return " | ".join(parts) if parts else ""
    if isinstance(result, StaticAnalysisResult):
        n = len(result.flags)
        return f"{result.files_scanned} file(s) scanned. {n} flag(s)." if n else f"{result.files_scanned} file(s) scanned. No flags."
    if isinstance(result, SupplyChainResult):
        n_deps = len(result.dependencies)
        n_flags = len(result.flags)
        dep_str = f"{n_deps} dependencies. " if n_deps else ""
        flag_str = f"{n_flags} flag(s)." if n_flags else "No flags."
        return dep_str + flag_str
    if isinstance(result, IPReputationResult):
        if not result.flags:
            return f"{result.ips_checked} IP(s) checked. All clean."
        warn = sum(1 for f in result.flags if f.severity in ("warn", "critical"))
        return f"{result.ips_checked} IP(s) checked. {warn} suspicious."
    if isinstance(result, VirusTotalResult):
        if result.detections is not None:
            return f"{result.detections}/{result.total_engines} engines flagged."
        return ""
    return ""


def _overall_verdict_text(report: GuardiaReport) -> str:
    risk = report.overall_risk
    if risk == RiskLevel.CLEAN or risk == RiskLevel.LOW:
        return "Likely safe to install"
    if risk == RiskLevel.MEDIUM:
        return "Review flagged issues before installing"
    if risk == RiskLevel.HIGH:
        return "High risk — do not install without thorough manual review"
    if risk == RiskLevel.CRITICAL:
        return "CRITICAL — malicious behavior detected"
    return "Unknown risk level"


# ---------------------------------------------------------------------------
# Plain text fallback (no rich)
# ---------------------------------------------------------------------------

def _render_plain(report: GuardiaReport, quiet: bool) -> str:
    lines: list[str] = []
    sep = "━" * 48

    ts = report.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    target_label = f"{report.target.raw} ({report.target.type})"

    if not quiet:
        lines += [sep, f"  guardia report", f"  Target:  {target_label}", f"  Scanned: {ts}", sep, ""]

        def row(label, result):
            if result is None:
                return
            icon = RISK_ICONS.get(result.risk, "?")
            rl = "SKIPPED" if result.skipped else result.risk.upper()
            lines.append(f"  [{icon}] {label:<30} {rl}")
            detail = _module_detail(result)
            if detail:
                lines.append(f"      {detail}")

        row("Metadata & Reputation", report.metadata)
        row("ClamAV Scan", report.clamav)
        row("Static Analysis", report.static_analysis)
        row("Supply Chain", report.supply_chain)
        row("IP Reputation (AbuseIPDB)", report.ip_reputation)
        row("VirusTotal", report.virustotal)
        if report.ai_review:
            ai = report.ai_review
            icon = RISK_ICONS.get(ai.risk, "?")
            rl = "SKIPPED" if ai.skipped else ai.risk.upper()
            backend_tag = f" [via {ai.backend}]" if ai.backend else ""
            lines.append(f"  [{icon}] {'Claude AI Review':<30} {rl}{backend_tag}")
            if ai.verdict:
                lines.append(f"      {ai.verdict[:120]}")
        lines.append("")

    icon = RISK_ICONS.get(report.overall_risk, "?")
    verdict = _overall_verdict_text(report)
    lines += [
        sep,
        f"  {icon} OVERALL VERDICT: {report.overall_risk.upper()} — {verdict}",
        sep,
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def _render_json(report: GuardiaReport) -> str:
    def flags_to_list(flags):
        return [
            {
                "message": f.message,
                "severity": f.severity,
                "file": f.file,
                "line": f.line,
                "category": f.category,
            }
            for f in (flags or [])
        ]

    def module_to_dict(m):
        if m is None:
            return None
        base = {"risk": m.risk.value, "skipped": m.skipped}
        if hasattr(m, "skip_reason"):
            base["skip_reason"] = m.skip_reason
        if hasattr(m, "flags"):
            base["flags"] = flags_to_list(m.flags)
        if isinstance(m, ClamAVResult):
            base["files_scanned"] = m.files_scanned
            base["infected"] = m.infected
        if isinstance(m, MetadataResult):
            base["repo_age_days"] = m.repo_age_days
            base["stars"] = m.stars
            base["forks"] = m.forks
            base["contributors"] = m.contributors
            base["is_fork"] = m.is_fork
        if isinstance(m, StaticAnalysisResult):
            base["files_scanned"] = m.files_scanned
        if isinstance(m, SupplyChainResult):
            base["dependencies"] = m.dependencies
        if isinstance(m, AIReviewResult):
            base["summary"] = m.summary
            base["verdict"] = m.verdict
            base["backend"] = m.backend
            base["files_checked"] = m.files_checked
        return base

    def module_to_dict_ext(m):
        if m is None:
            return None
        d = module_to_dict(m)
        if isinstance(m, IPReputationResult):
            d["ips_checked"] = m.ips_checked
        if isinstance(m, VirusTotalResult):
            d["hash_checked"] = m.hash_checked
            d["detections"] = m.detections
            d["total_engines"] = m.total_engines
            d["detection_names"] = m.detection_names
            d["permalink"] = m.permalink
            d["uploaded"] = m.uploaded
        return d

    data = {
        "target": report.target.raw,
        "type": report.target.type,
        "timestamp": report.timestamp.isoformat() + "Z",
        "overall_risk": report.overall_risk.value,
        "modules": {
            "metadata": module_to_dict(report.metadata),
            "clamav": module_to_dict(report.clamav),
            "static_analysis": module_to_dict(report.static_analysis),
            "supply_chain": module_to_dict(report.supply_chain),
            "ip_reputation": module_to_dict_ext(report.ip_reputation),
            "virustotal": module_to_dict_ext(report.virustotal),
            "claude_review": module_to_dict(report.ai_review),
        },
    }
    return json.dumps(data, indent=2)


# ---------------------------------------------------------------------------
# Markdown output
# ---------------------------------------------------------------------------

def _render_markdown(report: GuardiaReport) -> str:
    lines: list[str] = []
    ts = report.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
    target_label = f"{report.target.raw} ({report.target.type})"

    lines += [
        "# guardia Security Report",
        "",
        f"**Target:** {target_label}  ",
        f"**Scanned:** {ts}  ",
        f"**Overall Risk:** {report.overall_risk.upper()}",
        "",
        "---",
        "",
        "## Module Results",
        "",
    ]

    def md_module(title: str, result) -> None:
        if result is None:
            return
        icon = RISK_ICONS.get(result.risk, "?")
        rl = "SKIPPED" if result.skipped else result.risk.upper()
        lines.append(f"### {icon} {title} — {rl}")
        lines.append("")
        detail = _module_detail(result)
        if detail:
            lines.append(detail)
            lines.append("")
        if hasattr(result, "flags") and result.flags:
            lines.append("**Flags:**")
            for f in result.flags:
                loc = f" `{f.format_location()}`" if f.format_location() else ""
                lines.append(f"- [{f.severity.upper()}]{loc} {f.message}")
            lines.append("")

    md_module("Metadata & Reputation", report.metadata)
    md_module("ClamAV Scan", report.clamav)
    md_module("Static Analysis", report.static_analysis)
    md_module("Supply Chain", report.supply_chain)
    md_module("IP Reputation (AbuseIPDB)", report.ip_reputation)
    md_module("VirusTotal", report.virustotal)

    if report.ai_review:
        ai = report.ai_review
        icon = RISK_ICONS.get(ai.risk, "?")
        rl = "SKIPPED" if ai.skipped else ai.risk.upper()
        backend_tag = f" *(via {ai.backend})*" if ai.backend else ""
        lines.append(f"### {icon} Claude AI Review — {rl}{backend_tag}")
        lines.append("")
        if ai.summary:
            lines.append(ai.summary)
            lines.append("")
        if ai.flags:
            lines.append("**Flags:**")
            for f in ai.flags:
                loc = f" `{f.format_location()}`" if f.format_location() else ""
                lines.append(f"- [{f.severity.upper()}]{loc} {f.message}")
            lines.append("")
        if ai.verdict:
            lines.append(f"**Verdict:** {ai.verdict}")
            lines.append("")

    lines += [
        "---",
        "",
        f"## Overall Verdict",
        "",
        f"**{report.overall_risk.upper()} — {_overall_verdict_text(report)}**",
        "",
        f"*Generated by [guardia](https://github.com/pmsosa/guardia)*",
    ]

    return "\n".join(lines)
