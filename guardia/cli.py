"""guardia CLI — multi-layered security analysis for packages, repos, and local directories."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Optional

import click

from . import __version__
from .cache import (
    clear_expired,
    compute_directory_hash,
    compute_string_hash,
    deserialize_scan_results,
    load_cache,
    save_cache,
    serialize_scan_results,
)
from .config import CONFIG_FILE, get_anthropic_key, load_config, save_config
from .models import GuardiaReport, RiskLevel
from .modules import ai_review, clamav, metadata, report, resolver, static_analysis, supply_chain


# ---------------------------------------------------------------------------
# Setup wizard
# ---------------------------------------------------------------------------

def _run_setup(ctx: click.Context, _param: click.Parameter, value: bool) -> None:
    if not value or ctx.resilient_parsing:
        return

    click.echo("\nguardia setup\n" + "─" * 40)
    cfg = load_config()
    changed = False

    # ── ClamAV ──────────────────────────────────────────────────────────────
    click.echo("\n[1/2] ClamAV antivirus")
    if clamav.check_installed():
        age = clamav.definitions_age_days()
        if age is None:
            click.echo("  ✓ ClamAV installed (definition age unknown)")
        elif age >= 1:
            click.echo(f"  ✓ ClamAV installed, definitions are {age} day(s) old")
            if click.confirm("  Update virus definitions now?", default=True):
                click.echo("  Updating…")
                clamav.update_definitions()
                click.echo("  ✓ Definitions updated")
        else:
            click.echo("  ✓ ClamAV installed, definitions up to date")
    else:
        click.echo("  ✗ ClamAV not found")
        if click.confirm("  Install ClamAV via Homebrew now?", default=True):
            click.echo("  Installing…")
            if clamav.install_clamav():
                click.echo("  ✓ ClamAV installed")
            else:
                click.echo("  ✗ Installation failed — install manually: brew install clamav")
        else:
            click.echo("  ⚠ Skipping — antivirus scans will be unavailable")

    # ── AI backend ──────────────────────────────────────────────────────────
    click.echo("\n[2/2] AI code review backend")

    existing_key = get_anthropic_key(cfg)
    claude_cli = shutil.which("claude")

    if existing_key:
        source = "environment variable" if os.environ.get("ANTHROPIC_API_KEY") else "config file"
        click.echo(f"  ✓ ANTHROPIC_API_KEY found ({source})")
    else:
        click.echo("  ✗ ANTHROPIC_API_KEY not set")

    if claude_cli:
        click.echo(f"  ✓ Claude CLI found at {claude_cli}")
    else:
        click.echo("  ✗ Claude CLI not found on PATH")

    if not existing_key and not claude_cli:
        click.echo("\n  Choose an AI backend:")
        click.echo("    1) Enter an Anthropic API key (saved to ~/.guardia/config.toml)")
        click.echo("    2) Install Claude CLI (brew install --cask claude)")
        click.echo("    3) Skip — AI review will be disabled")
        choice = click.prompt("  Choice", type=click.Choice(["1", "2", "3"]), default="1")

        if choice == "1":
            key = click.prompt("  Paste your ANTHROPIC_API_KEY", hide_input=True).strip()
            if key:
                cfg["api"]["anthropic_key"] = key
                changed = True
                click.echo("  ✓ API key saved to ~/.guardia/config.toml")
            else:
                click.echo("  ⚠ Empty key — skipping")
        elif choice == "2":
            click.echo("  Run: brew install --cask claude")
            click.echo("  Then re-run: guardia --setup")
        else:
            click.echo("  ⚠ AI review will be skipped during scans")

    if changed:
        save_config(cfg)

    # ── Summary ─────────────────────────────────────────────────────────────
    click.echo("\n" + "─" * 40)
    click.echo(f"Config file: {CONFIG_FILE}")
    click.echo("Setup complete. Run `guardia --help` to get started.\n")
    ctx.exit()


# ---------------------------------------------------------------------------
# CLI definition
# ---------------------------------------------------------------------------

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, "-V", "--version")
@click.option("--setup", is_flag=True, is_eager=True, expose_value=False, callback=_run_setup,
              help="Run the interactive setup wizard (ClamAV + AI backend)")
# Target selection (mutually exclusive, at least one required)
@click.option("--brew", "target_brew", metavar="FORMULA",
              help="Analyze a Homebrew formula (e.g. ffmpeg, org/tap/formula)")
@click.option("--git",  "target_git",  metavar="URL",
              help="Clone and analyze a remote Git repository")
@click.option("--local","target_local",metavar="PATH",
              help="Analyze a local directory or file")
# Scan depth
@click.option("--deep", is_flag=True, default=False,
              help="Run a thorough Claude review (more tokens, more time, higher cost)")
@click.option("--chunking", type=click.Choice(["sliding-window", "file-by-file"]),
              default="sliding-window", show_default=True,
              help="Chunking strategy for deep review")
# Output
@click.option("--output", "-o", "output_fmt",
              type=click.Choice(["terminal", "json", "markdown"]),
              default=None,
              help="Output format (default: terminal)")
# Module toggles
@click.option("--no-clam", is_flag=True, default=False,
              help="Skip ClamAV antivirus scan")
@click.option("--no-ai",   is_flag=True, default=False,
              help="Skip Claude AI code review")
# Caching
@click.option("--cache",  is_flag=True, default=False,
              help="Use cached results for previously scanned targets")
@click.option("--force",  is_flag=True, default=False,
              help="Ignore cache and re-run all checks")
# Verbosity
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Print detailed step-by-step progress")
@click.option("--quiet",   "-q", is_flag=True, default=False,
              help="Only print the final verdict line")
def main(
    target_brew: Optional[str],
    target_git: Optional[str],
    target_local: Optional[str],
    deep: bool,
    chunking: str,
    output_fmt: Optional[str],
    no_clam: bool,
    no_ai: bool,
    cache: bool,
    force: bool,
    verbose: bool,
    quiet: bool,
) -> None:
    """guardia — security analysis before you install.

    \b
    Examples:
      guardia --brew wyattjoh/claude-code-notification
      guardia --git https://github.com/example/tool
      guardia --local ~/Downloads/some-package
      guardia --git https://github.com/example/tool --deep --no-clam --output json
    """
    # ------------------------------------------------------------------ setup
    cfg = load_config()

    if output_fmt is None:
        output_fmt = cfg.get("defaults", {}).get("output_format", "terminal")

    if not cache:
        cache = cfg.get("defaults", {}).get("use_cache", False)

    ttl_days = cfg.get("defaults", {}).get("cache_ttl_days", 7)
    clear_expired(ttl_days)

    # ----------------------------------------------------------------- target
    target_type, target_value = _resolve_target_args(target_brew, target_git, target_local)

    # ------------------------------------------------------- first-run prompts
    if not no_ai:
        _maybe_prompt_api_key(cfg)

    # -------------------------------------------- resolve & fetch
    if not quiet:
        _echo_step("Resolving target…", verbose)

    try:
        scan_target = resolver.resolve(target_type, target_value, verbose=verbose)
    except RuntimeError as exc:
        _fatal(str(exc))

    # ------------------------------------------------------ cache check
    content_hash: Optional[str] = None
    if (cache or cfg.get("defaults", {}).get("use_cache", False)) and not force:
        if scan_target.local_path:
            try:
                content_hash = compute_directory_hash(scan_target.local_path)
            except Exception:
                content_hash = compute_string_hash(target_value)
        else:
            content_hash = compute_string_hash(target_value)

        cached = load_cache(content_hash, ttl_days)
        if cached and "metadata" in cached:
            if verbose:
                click.echo("  ← Returning cached result")
            meta_r, clam_r, static_r, supply_r, ai_r = deserialize_scan_results(cached)
            if no_clam:
                from .models import ClamAVResult
                clam_r = ClamAVResult(risk=RiskLevel.SKIPPED, skipped=True, skip_reason="Skipped via --no-clam")
            if no_ai:
                from .models import AIReviewResult
                ai_r = AIReviewResult(risk=RiskLevel.SKIPPED, skipped=True, skip_reason="Skipped via --no-ai")
            cached_report = report.build_report(scan_target, meta_r, clam_r, static_r, supply_r, ai_r)
            click.echo(report.render(cached_report, output_fmt, quiet=quiet))
            resolver.cleanup(scan_target)
            sys.exit(0)

    # -------------------------------------------------------- module pipeline
    meta_result = None
    clam_result = None
    static_result = None
    supply_result = None
    ai_result = None

    # Module 2: Metadata & Reputation
    if not quiet:
        _echo_step("Checking metadata & reputation…", verbose)
    meta_result = metadata.analyze(scan_target, cfg, verbose=verbose)

    # Module 3: ClamAV
    if not no_clam:
        if not quiet:
            _echo_step("Running ClamAV scan…", verbose)
        clam_result = _run_clamav(scan_target, cfg, verbose, quiet)
    else:
        from .models import ClamAVResult
        clam_result = ClamAVResult(
            risk=RiskLevel.SKIPPED, skipped=True, skip_reason="Skipped via --no-clam"
        )

    # Module 4: Static Analysis
    if not quiet:
        _echo_step("Running static analysis…", verbose)
    static_result = static_analysis.analyze(scan_target, verbose=verbose)

    # Module 5: Supply Chain
    if not quiet:
        _echo_step("Analyzing supply chain…", verbose)
    supply_result = supply_chain.analyze(scan_target, verbose=verbose)

    # Module 6: AI Review
    if not no_ai:
        if not quiet:
            _echo_step("Running AI code review…", verbose)
        chunking_strategy = chunking.replace("-", "_")
        ai_result = ai_review.review(
            scan_target,
            cfg,
            deep=deep,
            chunking=chunking_strategy,
            verbose=verbose,
        )
    else:
        from .models import AIReviewResult
        ai_result = AIReviewResult(
            risk=RiskLevel.SKIPPED, skipped=True, skip_reason="Skipped via --no-ai"
        )

    # -------------------------------------------------------- report
    final_report = report.build_report(
        scan_target, meta_result, clam_result, static_result, supply_result, ai_result
    )
    output_text = report.render(final_report, output_fmt, quiet=quiet)
    click.echo(output_text)

    # -------------------------------------------------------- cache save
    if content_hash:
        try:
            save_cache(content_hash, serialize_scan_results(
                meta_result, clam_result, static_result, supply_result, ai_result
            ))
        except Exception:
            pass

    # -------------------------------------------------------- cleanup
    resolver.cleanup(scan_target)

    # Exit code reflects overall risk
    sys.exit(_exit_code(final_report.overall_risk))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_target_args(brew, git, local) -> tuple[str, str]:
    targets = [(kind, val) for kind, val in [
        ("brew",  brew),
        ("git",   git),
        ("local", local),
    ] if val]

    if len(targets) == 0:
        click.echo(
            "Error: specify one of --brew FORMULA, --git URL, or --local PATH\n"
            "Run with --help for usage.",
            err=True,
        )
        sys.exit(1)

    if len(targets) > 1:
        click.echo("Error: only one of --brew, --git, --local may be specified at a time.", err=True)
        sys.exit(1)

    return targets[0]


def _run_clamav(scan_target, cfg, verbose: bool, quiet: bool):
    from .models import ClamAVResult

    if not clamav.check_installed():
        if not quiet:
            click.echo(
                "\n  ClamAV is not installed.",
                err=False,
            )
            if click.confirm("  Install ClamAV via Homebrew now?", default=False):
                click.echo("  Installing ClamAV…")
                if not clamav.install_clamav():
                    click.echo("  ⚠ ClamAV installation failed. Skipping antivirus scan.", err=True)
                    return ClamAVResult(
                        risk=RiskLevel.SKIPPED,
                        skipped=True,
                        skip_reason="ClamAV installation failed",
                    )
            else:
                return ClamAVResult(
                    risk=RiskLevel.SKIPPED,
                    skipped=True,
                    skip_reason="ClamAV not installed — user declined installation",
                )
        else:
            return ClamAVResult(
                risk=RiskLevel.SKIPPED,
                skipped=True,
                skip_reason="ClamAV not installed",
            )

    # Check definition age
    age = clamav.definitions_age_days()
    if age is not None and age >= 1 and not quiet:
        if click.confirm(f"  ClamAV definitions are {age} day(s) old. Update now?", default=False):
            click.echo("  Updating ClamAV definitions…")
            clamav.update_definitions()

    return clamav.scan(scan_target.local_path or ".", verbose=verbose)


def _maybe_prompt_api_key(cfg: dict) -> None:
    key = get_anthropic_key(cfg)
    if key:
        return

    # Only prompt if interactive
    if not sys.stdin.isatty():
        return

    if ai_review.detect_backend(cfg) is None:
        click.echo(
            "\n  No AI backend found. For AI-powered code review you can either:\n"
            "    · Set ANTHROPIC_API_KEY environment variable\n"
            "    · Install Claude CLI: brew install --cask claude\n"
            "  Continuing without AI review.\n"
        )


def _echo_step(msg: str, verbose: bool) -> None:
    if verbose:
        click.echo(f"  → {msg}")


def _fatal(msg: str) -> None:
    click.echo(f"Error: {msg}", err=True)
    sys.exit(1)


def _exit_code(risk: RiskLevel) -> int:
    return {
        RiskLevel.CLEAN: 0,
        RiskLevel.LOW: 0,
        RiskLevel.MEDIUM: 1,
        RiskLevel.HIGH: 2,
        RiskLevel.CRITICAL: 3,
        RiskLevel.SKIPPED: 0,
        RiskLevel.ERROR: 1,
    }.get(risk, 1)


if __name__ == "__main__":
    main()
