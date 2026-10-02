"""Semgrep adapter: pattern-based static analysis of the source tree.

Offline by default. ``--config auto`` would log in to the Semgrep registry and
download rules at scan time, which an air-gapped deployment cannot do, so the
rule packs are provisioned once by ``qa_agent seed`` and read from disk.
"""

from __future__ import annotations

import time
from pathlib import Path

from qa_agent.logging_setup import get_logger
from qa_agent.models.run import Verdict
from qa_agent.parsers.semgrep import parse_semgrep
from qa_agent.tools.base import ScanOutcome, ToolContext, load_json
from qa_agent.tools.process import resolve_executable, run_command

log = get_logger(__name__)

TOOL = "semgrep"
# Per-rule-per-file limit; one pathological file must not stall the scan.
PER_RULE_TIMEOUT_S = "30"
# Skip generated bundles and minified assets, which produce noise, not findings.
MAX_TARGET_BYTES = "1000000"


def rescan_semgrep(source: Path, files: list[str], ctx: ToolContext) -> set[str] | None:
    """Re-run Semgrep on just *files* and return the fingerprints it reports.

    Used by verification. Semgrep is deterministic, so this mostly guards
    something else: that a finding's fingerprint is stable. If the same rule on
    the same line produced a different id on a second run, dedup and phase 3's
    consistency metric would both be quietly broken, and this would expose it.
    Returns None when the re-scan itself could not run.
    """
    settings = ctx.settings
    binary = resolve_executable(settings.semgrep_bin, [settings.vendor_bin_dir])
    rules_dir = settings.semgrep_rules_dir
    config = settings.semgrep_config or str(rules_dir)
    if binary is None or not files or (not settings.semgrep_config and not rules_dir.is_dir()):
        return None

    output = ctx.workspace.raw_path("semgrep-verify")
    argv = [
        binary,
        "scan",
        "--config",
        config,
        "--json",
        f"--json-output={output}",
        "--metrics=off",
        "--disable-version-check",
        "--quiet",
        "--timeout",
        PER_RULE_TIMEOUT_S,
        *files,
    ]
    result = run_command(
        argv, timeout=settings.tool_timeout_s, log_path=ctx.command_log, cwd=source
    )
    if result.timed_out or not output.exists():
        return None
    try:
        payload = load_json(output)
    except ValueError:
        return None
    return {f.id for f in parse_semgrep(payload, repo_root=source, rules_dir=rules_dir)}


def run_semgrep(source: Path, ctx: ToolContext) -> ScanOutcome:
    """Scan *source* with Semgrep and return unified findings."""
    settings = ctx.settings
    binary = resolve_executable(settings.semgrep_bin, [settings.vendor_bin_dir])
    if binary is None:
        return ScanOutcome.skipped(TOOL, "semgrep is not installed (see check_env)")

    rules_dir = settings.semgrep_rules_dir
    config = settings.semgrep_config or str(rules_dir)
    if not settings.semgrep_config and not rules_dir.is_dir():
        return ScanOutcome.skipped(
            TOOL, "no offline rule packs found; run 'python -m qa_agent seed' first"
        )

    output = ctx.workspace.raw_path(TOOL)
    argv = [
        binary,
        "scan",
        "--config",
        config,
        "--json",
        f"--json-output={output}",
        "--metrics=off",  # no telemetry to semgrep.dev
        "--disable-version-check",  # no update ping at start-up
        "--quiet",
        "--timeout",
        PER_RULE_TIMEOUT_S,
        "--max-target-bytes",
        MAX_TARGET_BYTES,
        str(source),
    ]

    started = time.perf_counter()
    result = run_command(
        argv, timeout=settings.tool_timeout_s, log_path=ctx.command_log, cwd=source
    )
    elapsed = time.perf_counter() - started

    if result.timed_out:
        return ScanOutcome.of(
            TOOL,
            Verdict.TIMEOUT,
            duration_s=elapsed,
            detail=f"semgrep exceeded {settings.tool_timeout_s}s and was stopped",
        )

    # Semgrep exits non-zero simply because it found something, so the output
    # file is the real signal, not the exit code.
    if not output.exists():
        return ScanOutcome.failed(
            TOOL, f"semgrep produced no output: {result.stderr.strip()[:300]}", elapsed
        )

    try:
        payload = load_json(output)
    except ValueError as exc:
        return ScanOutcome.failed(TOOL, f"semgrep output was not valid JSON: {exc}", elapsed)

    findings = parse_semgrep(payload, repo_root=source, rules_dir=rules_dir)

    scan_errors = len((payload or {}).get("errors", []) or [])
    detail = f"scanned {source.name} with rules from {config}"
    if scan_errors:
        detail += f"; {scan_errors} file(s) could not be parsed"

    log.info("semgrep: %d finding(s) in %.1fs", len(findings), elapsed)
    return ScanOutcome.of(
        TOOL,
        Verdict.OK,
        findings=findings,
        duration_s=elapsed,
        detail=detail,
        raw_output=str(output),
    )
