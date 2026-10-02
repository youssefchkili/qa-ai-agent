"""Trivy adapter: dependency vulnerabilities, committed secrets, misconfigurations.

Two entry points, because they answer different questions:

``run_trivy_fs``
    scans the source tree. Finds secrets and unsafe Dockerfile/Terraform
    settings, and dependency vulnerabilities *when a lockfile is committed*.
``run_trivy_image``
    scans a built container image. The image contains the dependencies that
    were actually installed, so this works even when the repository commits no
    lockfile (OWASP Juice Shop is exactly that case).
"""

from __future__ import annotations

import time
from pathlib import Path

from qa_agent.logging_setup import get_logger
from qa_agent.models.run import Verdict
from qa_agent.parsers.trivy import parse_trivy
from qa_agent.tools.base import ScanOutcome, ToolContext, load_json
from qa_agent.tools.process import resolve_executable, run_command

log = get_logger(__name__)

TOOL = "trivy"
# Installed or generated files, not the project's own source. Manifests and
# lockfiles already describe the dependencies. Found on a real project: Trivy
# crashed walking a Python virtualenv with thousands of files.
SKIPPED_DIRS = (
    "**/node_modules",
    "**/.venv",
    "**/venv",
    "**/__pycache__",
    "**/.next",
    "**/dist",
    "**/build",
)


def _offline_flags(ctx: ToolContext) -> list[str]:
    """Flags that keep Trivy from reaching the internet mid-scan."""
    settings = ctx.settings
    flags = [
        "--cache-dir",
        str(settings.trivy_cache_dir),
        "--disable-telemetry",  # Trivy reports usage data by default
        "--skip-version-check",
        "-q",
    ]
    if settings.offline:
        flags += [
            "--skip-db-update",  # use the database provisioned by 'seed'
            "--skip-java-db-update",
            "--skip-check-update",  # use the built-in misconfiguration checks
            "--offline-scan",  # never call out to resolve dependencies
        ]
    return flags


def _run(argv: list[str], ctx: ToolContext, output: Path, label: str) -> ScanOutcome:
    """Shared execution and parsing path for both Trivy modes."""
    started = time.perf_counter()
    result = run_command(argv, timeout=ctx.settings.tool_timeout_s, log_path=ctx.command_log)
    elapsed = time.perf_counter() - started

    if result.timed_out:
        return ScanOutcome.of(
            TOOL,
            Verdict.TIMEOUT,
            duration_s=elapsed,
            detail=f"trivy exceeded {ctx.settings.tool_timeout_s}s and was stopped",
        )
    if not output.exists():
        return ScanOutcome.failed(
            TOOL, f"trivy produced no output: {result.stderr.strip()[:300]}", elapsed
        )

    try:
        payload = load_json(output)
    except ValueError as exc:
        return ScanOutcome.failed(TOOL, f"trivy output was not valid JSON: {exc}", elapsed)

    findings = parse_trivy(payload)
    log.info("trivy (%s): %d finding(s) in %.1fs", label, len(findings), elapsed)
    return ScanOutcome.of(
        TOOL,
        Verdict.OK,
        findings=findings,
        duration_s=elapsed,
        detail=label,
        raw_output=str(output),
    )


def run_trivy_fs(source: Path, ctx: ToolContext) -> ScanOutcome:
    """Scan the source tree for vulnerabilities, secrets and misconfigurations."""
    binary = resolve_executable(ctx.settings.trivy_bin, [ctx.settings.vendor_bin_dir])
    if binary is None:
        return ScanOutcome.skipped(TOOL, "trivy is not installed (see check_env)")
    if not ctx.settings.trivy_cache_dir.is_dir() and ctx.settings.offline:
        return ScanOutcome.skipped(
            TOOL, "no offline vulnerability database; run 'python -m qa_agent seed' first"
        )

    output = ctx.workspace.raw_path(TOOL)
    argv = [
        binary,
        "fs",
        "--scanners",
        "vuln,secret,misconfig",
        "-f",
        "json",
        "-o",
        str(output),
        *_offline_flags(ctx),
        *(flag for pattern in SKIPPED_DIRS for flag in ("--skip-dirs", pattern)),
        str(source),
    ]
    return _run(argv, ctx, output, f"filesystem scan of {source.name}")


def run_trivy_image(image: str, ctx: ToolContext) -> ScanOutcome:
    """Scan a built container image for vulnerable installed packages."""
    binary = resolve_executable(ctx.settings.trivy_bin, [ctx.settings.vendor_bin_dir])
    if binary is None:
        return ScanOutcome.skipped(TOOL, "trivy is not installed (see check_env)")

    output = ctx.workspace.raw_path("trivy-image")
    argv = [
        binary,
        "image",
        "--scanners",
        "vuln,secret",
        "-f",
        "json",
        "-o",
        str(output),
        *_offline_flags(ctx),
        image,
    ]
    return _run(argv, ctx, output, f"image scan of {image}")
