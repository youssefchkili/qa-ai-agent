"""OSV-Scanner adapter: a second, independent opinion on dependency risk.

Running OSV alongside Trivy is deliberate. They draw on overlapping but not
identical advisory data, so a vulnerability reported by both is strong evidence
it is real, and one reported by only one is worth a closer look. The report
records which tools agreed.

Offline notes:

* ``--offline-vulnerabilities`` uses the database provisioned by ``seed``.
* ``--data-source native`` stops OSV querying deps.dev for package metadata.
* ``--no-resolve`` stops it resolving manifests (requirements.txt) into their
  transitive dependencies, which queries the package registry. Found by the
  evaluation: with it on, results varied with whether PyPI was reachable.
* Exit code 128 means "no package sources found" (no lockfile), which is a
  legitimate outcome, not a failure.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

from qa_agent.logging_setup import get_logger
from qa_agent.models.run import Verdict
from qa_agent.parsers.osv import parse_osv
from qa_agent.tools.base import ScanOutcome, ToolContext, load_json
from qa_agent.tools.process import resolve_executable, run_command

log = get_logger(__name__)

TOOL = "osv"
# OSV-Scanner's documented exit codes.
EXIT_NO_VULNERABILITIES = 0
EXIT_VULNERABILITIES_FOUND = 1
EXIT_NO_PACKAGES_FOUND = 128


def _environment(ctx: ToolContext) -> dict[str, str]:
    """Point OSV at the provisioned offline database directory."""
    env = dict(os.environ)
    env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(ctx.settings.osv_db_dir)
    return env


def _execute(
    argv: list[str],
    ctx: ToolContext,
    output: Path,
    label: str,
    root: Path | None = None,
) -> ScanOutcome:
    """Run OSV and parse its report.

    *root* is the directory actually scanned, and paths are made relative to
    it. Found by the evaluation: computing them against the clone directory
    left absolute, machine-specific paths (C:/Users/...) whenever a local
    folder was scanned, so those findings fingerprinted differently per machine.
    """
    started = time.perf_counter()
    result = run_command(
        argv,
        timeout=ctx.settings.tool_timeout_s,
        env=_environment(ctx),
        log_path=ctx.command_log,
    )
    elapsed = time.perf_counter() - started

    if result.timed_out:
        return ScanOutcome.of(
            TOOL,
            Verdict.TIMEOUT,
            duration_s=elapsed,
            detail=f"osv-scanner exceeded {ctx.settings.tool_timeout_s}s and was stopped",
        )

    if result.returncode == EXIT_NO_PACKAGES_FOUND:
        return ScanOutcome.not_applicable(
            TOOL,
            "no dependency manifest or lockfile found, so no dependency scan was possible "
            "(a committed lockfile such as package-lock.json is required)",
        )

    if result.returncode not in (EXIT_NO_VULNERABILITIES, EXIT_VULNERABILITIES_FOUND):
        return ScanOutcome.failed(
            TOOL,
            f"osv-scanner exited with {result.returncode}: {result.stderr.strip()[:300]}",
            elapsed,
        )

    # OSV writes its report to stdout, so the adapter persists it for auditing.
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(result.stdout or "{}", encoding="utf-8")

    try:
        payload = load_json(output)
    except ValueError as exc:
        return ScanOutcome.failed(TOOL, f"osv-scanner output was not valid JSON: {exc}", elapsed)

    findings = parse_osv(payload, repo_root=root)
    log.info("osv (%s): %d finding(s) in %.1fs", label, len(findings), elapsed)
    return ScanOutcome.of(
        TOOL,
        Verdict.OK,
        findings=findings,
        duration_s=elapsed,
        detail=label,
        raw_output=str(output),
    )


def _common_flags(ctx: ToolContext, *, source_scan: bool) -> list[str]:
    """Flags shared by both modes.

    ``--data-source`` stops OSV asking deps.dev about packages, but it is only
    defined on ``scan source``; passing it to ``scan image`` is a usage error.
    """
    flags = ["--format", "json"]
    if ctx.settings.offline:
        flags.append("--offline-vulnerabilities")
        if source_scan:
            flags += ["--data-source", "native", "--no-resolve"]
    return flags


def run_osv_source(source: Path, ctx: ToolContext) -> ScanOutcome:
    """Scan lockfiles and manifests in the source tree."""
    binary = resolve_executable(ctx.settings.osv_bin, [ctx.settings.vendor_bin_dir])
    if binary is None:
        return ScanOutcome.skipped(TOOL, "osv-scanner is not installed (see check_env)")
    if ctx.settings.offline and not ctx.settings.osv_db_dir.is_dir():
        return ScanOutcome.skipped(
            TOOL, "no offline OSV database; run 'python -m qa_agent seed' first"
        )

    argv = [binary, "scan", "source", *_common_flags(ctx, source_scan=True), "-r", str(source)]
    return _execute(
        argv, ctx, ctx.workspace.raw_path(TOOL), f"source scan of {source.name}", root=source
    )


def normalize_image_ref(image: str) -> str:
    """Ensure the image reference carries an explicit tag.

    Docker treats a bare ``repo/name`` as ``repo/name:latest``, but
    OSV-Scanner refuses it outright with "is not a tagged image name", so the
    implicit tag is made explicit here.
    """
    reference = image.strip()
    if not reference or "@" in reference:  # already pinned by digest
        return reference

    # A colon before the last slash belongs to a registry port, not a tag.
    last_segment = reference.rsplit("/", 1)[-1]
    if ":" in last_segment:
        return reference
    return f"{reference}:latest"


def run_osv_image(image: str, ctx: ToolContext) -> ScanOutcome:
    """Scan the packages installed inside a built container image."""
    binary = resolve_executable(ctx.settings.osv_bin, [ctx.settings.vendor_bin_dir])
    if binary is None:
        return ScanOutcome.skipped(TOOL, "osv-scanner is not installed (see check_env)")

    reference = normalize_image_ref(image)
    argv = [binary, "scan", "image", *_common_flags(ctx, source_scan=False), reference]
    return _execute(argv, ctx, ctx.workspace.raw_path("osv-image"), f"image scan of {reference}")
