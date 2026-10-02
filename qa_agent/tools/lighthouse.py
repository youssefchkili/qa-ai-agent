"""Lighthouse adapter: performance, best-practices and SEO scoring per page.

Two Windows-specific details drive the design:

* Lighthouse is run through ``node cli/index.js`` rather than the generated
  ``lighthouse.cmd`` shim, which keeps the invocation identical on Windows and
  in the phase 3 Linux container.
* On Windows the process frequently exits non-zero *after* writing a perfectly
  good report, because Chrome's launcher cannot delete its temporary profile
  directory. Success is therefore judged by the report file, not the exit code.

Lighthouse drives the Chromium that Playwright already installed, so no system
Chrome is required and nothing is downloaded at scan time.
"""

from __future__ import annotations

import os
import time
from functools import lru_cache

from qa_agent.logging_setup import get_logger
from qa_agent.models.run import Verdict
from qa_agent.parsers.lighthouse import parse_lighthouse
from qa_agent.tools.base import ScanOutcome, ToolContext, load_json
from qa_agent.tools.process import resolve_executable, run_command

log = get_logger(__name__)

TOOL = "lighthouse"
# A single page audit should never hold the pipeline for minutes.
LIGHTHOUSE_TIMEOUT_S = 180


@lru_cache(maxsize=1)
def chromium_path() -> str:
    """Absolute path of the Chromium that Playwright manages.

    Cached because starting the Playwright driver just to read a path is slow,
    and every audited page would otherwise pay that cost.
    """
    try:
        from playwright.sync_api import sync_playwright

        driver = sync_playwright().start()
        try:
            return driver.chromium.executable_path or ""
        finally:
            driver.stop()
    except Exception as exc:  # noqa: BLE001 - fall back to whatever Chrome exists
        log.debug("could not resolve Playwright Chromium: %s", exc)
        return ""


def run_lighthouse(url: str, ctx: ToolContext, *, index: int = 0) -> ScanOutcome:
    """Audit one page and return findings for categories below budget."""
    settings = ctx.settings

    cli = settings.lighthouse_cli
    if not cli.is_file():
        return ScanOutcome.skipped(
            TOOL, "lighthouse is not installed; run 'python -m qa_agent seed' first"
        )
    node = resolve_executable(settings.node_bin, [settings.vendor_bin_dir])
    if node is None:
        return ScanOutcome.skipped(TOOL, "node is not installed (see check_env)")

    output = ctx.workspace.raw_path(f"lighthouse-{index:02d}")
    env = dict(os.environ)
    chrome = chromium_path()
    if chrome:
        env["CHROME_PATH"] = chrome

    argv = [
        node,
        str(cli),
        url,
        "--output=json",
        f"--output-path={output}",
        "--quiet",
        "--only-categories=performance,best-practices,seo",
        f"--throttling-method={settings.lighthouse_throttling}",
        "--chrome-flags=--headless=new --no-sandbox --disable-gpu",
    ]

    started = time.perf_counter()
    result = run_command(argv, timeout=LIGHTHOUSE_TIMEOUT_S, env=env, log_path=ctx.command_log)
    elapsed = time.perf_counter() - started

    if result.timed_out:
        return ScanOutcome.of(
            TOOL,
            Verdict.TIMEOUT,
            duration_s=elapsed,
            detail=f"lighthouse exceeded {LIGHTHOUSE_TIMEOUT_S}s on {url}",
        )

    # The report file, not the exit code, decides whether this worked.
    if not output.exists():
        return ScanOutcome.failed(
            TOOL, f"lighthouse produced no report: {result.stderr.strip()[:300]}", elapsed
        )

    try:
        payload = load_json(output)
    except ValueError as exc:
        return ScanOutcome.failed(TOOL, f"lighthouse output was not valid JSON: {exc}", elapsed)

    findings = parse_lighthouse(
        payload,
        url,
        budgets={
            "performance": settings.performance_budget,
            "best-practices": settings.best_practices_budget,
            "seo": settings.seo_budget,
        },
    )

    detail = f"audited {url}"
    if not result.ok:
        # Worth recording, but not a failure: the report was produced.
        detail += " (lighthouse exited non-zero after writing the report)"

    log.info("lighthouse: %d finding(s) for %s in %.1fs", len(findings), url, elapsed)
    return ScanOutcome.of(
        TOOL,
        Verdict.OK,
        findings=findings,
        duration_s=elapsed,
        detail=detail,
        raw_output=str(output),
    )
