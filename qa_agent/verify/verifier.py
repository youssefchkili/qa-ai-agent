"""The verification rule: a finding must happen twice before it counts.

This is the defence against the two ways a QA agent produces noise:

* **Flakiness.** A request that timed out once, a race in a single-page app.
  Browser-observed findings are re-checked by visiting the page again in a
  brand-new browser session.
* **Generated tests.** A failing LLM-planned flow is re-run in a fresh
  browser; it must fail again, at the same step.

Semgrep findings are re-checked by re-scanning just the affected files, which
also proves the fingerprints are stable. Trivy, OSV, ZAP, axe and Lighthouse
results are deterministic lookups against fixed data, so they keep the
"deterministic tool output" method rather than being re-run for show.

A finding that does not reproduce is not deleted. It stays in the report,
marked ``verified: false``, and is excluded from the headline numbers.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from qa_agent.logging_setup import get_logger
from qa_agent.models.finding import Finding, Tool
from qa_agent.tools.base import ToolContext
from qa_agent.web.page_model import PageObservation

log = get_logger(__name__)

METHOD_DETERMINISTIC = "deterministic tool output"
METHOD_RERUN_TEST = "re-ran the generated test in a fresh browser"
METHOD_REVISIT = "re-visited the page in a fresh browser"
METHOD_RESCAN = "re-ran semgrep on the affected file"

_COMPARE_CHARS = 120

Verdict = tuple[bool, str] | None


@dataclass(frozen=True)
class VerificationStats:
    """How many findings were re-checked, and how many held up."""

    checked: int = 0
    confirmed: int = 0
    not_reproduced: int = 0
    could_not_check: int = 0


def _same_text(first: str, second: str) -> bool:
    """Compare two messages, ignoring whitespace and anything past the prefix."""
    return " ".join(str(first).split())[:_COMPARE_CHARS] == (
        " ".join(str(second).split())[:_COMPARE_CHARS]
    )


def crawler_finding_reproduced(finding: Finding, page: PageObservation) -> bool:
    """Did the fresh visit show the same problem the crawl recorded?"""
    rule = finding.rule_id
    meta = finding.metadata
    if rule == "page-load-failed":
        return bool(page.load_error)
    if rule.startswith("http-status:"):
        return page.status == meta.get("status")
    if rule.startswith("console:"):
        return any(_same_text(message, meta.get("message", "")) for message in page.console_errors)
    if rule.startswith("network:"):
        return any(
            failure.url == meta.get("request_url") and failure.status == meta.get("status")
            for failure in page.network_failures
        )
    return False


def _mark(finding: Finding, verified: bool, method: str) -> Finding:
    return finding.model_copy(update={"verified": verified, "verification_method": method})


def _describe(method: str, reproduced: bool, yes: str = "reproduced") -> str:
    return f"{method}: {yes if reproduced else 'did not reproduce'}"


def _verify_generated(
    findings: list[Finding], ctx: ToolContext, rerun: Callable
) -> dict[str, Verdict]:
    verdicts: dict[str, Verdict] = {}
    for finding in findings:
        script = ctx.workspace.tests_dir / str(finding.metadata.get("script", ""))
        if not script.is_file():
            verdicts[finding.id] = (False, f"{METHOD_RERUN_TEST}: script missing")
            continue
        run = rerun(
            script,
            timeout_s=ctx.settings.testgen_run_timeout_s,
            log_path=ctx.workspace.command_log,
        )
        same = run.status == "fail" and run.step == finding.metadata.get("failed_step")
        verdicts[finding.id] = (
            same,
            _describe(METHOD_RERUN_TEST, same, "failed again at the same step"),
        )
    return verdicts


def _verify_crawler(
    findings: list[Finding], ctx: ToolContext, observe: Callable
) -> dict[str, Verdict]:
    urls = list(dict.fromkeys(str(f.metadata.get("page") or f.location) for f in findings))
    try:
        pages = observe(
            urls,
            pages_dir=ctx.workspace.pages_dir / "verify",
            page_timeout_s=ctx.settings.page_timeout_s,
        )
    except Exception as exc:  # noqa: BLE001 - failing to re-check is not a verdict
        log.warning("could not re-visit pages for verification: %s", exc)
        return {f.id: None for f in findings}

    by_url = {page.url: page for page in pages}
    verdicts: dict[str, Verdict] = {}
    for finding in findings:
        page = by_url.get(str(finding.metadata.get("page") or finding.location))
        if page is None:
            verdicts[finding.id] = None
            continue
        reproduced = crawler_finding_reproduced(finding, page)
        verdicts[finding.id] = (reproduced, _describe(METHOD_REVISIT, reproduced))
    return verdicts


def _verify_semgrep(
    findings: list[Finding], ctx: ToolContext, source: Path, rescan: Callable
) -> dict[str, Verdict]:
    files = sorted({str(f.metadata.get("file")) for f in findings if f.metadata.get("file")})
    ids = rescan(source, files, ctx)
    if ids is None:
        return {f.id: None for f in findings}
    return {f.id: (f.id in ids, _describe(METHOD_RESCAN, f.id in ids)) for f in findings}


def verify_findings(
    findings: list[Finding],
    *,
    ctx: ToolContext,
    source_path: Path | None,
    observe: Callable | None = None,
    rescan: Callable | None = None,
    rerun: Callable | None = None,
) -> tuple[list[Finding], VerificationStats]:
    """Re-check every finding that can be re-checked; return updated copies.

    The three re-check strategies are injectable so each path can be tested
    without a browser or a scanner.
    """
    if observe is None:
        from qa_agent.web.crawler import observe_pages as observe
    if rescan is None:
        from qa_agent.tools.semgrep import rescan_semgrep as rescan
    if rerun is None:
        from qa_agent.testgen.runner import run_flow_script as rerun

    generated = [f for f in findings if f.tool == Tool.PLAYWRIGHT]
    browser = [f for f in findings if f.tool == Tool.CRAWLER]
    semgrep = [f for f in findings if f.tool == Tool.SEMGREP]

    verdicts: dict[str, Verdict] = {}
    if generated:
        verdicts.update(_verify_generated(generated, ctx, rerun))
    if browser:
        verdicts.update(_verify_crawler(browser, ctx, observe))
    if semgrep and source_path is not None:
        verdicts.update(_verify_semgrep(semgrep, ctx, source_path, rescan))

    updated: list[Finding] = []
    confirmed = not_reproduced = could_not_check = 0
    for finding in findings:
        if finding.id not in verdicts:
            updated.append(_mark(finding, True, METHOD_DETERMINISTIC))
            continue
        verdict = verdicts[finding.id]
        if verdict is None:
            # The re-check itself could not run: keep the original observation,
            # and say so, rather than inventing a verdict either way.
            could_not_check += 1
            updated.append(
                _mark(finding, True, "re-check could not run; original tool output kept")
            )
            continue
        ok, method = verdict
        confirmed += int(ok)
        not_reproduced += int(not ok)
        updated.append(_mark(finding, ok, method))

    stats = VerificationStats(
        checked=len(verdicts),
        confirmed=confirmed,
        not_reproduced=not_reproduced,
        could_not_check=could_not_check,
    )
    log.info(
        "verification: %d re-checked, %d confirmed, %d not reproduced",
        stats.checked,
        stats.confirmed,
        stats.not_reproduced,
    )
    return updated, stats
