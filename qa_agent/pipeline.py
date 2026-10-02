"""The orchestrator: one plain Python function, start to finish.

Deliberately a straight sequence rather than a graph framework. The pipeline is
linear, every step's failure mode is known, and a reader can follow it top to
bottom. Nothing here decides *what* is wrong with the target; it only decides
which tools to run, records their verdicts, and hands their findings on.

Phase 1 contains no AI at all. Phase 2 inserts triage and verification between
``deduplicate`` and ``render_reports`` without changing anything above them.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from qa_agent.config import Settings
from qa_agent.input.launcher import LaunchedApp, launch_app, shutdown
from qa_agent.input.repo import CloneFailed, SourceTree, clone_repo, use_local_path
from qa_agent.input.target import TargetKind, classify_target
from qa_agent.llm.client import LLMClient
from qa_agent.llm.summary import build_facts, fallback_summary, write_executive_summary
from qa_agent.llm.triage import triage_findings
from qa_agent.logging_setup import get_logger, setup_logging
from qa_agent.models.finding import Finding
from qa_agent.models.run import RunSummary, ToolRun, Verdict
from qa_agent.parsers.axe import parse_axe
from qa_agent.parsers.browser import parse_pages
from qa_agent.report.dedupe import deduplicate
from qa_agent.report.render import render_reports
from qa_agent.safety import TargetNotAllowed, assert_target_allowed
from qa_agent.tools.base import ScanOutcome, ToolContext
from qa_agent.tools.lighthouse import run_lighthouse
from qa_agent.tools.osv import run_osv_image, run_osv_source
from qa_agent.tools.semgrep import run_semgrep
from qa_agent.tools.trivy import run_trivy_fs, run_trivy_image
from qa_agent.tools.zap import run_zap_baseline
from qa_agent.verify.verifier import verify_findings
from qa_agent.web.page_model import PageObservation
from qa_agent.workspace import RunWorkspace

log = get_logger(__name__)


@dataclass
class PipelineResult:
    """Everything a caller needs after a run."""

    workspace: RunWorkspace
    summary: RunSummary
    findings: list[Finding] = field(default_factory=list)
    report_md: Path | None = None
    report_html: Path | None = None


def run_pipeline(
    *,
    settings: Settings,
    url: str = "",
    app_url: str = "",
    image: str = "",
    run_id: str | None = None,
    launch: bool = True,
    skip: frozenset[str] = frozenset(),
    verbose: bool = False,
    use_llm: bool = True,
) -> PipelineResult:
    """Scan a repository, a running application, or both, and write a report."""
    workspace = RunWorkspace.create(settings.workspace_dir, run_id)
    setup_logging(verbose=verbose, log_file=workspace.run_log)
    log.info("run %s -> %s", workspace.run_id, workspace.root)

    summary = RunSummary(run_id=workspace.run_id, repo_url=url, app_url=app_url, image_ref=image)
    context = ToolContext(settings=settings, workspace=workspace)
    findings: list[Finding] = []
    launched: LaunchedApp | None = None

    try:
        # -- 1. source code -------------------------------------------------
        source = _acquire_source(url, workspace, settings, summary)

        # -- 2. static analysis ---------------------------------------------
        if source is not None:
            summary.commit = source.commit
            for name, runner in (
                ("semgrep", run_semgrep),
                ("trivy", run_trivy_fs),
                ("osv", run_osv_source),
            ):
                if name in skip:
                    summary.add(ToolRun(tool=name, verdict=Verdict.SKIPPED, detail="--skip"))
                    continue
                findings += _record(summary, runner(source.path, context))

        # -- 3. a running application ---------------------------------------
        target_url = app_url
        if not target_url and launch and source is not None:
            launched = launch_app(
                source.path,
                docker_bin=settings.docker_bin,
                run_id=workspace.run_id,
                timeout_s=settings.app_launch_timeout_s,
            )
            summary.add(
                ToolRun(
                    tool="app launcher",
                    verdict=Verdict.OK if launched.ok else Verdict.FAILED,
                    detail=launched.detail,
                )
            )
            if launched.ok:
                target_url = launched.url
                summary.app_url = target_url
            else:
                # Explicit, so the report never implies the app was found clean.
                summary.note(
                    "The application could not be launched automatically, so no dynamic "
                    f"testing was performed. {launched.detail} "
                    "Pass --app-url to point the agent at a running instance."
                )

        # -- 4. dynamic analysis --------------------------------------------
        pages: list[PageObservation] = []
        if target_url:
            dynamic_findings, pages = _dynamic_phase(target_url, context, summary, skip)
            findings += dynamic_findings
        elif not app_url:
            summary.note("No running application was available, so only static analysis ran.")

        # -- 5. container image ---------------------------------------------
        image_ref = image or (launched.image if launched and launched.image else "")
        if image_ref and "image" not in skip:
            summary.image_ref = image_ref
            findings += _record(summary, run_trivy_image(image_ref, context))
            findings += _record(summary, run_osv_image(image_ref, context))

        # ===== phase 2: everything below is where the local model helps =====
        # The model never adds a finding of its own. Generated tests produce
        # findings only when the browser observes a failure.
        llm = _connect_llm(settings, workspace, summary, use_llm)

        # -- 6. generated test flows ----------------------------------------
        if llm is not None and pages and "testgen" not in skip:
            findings += _testgen_phase(llm, pages, target_url, context, summary)

        # -- 7. deduplicate, then re-confirm before anything is reported ------
        findings = deduplicate(findings)
        if settings.verify_findings and "verify" not in skip:
            findings = _verify_phase(findings, context, source, summary)

        # -- 8. triage and executive summary ---------------------------------
        if llm is not None and "triage" not in skip:
            findings = _triage_phase(llm, findings, settings, summary)
        findings = sorted(findings, key=lambda finding: finding.sort_key)
        _summary_phase(llm, findings, summary)

        # -- 9. report -------------------------------------------------------
        summary.finished_at = datetime.now(UTC)
        report_md, report_html = render_reports(findings, summary, workspace)

        log.info("%d finding(s) in the report", len(findings))
        return PipelineResult(workspace, summary, findings, report_md, report_html)

    finally:
        if launched is not None and launched.ok:
            log.info("shutting down the application the agent started")
            shutdown(launched)


def _record(summary: RunSummary, outcome: ScanOutcome) -> list[Finding]:
    """Store a tool's verdict on the summary and return its findings."""
    summary.add(outcome.run)
    if outcome.run.verdict is not Verdict.OK:
        log.warning("%s: %s (%s)", outcome.run.tool, outcome.run.verdict.value, outcome.run.detail)
    return outcome.findings


def _acquire_source(
    url: str, workspace: RunWorkspace, settings: Settings, summary: RunSummary
) -> SourceTree | None:
    """Clone the repository, or use a local directory, or return None."""
    if not url:
        return None

    kind = classify_target(url)
    if kind == TargetKind.WEB_APP:
        # The user passed a live URL as --url; treat it as the app, not a repo.
        summary.app_url = summary.app_url or url
        summary.repo_url = ""
        return None

    try:
        if kind == TargetKind.LOCAL_PATH:
            source = use_local_path(Path(url), git_bin=settings.git_bin)
        else:
            source = clone_repo(
                url,
                workspace.repo_dir,
                git_bin=settings.git_bin,
                timeout=settings.tool_timeout_s,
                log_path=workspace.command_log,
            )
        summary.add(ToolRun(tool="source", verdict=Verdict.OK, detail=source.detail))
        return source
    except CloneFailed as exc:
        summary.add(ToolRun(tool="source", verdict=Verdict.FAILED, detail=str(exc)))
        summary.note(f"The repository could not be fetched, so no static analysis ran: {exc}")
        return None


def _dynamic_phase(
    target_url: str,
    context: ToolContext,
    summary: RunSummary,
    skip: frozenset[str],
) -> tuple[list[Finding], list[PageObservation]]:
    """Crawl, then run the page-level and site-level scanners.

    Returns the findings and the crawled pages; phase 2 plans tests from the
    pages' interactive elements.
    """
    settings = context.settings
    findings: list[Finding] = []

    # The guardrail runs before a single request is sent.
    try:
        classification = assert_target_allowed(
            target_url, allow_public=settings.allow_public_targets
        )
        summary.note(f"Dynamic testing target {target_url} classified as {classification.value}.")
    except TargetNotAllowed as exc:
        summary.add(ToolRun(tool="crawler", verdict=Verdict.SKIPPED, detail=str(exc)))
        summary.note(str(exc))
        return findings, []

    if "crawler" in skip:
        summary.add(ToolRun(tool="crawler", verdict=Verdict.SKIPPED, detail="--skip"))
        return findings, []

    from qa_agent.web.crawler import crawl  # imported late: needs a browser

    started = time.perf_counter()
    try:
        pages = crawl(
            target_url,
            pages_dir=context.workspace.pages_dir,
            max_pages=settings.max_pages,
            page_timeout_s=settings.page_timeout_s,
            run_axe="axe" not in skip,
        )
    except Exception as exc:  # noqa: BLE001 - a browser failure must not kill the run
        summary.add(ToolRun(tool="crawler", verdict=Verdict.FAILED, detail=str(exc)[:300]))
        summary.note(f"The crawl failed, so no dynamic findings are present: {exc}")
        return findings, []

    elapsed = time.perf_counter() - started
    summary.pages_crawled = len(pages)
    _save_pages(pages, context.workspace)

    browser_findings = parse_pages(pages)
    summary.add(
        ToolRun(
            tool="crawler",
            verdict=Verdict.OK,
            duration_s=round(elapsed, 2),
            findings_count=len(browser_findings),
            detail=f"visited {len(pages)} page(s) from {target_url}",
        )
    )
    findings += browser_findings

    # Accessibility: results were collected during the crawl itself.
    if "axe" not in skip:
        axe_findings: list[Finding] = []
        audited = 0
        for page in pages:
            if page.axe is None:
                continue
            audited += 1
            axe_findings += parse_axe(page.axe, page.url, screenshot=page.screenshot)
        summary.add(
            ToolRun(
                tool="axe",
                verdict=Verdict.OK if audited else Verdict.FAILED,
                findings_count=len(axe_findings),
                detail=f"axe-core ran on {audited} page(s)",
            )
        )
        findings += axe_findings

    # Performance: costly, so only the first few pages.
    if "lighthouse" not in skip:
        for index, page in enumerate(pages[: settings.lighthouse_max_pages]):
            findings += _record(summary, run_lighthouse(page.url, context, index=index))

    # Passive security scan of the whole site.
    if "zap" not in skip:
        findings += _record(summary, run_zap_baseline(target_url, context))

    return findings, pages


def _save_pages(pages: list[PageObservation], workspace: RunWorkspace) -> None:
    """Persist what the crawler saw, so generated tests can be audited later."""
    workspace.save_json(
        workspace.pages_dir / "pages.json",
        [
            {
                "url": page.url,
                "title": page.title,
                "status": page.status,
                "load_error": page.load_error,
                "console_errors": page.console_errors,
                "network_failures": [vars(failure) for failure in page.network_failures],
                "screenshot": page.screenshot,
                "structure": page.structure,
            }
            for page in pages
        ],
    )


# ==========================================================================
# phase 2 stages
# ==========================================================================
def _connect_llm(
    settings: Settings, workspace: RunWorkspace, summary: RunSummary, use_llm: bool
) -> LLMClient | None:
    """A client for the local model, or None with a recorded reason.

    Without a model the run still completes: it is exactly the phase 1
    report, and it says so, because every finding is still real tool output.
    """
    if not use_llm or not settings.use_llm:
        summary.add(ToolRun(tool="llm", verdict=Verdict.SKIPPED, detail="disabled"))
        return None

    client = LLMClient(settings, log_path=workspace.llm_log)
    available, reason = client.check_available()
    if not available:
        summary.add(ToolRun(tool="llm", verdict=Verdict.SKIPPED, detail=reason))
        summary.note(
            f"The local model was not available ({reason}), so this report has no "
            "triage, generated tests or model-written summary. Every finding is still "
            "real tool output."
        )
        return None

    summary.llm_model = client.model
    return client


def _testgen_phase(
    llm: LLMClient,
    pages: list[PageObservation],
    target_url: str,
    context: ToolContext,
    summary: RunSummary,
) -> list[Finding]:
    """Plan and run browser tests; return findings for flows that failed."""
    from qa_agent.testgen.generator import (
        STATUS_FAIL,
        STATUS_NOT_TESTABLE,
        STATUS_PASS,
        generate_and_run,
        outcome_to_finding,
    )

    settings = context.settings
    # The spec's guardrail, re-checked right where generated code is about to
    # run: never execute generated tests against a non-local target.
    try:
        assert_target_allowed(
            target_url,
            allow_public=settings.allow_public_targets,
            action="run generated tests against",
        )
    except TargetNotAllowed as exc:
        summary.add(ToolRun(tool="testgen", verdict=Verdict.SKIPPED, detail=str(exc)))
        return []

    started = time.perf_counter()
    outcomes = generate_and_run(
        pages, client=llm, settings=settings, workspace=context.workspace, base_url=target_url
    )
    summary.flows = [outcome.to_dict() for outcome in outcomes]

    counts = {
        status: sum(1 for o in outcomes if o.status == status)
        for status in (STATUS_PASS, STATUS_FAIL, STATUS_NOT_TESTABLE)
    }
    failures = [outcome_to_finding(o) for o in outcomes if o.status == STATUS_FAIL]
    summary.add(
        ToolRun(
            tool="testgen",
            verdict=Verdict.OK if outcomes else Verdict.FAILED,
            duration_s=round(time.perf_counter() - started, 2),
            findings_count=len(failures),
            detail=(
                f"{len(outcomes)} flow(s) planned by {llm.model}: {counts[STATUS_PASS]} passed, "
                f"{counts[STATUS_FAIL]} failed, {counts[STATUS_NOT_TESTABLE]} not testable"
            ),
        )
    )
    return failures


def _verify_phase(
    findings: list[Finding],
    context: ToolContext,
    source: SourceTree | None,
    summary: RunSummary,
) -> list[Finding]:
    started = time.perf_counter()
    updated, stats = verify_findings(
        findings, ctx=context, source_path=source.path if source else None
    )
    summary.add(
        ToolRun(
            tool="verifier",
            verdict=Verdict.OK,
            duration_s=round(time.perf_counter() - started, 2),
            findings_count=stats.not_reproduced,
            detail=(
                f"{stats.checked} finding(s) re-checked: {stats.confirmed} confirmed, "
                f"{stats.not_reproduced} did not reproduce, "
                f"{stats.could_not_check} could not be re-checked"
            ),
        )
    )
    if stats.not_reproduced:
        summary.note(
            f"{stats.not_reproduced} finding(s) did not reproduce when re-checked. They are "
            "listed as not verified and excluded from the headline numbers."
        )
    return updated


def _triage_phase(
    llm: LLMClient, findings: list[Finding], settings: Settings, summary: RunSummary
) -> list[Finding]:
    started = time.perf_counter()
    updated, stats = triage_findings(
        findings,
        llm,
        batch_size=settings.triage_batch_size,
        max_findings=settings.triage_max_findings,
    )
    summary.add(
        ToolRun(
            tool="triage",
            verdict=Verdict.OK if stats.reviewed else Verdict.FAILED,
            duration_s=round(time.perf_counter() - started, 2),
            detail=(
                f"{stats.reviewed} reviewed by {llm.model}: {stats.false_positive_flags} flagged "
                f"as likely false positives, {stats.severity_changes} re-scored "
                f"(by at most one level)"
            ),
        )
    )
    if stats.not_reviewed:
        summary.note(
            f"{stats.not_reviewed} verified finding(s) were not reviewed by the model; only "
            f"the {settings.triage_max_findings} most severe are triaged per run "
            "(QA_AGENT_TRIAGE_MAX_FINDINGS)."
        )
    return updated


def _summary_phase(llm: LLMClient | None, findings: list[Finding], summary: RunSummary) -> None:
    facts = build_facts(findings, summary)
    if llm is None:
        summary.executive_summary = fallback_summary(facts)
        summary.summary_source = "fallback: no local model"
        return
    summary.executive_summary, summary.summary_source = write_executive_summary(llm, facts)
