"""Tests for the verification rule: a finding must reproduce before it counts."""

from __future__ import annotations

import pytest

from qa_agent.config import Settings
from qa_agent.models.finding import Category, Finding, Severity, Tool
from qa_agent.testgen.runner import FlowRun
from qa_agent.tools.base import ToolContext
from qa_agent.verify.verifier import (
    METHOD_DETERMINISTIC,
    crawler_finding_reproduced,
    verify_findings,
)
from qa_agent.web.page_model import NetworkFailure, PageObservation
from qa_agent.workspace import RunWorkspace

PAGE = "http://localhost:3000/#/login"


@pytest.fixture
def ctx(tmp_path) -> ToolContext:
    settings = Settings(data_dir=tmp_path / "data")
    return ToolContext(settings=settings, workspace=RunWorkspace.create(settings.workspace_dir))


def crawler_finding(rule_id: str, **metadata) -> Finding:
    return Finding(
        tool=Tool.CRAWLER,
        category=Category.FUNCTIONAL,
        severity=Severity.MEDIUM,
        title="t",
        location=PAGE,
        rule_id=rule_id,
        metadata={"page": PAGE, **metadata},
    )


def generated_finding(script: str, step: int) -> Finding:
    return Finding(
        tool=Tool.PLAYWRIGHT,
        category=Category.FUNCTIONAL,
        severity=Severity.LOW,
        title=f"flow failed {script}",
        location=PAGE,
        rule_id=f"flow:{script}",
        metadata={"script": script, "failed_step": step},
    )


def semgrep_finding(fid: str) -> Finding:
    return Finding(
        id=fid,
        tool=Tool.SEMGREP,
        category=Category.SECURITY,
        severity=Severity.HIGH,
        title="eval",
        location="a.js:1",
        rule_id="r",
        metadata={"file": "a.js"},
    )


def never(*args, **kwargs):
    raise AssertionError("this re-check should not have run")


# --------------------------------------------------------------------------
# matching a crawler finding against a fresh visit
# --------------------------------------------------------------------------
def test_console_errors_match_on_normalised_text():
    finding = crawler_finding("console:x", message="TypeError:   x is\nundefined")
    page = PageObservation(url=PAGE, console_errors=["TypeError: x is undefined"])
    assert crawler_finding_reproduced(finding, page)


def test_a_different_console_error_does_not_count():
    finding = crawler_finding("console:x", message="TypeError: x")
    page = PageObservation(url=PAGE, console_errors=["ReferenceError: y"])
    assert not crawler_finding_reproduced(finding, page)


def test_network_failures_match_on_url_and_status():
    finding = crawler_finding("network:500:u", request_url="http://x/api", status=500)
    same = PageObservation(url=PAGE, network_failures=[NetworkFailure("http://x/api", 500)])
    other = PageObservation(url=PAGE, network_failures=[NetworkFailure("http://x/api", 404)])
    assert crawler_finding_reproduced(finding, same)
    assert not crawler_finding_reproduced(finding, other)


def test_load_failures_and_status_codes_match():
    assert crawler_finding_reproduced(
        crawler_finding("page-load-failed"), PageObservation(url=PAGE, load_error="timeout")
    )
    assert crawler_finding_reproduced(
        crawler_finding("http-status:500", status=500), PageObservation(url=PAGE, status=500)
    )
    assert not crawler_finding_reproduced(crawler_finding("unknown"), PageObservation(url=PAGE))


# --------------------------------------------------------------------------
# the verifier
# --------------------------------------------------------------------------
def test_deterministic_findings_are_not_re_run(ctx):
    trivy = Finding(
        tool=Tool.TRIVY,
        category=Category.DEPENDENCY,
        severity=Severity.HIGH,
        title="cve",
        rule_id="CVE-1",
    )
    updated, stats = verify_findings(
        [trivy], ctx=ctx, source_path=None, observe=never, rescan=never, rerun=never
    )
    assert updated[0].verified and updated[0].verification_method == METHOD_DETERMINISTIC
    assert stats.checked == 0


def test_a_generated_failure_must_fail_again_at_the_same_step(ctx):
    (ctx.workspace.tests_dir / "a.py").write_text("", encoding="utf-8")
    (ctx.workspace.tests_dir / "b.py").write_text("", encoding="utf-8")
    findings = [generated_finding("a.py", 4), generated_finding("b.py", 4)]

    def rerun(script, **kwargs):
        # a.py fails again at step 4; b.py passes on the second run (flaky).
        return FlowRun(status="fail", step=4) if script.name == "a.py" else FlowRun(status="pass")

    updated, stats = verify_findings(
        findings, ctx=ctx, source_path=None, observe=never, rescan=never, rerun=rerun
    )

    by_script = {f.metadata["script"]: f for f in updated}
    assert by_script["a.py"].verified
    assert not by_script["b.py"].verified
    assert "did not reproduce" in by_script["b.py"].verification_method
    assert stats.confirmed == 1 and stats.not_reproduced == 1


def test_a_missing_generated_script_is_not_verified(ctx):
    updated, _ = verify_findings(
        [generated_finding("gone.py", 1)],
        ctx=ctx,
        source_path=None,
        observe=never,
        rescan=never,
        rerun=never,
    )
    assert not updated[0].verified


def test_crawler_findings_are_re_observed_in_a_fresh_browser(ctx):
    finding = crawler_finding("console:x", message="boom")

    def observe(urls, **kwargs):
        assert urls == [PAGE]
        return [PageObservation(url=PAGE, console_errors=["boom"])]

    updated, _ = verify_findings(
        [finding], ctx=ctx, source_path=None, observe=observe, rescan=never, rerun=never
    )
    assert updated[0].verified and "reproduced" in updated[0].verification_method


def test_a_browser_that_cannot_start_does_not_invent_a_verdict(ctx):
    def observe(urls, **kwargs):
        raise RuntimeError("chromium crashed")

    updated, stats = verify_findings(
        [crawler_finding("console:x", message="boom")],
        ctx=ctx,
        source_path=None,
        observe=observe,
        rescan=never,
        rerun=never,
    )
    assert updated[0].verified  # original observation kept...
    assert "could not run" in updated[0].verification_method  # ...and labelled as such
    assert stats.could_not_check == 1


def test_semgrep_findings_are_re_scanned_by_file(ctx, tmp_path):
    findings = [semgrep_finding("keep"), semgrep_finding("lost")]
    seen: dict = {}

    def rescan(source, files, context):
        seen["files"] = files
        return {"keep"}

    updated, _ = verify_findings(
        findings, ctx=ctx, source_path=tmp_path, observe=never, rescan=rescan, rerun=never
    )

    assert seen["files"] == ["a.js"]
    assert {f.id: f.verified for f in updated} == {"keep": True, "lost": False}


def test_a_failed_rescan_keeps_the_original_output(ctx, tmp_path):
    updated, stats = verify_findings(
        [semgrep_finding("x")],
        ctx=ctx,
        source_path=tmp_path,
        observe=never,
        rescan=lambda *a: None,
        rerun=never,
    )
    assert updated[0].verified and stats.could_not_check == 1


def test_verification_returns_copies(ctx):
    finding = crawler_finding("console:x", message="boom")
    verify_findings(
        [finding],
        ctx=ctx,
        source_path=None,
        observe=lambda urls, **k: [PageObservation(url=PAGE)],
        rescan=never,
        rerun=never,
    )
    assert finding.verified and finding.verification_method == "tool-output"
