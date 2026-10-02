"""Tests for deduplication, cross-tool merging and report rendering."""

from __future__ import annotations

import json

from qa_agent.models.finding import Category, Finding, Severity, Tool
from qa_agent.models.run import RunSummary, ToolRun, Verdict
from qa_agent.report.dedupe import (
    collapse_page_findings,
    dedupe_exact,
    deduplicate,
    merge_dependency_findings,
)
from qa_agent.report.render import build_context, group_by_category, render_reports
from qa_agent.workspace import RunWorkspace


def code_finding(**overrides) -> Finding:
    defaults = dict(
        tool=Tool.SEMGREP,
        category=Category.SECURITY,
        severity=Severity.HIGH,
        title="eval detected",
        location="routes/a.ts:22",
        rule_id="javascript.eval-detected",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def dependency_finding(tool: Tool, rule_id: str, **overrides) -> Finding:
    metadata = {"package": "lodash", "installed_version": "4.17.20"}
    metadata.update(overrides.pop("metadata", {}))
    defaults = dict(
        tool=tool,
        category=Category.DEPENDENCY,
        severity=Severity.HIGH,
        title=f"{rule_id} in lodash",
        location="package-lock.json: lodash@4.17.20",
        rule_id=rule_id,
        metadata=metadata,
    )
    defaults.update(overrides)
    return Finding(**defaults)


def page_finding(rule_id: str, page: str, **overrides) -> Finding:
    defaults = dict(
        tool=Tool.AXE,
        category=Category.ACCESSIBILITY,
        severity=Severity.MEDIUM,
        title="Elements must have sufficient colour contrast",
        location=page,
        rule_id=rule_id,
        metadata={"page": page},
    )
    defaults.update(overrides)
    return Finding(**defaults)


# --------------------------------------------------------------------------
# exact duplicates
# --------------------------------------------------------------------------
def test_identical_findings_collapse_to_one():
    assert len(dedupe_exact([code_finding(), code_finding()])) == 1


def test_distinct_findings_are_kept():
    assert len(dedupe_exact([code_finding(), code_finding(location="routes/b.ts:1")])) == 2


def test_collapsing_keeps_the_more_severe_verdict():
    merged = dedupe_exact(
        [code_finding(severity=Severity.LOW), code_finding(severity=Severity.CRITICAL)]
    )
    assert merged[0].severity == Severity.CRITICAL


def test_collapsing_preserves_first_seen_order():
    first = code_finding(location="a.ts:1")
    second = code_finding(location="b.ts:1")
    assert [f.location for f in dedupe_exact([first, second, first])] == ["a.ts:1", "b.ts:1"]


# --------------------------------------------------------------------------
# cross-tool dependency merging
# --------------------------------------------------------------------------
def test_trivy_and_osv_reports_of_one_vulnerability_merge():
    trivy = dependency_finding(Tool.TRIVY, "CVE-2021-23337")
    osv = dependency_finding(
        Tool.OSV, "CVE-2021-23337", metadata={"aliases": ["GHSA-35jh-r3h4-6jhm", "CVE-2021-23337"]}
    )

    merged = merge_dependency_findings([trivy, osv])

    assert len(merged) == 1
    assert set(merged[0].sources) == {Tool.TRIVY, Tool.OSV}
    # Agreement between two independent scanners is recorded for the report.
    assert merged[0].metadata["confirmed_by"] == ["trivy", "osv"]


def test_merging_matches_through_an_alias():
    # Trivy reports the CVE; OSV's primary id is the GHSA but lists the CVE.
    trivy = dependency_finding(Tool.TRIVY, "CVE-2021-23337")
    osv = dependency_finding(
        Tool.OSV, "GHSA-35jh-r3h4-6jhm", metadata={"aliases": ["CVE-2021-23337"]}
    )

    assert len(merge_dependency_findings([trivy, osv])) == 1


def test_different_vulnerabilities_in_one_package_stay_separate():
    first = dependency_finding(Tool.TRIVY, "CVE-2021-23337")
    second = dependency_finding(Tool.TRIVY, "CVE-2020-8203")

    assert len(merge_dependency_findings([first, second])) == 2


def test_the_same_advisory_in_a_different_version_stays_separate():
    first = dependency_finding(Tool.TRIVY, "CVE-2021-23337")
    second = dependency_finding(
        Tool.TRIVY, "CVE-2021-23337", metadata={"installed_version": "3.0.0"}
    )

    assert len(merge_dependency_findings([first, second])) == 2


def test_non_dependency_findings_pass_through_merging():
    assert len(merge_dependency_findings([code_finding()])) == 1


# --------------------------------------------------------------------------
# page-level collapsing
# --------------------------------------------------------------------------
def test_one_rule_across_many_pages_is_reported_once():
    findings = [
        page_finding("color-contrast", "http://localhost:3000/"),
        page_finding("color-contrast", "http://localhost:3000/#/login"),
        page_finding("color-contrast", "http://localhost:3000/#/contact"),
    ]

    collapsed = collapse_page_findings(findings)

    assert len(collapsed) == 1
    assert collapsed[0].metadata["affected_page_count"] == 3
    assert len(collapsed[0].metadata["affected_pages"]) == 3


def test_collapsing_keeps_the_worst_severity_seen():
    findings = [
        page_finding("color-contrast", "http://a/", severity=Severity.LOW),
        page_finding("color-contrast", "http://b/", severity=Severity.HIGH),
    ]
    assert collapse_page_findings(findings)[0].severity == Severity.HIGH


def test_different_rules_are_not_collapsed_together():
    findings = [
        page_finding("color-contrast", "http://a/"),
        page_finding("aria-dialog-name", "http://a/"),
    ]
    assert len(collapse_page_findings(findings)) == 2


def test_code_findings_are_never_collapsed_by_page():
    findings = [code_finding(location="a.ts:1"), code_finding(location="b.ts:1")]
    assert len(collapse_page_findings(findings)) == 2


def test_a_single_page_hit_gains_no_page_list():
    collapsed = collapse_page_findings([page_finding("color-contrast", "http://a/")])
    assert "affected_pages" not in collapsed[0].metadata


# --------------------------------------------------------------------------
# full pipeline and ordering
# --------------------------------------------------------------------------
def test_deduplicate_sorts_most_severe_first():
    findings = [
        code_finding(location="a.ts:1", severity=Severity.LOW),
        code_finding(location="b.ts:2", severity=Severity.CRITICAL),
        code_finding(location="c.ts:3", severity=Severity.MEDIUM),
    ]

    severities = [f.severity for f in deduplicate(findings)]

    assert severities == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_deduplicate_handles_an_empty_list():
    assert deduplicate([]) == []


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------
def test_groups_follow_the_report_order_and_skip_empties():
    findings = [
        page_finding("color-contrast", "http://a/"),
        code_finding(),
    ]

    groups = group_by_category(findings)

    assert [g["key"] for g in groups] == ["security", "accessibility"]
    assert groups[0]["count"] == 1


def test_context_separates_tools_that_ran_from_those_that_did_not():
    summary = RunSummary(run_id="test")
    summary.add(ToolRun(tool="semgrep", verdict=Verdict.OK))
    summary.add(ToolRun(tool="osv", verdict=Verdict.NOT_APPLICABLE, detail="no lockfile"))

    context = build_context([code_finding()], summary)

    assert [t["tool"] for t in context["tools_that_ran"]] == ["semgrep"]
    assert [t["tool"] for t in context["tools_that_did_not_run"]] == ["osv"]


def test_render_writes_all_three_artefacts(tmp_path):
    workspace = RunWorkspace.create(tmp_path, run_id="20260923-101112-abcdef")
    summary = RunSummary(run_id=workspace.run_id, app_url="http://localhost:3000")
    summary.add(ToolRun(tool="semgrep", verdict=Verdict.OK, findings_count=1))

    md_path, html_path = render_reports([code_finding()], summary, workspace)

    assert md_path.is_file() and html_path.is_file()
    assert workspace.findings_path.is_file()

    stored = json.loads(workspace.findings_path.read_text(encoding="utf-8"))
    assert stored[0]["rule_id"] == "javascript.eval-detected"

    markdown = md_path.read_text(encoding="utf-8")
    assert "eval detected" in markdown
    assert "[HIGH]" in markdown


def test_html_escapes_text_taken_from_the_scanned_application(tmp_path):
    workspace = RunWorkspace.create(tmp_path, run_id="20260923-101112-abcdef")
    summary = RunSummary(run_id=workspace.run_id)
    hostile = code_finding(title="<script>alert('xss')</script>", location="evil.ts:1")

    _, html_path = render_reports([hostile], summary, workspace)
    html = html_path.read_text(encoding="utf-8")

    # A malicious page title must not become live script in the report.
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_report_states_when_nothing_was_found(tmp_path):
    workspace = RunWorkspace.create(tmp_path, run_id="20260923-101112-abcdef")
    summary = RunSummary(run_id=workspace.run_id)

    md_path, _ = render_reports([], summary, workspace)

    assert "No findings were reported" in md_path.read_text(encoding="utf-8")
