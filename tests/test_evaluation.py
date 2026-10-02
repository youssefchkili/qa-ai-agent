"""Tests for the evaluation harness: answer-sheet matching, metrics, and the
secret de-duplication that keeps precision honest."""

from __future__ import annotations

import json

import pytest

from qa_agent.evaluation.answer_sheet import Bug, Matcher, finding_matches, load_answer_sheet
from qa_agent.evaluation.metrics import consistency, jaccard, score_run, summarise
from qa_agent.models.finding import Category, Finding, LLMAnnotation, Severity, Tool
from qa_agent.report.dedupe import deduplicate, merge_colocated_secrets


def finding(**overrides) -> Finding:
    defaults = dict(
        tool=Tool.SEMGREP,
        category=Category.SECURITY,
        severity=Severity.HIGH,
        title="formatted sql query",
        location="app.py:77",
        rule_id="python.lang.security.audit.formatted-sql-query",
    )
    defaults.update(overrides)
    return Finding(**defaults)


def bug(bug_id="B01", **match) -> Bug:
    defaults = {"categories": ("security",), "keywords": ("sql",)}
    defaults.update(match)
    return Bug(id=bug_id, title=bug_id, category="security", matcher=Matcher(**defaults))


# --------------------------------------------------------------------------
# matching
# --------------------------------------------------------------------------
def test_a_finding_with_the_right_category_location_and_keyword_matches():
    assert finding_matches(finding(), bug(location_any=("app.py",)))


def test_the_wrong_category_does_not_match():
    assert not finding_matches(finding(category=Category.CODE), bug())


def test_the_wrong_location_does_not_match():
    assert not finding_matches(finding(), bug(location_any=("config.py",)))


def test_a_page_level_location_is_matched_through_metadata():
    page_finding = finding(
        tool=Tool.CRAWLER,
        category=Category.FUNCTIONAL,
        title="Page returned HTTP 404",
        rule_id="http-status:404",
        location="http://127.0.0.1:5055/old-catalog",
        metadata={"page": "http://127.0.0.1:5055/old-catalog"},
    )
    target = bug(
        categories=("functional",), keywords=("http-status:404",), location_any=("old-catalog",)
    )
    assert finding_matches(page_finding, target)


def test_evidence_keywords_make_a_match_strict():
    # A failed flow on the right page is not enough: it must show the real defect.
    flow = finding(
        tool=Tool.PLAYWRIGHT,
        category=Category.FUNCTIONAL,
        title="Generated test flow failed: send message",
        rule_id="flow:send-message",
        location="http://127.0.0.1:5055/contact",
        evidence="The page was actually showing: Thank you",
    )
    target = bug(
        categories=("functional",),
        keywords=("flow",),
        location_any=("contact",),
        evidence_keywords=("method not allowed",),
    )
    assert not finding_matches(flow, target)
    shown = flow.model_copy(
        update={"evidence": "The page was actually showing: Method Not Allowed"}
    )
    assert finding_matches(shown, target)


def test_the_answer_sheet_loads_and_rejects_duplicates(tmp_path):
    path = tmp_path / "sheet.json"
    entry = {
        "id": "B01",
        "title": "t",
        "category": "security",
        "match": {"categories": ["Security"], "keywords": ["SQL"]},
    }
    path.write_text(json.dumps({"bugs": [entry]}), encoding="utf-8")
    bugs = load_answer_sheet(path)
    assert bugs[0].matcher.categories == ("security",)  # case-normalised

    path.write_text(json.dumps({"bugs": [entry, entry]}), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_answer_sheet(path)


def test_the_answer_sheet_requires_matchers(tmp_path):
    path = tmp_path / "sheet.json"
    path.write_text(json.dumps({"bugs": [{"id": "B01", "match": {}}]}), encoding="utf-8")
    with pytest.raises(ValueError, match="needs"):
        load_answer_sheet(path)


def test_the_real_answer_sheet_is_valid():
    from qa_agent.evaluation.harness import DEFAULT_ANSWER_SHEET

    if not DEFAULT_ANSWER_SHEET.is_file():
        pytest.skip("private answer sheet not present on this machine")
    bugs = load_answer_sheet(DEFAULT_ANSWER_SHEET)
    assert len(bugs) >= 15


# --------------------------------------------------------------------------
# metrics
# --------------------------------------------------------------------------
def test_precision_and_recall_on_a_known_example():
    bugs = [bug("B01"), bug("B02", keywords=("pickle",))]
    findings = [finding(), finding(title="missing alt", rule_id="image-alt", location="x.py:1")]

    score = score_run("r1", findings, bugs)

    assert score.precision == 0.5  # 1 of 2 findings detects a planted bug
    assert score.recall == 0.5  # 1 of 2 planted bugs detected
    assert score.detected == ("B01",) and score.missed == ("B02",)
    assert score.unmatched[0]["rule_id"] == "image-alt"


def test_reviewed_precision_counts_real_unplanted_issues_separately():
    bugs = [bug("B01")]
    known = [bug("R01", keywords=("urllib3",), categories=("dependency",))]
    findings = [
        finding(),  # planted
        finding(category=Category.DEPENDENCY, title="CVE-1 in urllib3 1.23", rule_id="CVE-1"),
        finding(title="nonsense", rule_id="noise", location="x.py:1"),  # neither
    ]

    score = score_run("r", findings, bugs, known)

    assert score.precision == pytest.approx(1 / 3)  # strict: only the planted one
    assert score.reviewed_precision == pytest.approx(2 / 3)  # plus the real unplanted one
    assert score.real_unplanted == 1
    assert [u["rule_id"] for u in score.unmatched] == ["noise"]


def test_unverified_findings_do_not_count():
    score = score_run("r", [finding(verified=False)], [bug()])
    assert score.total_findings == 0 and score.recall == 0.0 and score.unverified == 1


def test_model_flags_are_reported_but_do_not_change_the_score():
    flagged = finding(llm_annotation=LLMAnnotation(is_likely_false_positive=True))
    score = score_run("r", [flagged], [bug()])
    assert score.flagged_false_positive == 1 and score.precision == 1.0


def test_jaccard_and_consistency():
    assert jaccard({"a", "b"}, {"b", "c"}) == pytest.approx(1 / 3)
    assert jaccard(set(), set()) == 1.0
    assert consistency([{"a"}]) == 1.0
    assert consistency([{"a", "b"}, {"a", "b"}, {"a"}]) == pytest.approx((1 + 0.5 + 0.5) / 3)


def test_summary_separates_always_sometimes_and_never_detected():
    bugs = [bug("B01"), bug("B02", keywords=("pickle",)), bug("B03", keywords=("md5",))]
    run1 = score_run("r1", [finding(), finding(title="avoid pickle", rule_id="pickle")], bugs)
    run2 = score_run("r2", [finding()], bugs)

    report = summarise([run1, run2], [{"x"}, {"x"}], bugs)

    assert report.detected_every_run == ["B01"]
    assert report.detected_some_runs == ["B02"]
    assert report.never_detected == ["B03"]
    assert report.mean_recall == pytest.approx((2 / 3 + 1 / 3) / 2)
    assert report.to_dict()["planted_bugs"] == 3


# --------------------------------------------------------------------------
# secret de-duplication
# --------------------------------------------------------------------------
def secret(tool: Tool, location: str) -> Finding:
    if tool == Tool.TRIVY:
        return finding(
            tool=tool,
            title="Hardcoded secret: JWT token",
            rule_id="jwt-token",
            location=location,
            metadata={"secret_category": "JWT"},
        )
    return finding(
        tool=tool,
        title="detected jwt token",
        rule_id="generic.secrets.security.detected-jwt-token",
        location=location,
    )


def test_one_secret_seen_by_three_scanners_is_one_finding():
    # Observed on Juice Shop: Semgrep, Trivy (repo) and Trivy (image) all
    # reported the same line of the same unit-test file.
    merged = merge_colocated_secrets(
        [
            secret(Tool.SEMGREP, "frontend/src/app/app.guard.spec.ts:46"),
            secret(Tool.TRIVY, "frontend/src/app/app.guard.spec.ts:46"),
            secret(Tool.TRIVY, "/juice-shop/frontend/src/app/app.guard.spec.ts:46"),
        ]
    )
    assert len(merged) == 1
    assert set(merged[0].sources) == {Tool.SEMGREP, Tool.TRIVY}


def test_secrets_on_different_lines_stay_separate():
    merged = merge_colocated_secrets(
        [secret(Tool.TRIVY, "config.py:5"), secret(Tool.TRIVY, "config.py:6")]
    )
    assert len(merged) == 2


def test_non_secret_findings_are_never_merged_by_position():
    merged = merge_colocated_secrets([finding(), finding(rule_id="other.rule", title="other")])
    assert len(merged) == 2


def test_deduplicate_applies_the_secret_merge():
    result = deduplicate([secret(Tool.SEMGREP, "config.py:5"), secret(Tool.TRIVY, "config.py:5")])
    assert len(result) == 1
