"""Tests for the unified finding schema and its deterministic identity."""

from __future__ import annotations

from qa_agent.models.finding import (
    Category,
    Finding,
    LLMAnnotation,
    Severity,
    Tool,
    normalize_location,
)


def make(**overrides) -> Finding:
    defaults = dict(
        tool=Tool.SEMGREP,
        category=Category.SECURITY,
        severity=Severity.HIGH,
        title="eval detected",
        location="routes/captcha.ts:22",
        rule_id="javascript.browser.security.eval-detected",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# --------------------------------------------------------------------------
# fingerprints
# --------------------------------------------------------------------------
def test_identical_findings_share_an_id():
    assert make().id == make().id


def test_id_is_sixteen_hex_characters():
    finding_id = make().id
    assert len(finding_id) == 16
    assert all(char in "0123456789abcdef" for char in finding_id)


def test_different_locations_produce_different_ids():
    assert make().id != make(location="routes/other.ts:9").id


def test_different_rules_produce_different_ids():
    assert make().id != make(rule_id="javascript.express.security.xss").id


def test_reworded_message_keeps_the_same_id():
    # A tool upgrade that rewrites its message must not create a new finding.
    first = make(description="Detected the use of eval().")
    second = make(description="eval() usage detected; this is dangerous.")
    assert first.id == second.id


def test_rescored_severity_keeps_the_same_id():
    assert make(severity=Severity.HIGH).id == make(severity=Severity.LOW).id


def test_windows_and_posix_paths_fingerprint_alike():
    assert make(location="routes\\captcha.ts:22").id == make(location="routes/captcha.ts:22").id


def test_explicit_id_is_preserved():
    assert make(id="deadbeefdeadbeef").id == "deadbeefdeadbeef"


# --------------------------------------------------------------------------
# location normalisation
# --------------------------------------------------------------------------
def test_normalize_location_converts_separators():
    assert normalize_location("src\\app\\main.ts") == "src/app/main.ts"


def test_normalize_location_strips_leading_dot_slash():
    assert normalize_location("./src/main.ts") == "src/main.ts"


def test_normalize_location_drops_a_trailing_slash():
    assert normalize_location("http://localhost:3000/") == "http://localhost:3000"


def test_normalize_location_keeps_the_url_scheme_intact():
    assert normalize_location("http://localhost:3000//a//b") == "http://localhost:3000/a/b"


# --------------------------------------------------------------------------
# severity and annotations
# --------------------------------------------------------------------------
def test_severity_rank_orders_critical_first():
    ordered = sorted([Severity.LOW, Severity.CRITICAL, Severity.MEDIUM], key=lambda s: s.rank)
    assert ordered == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_effective_severity_defaults_to_the_tool_verdict():
    assert make(severity=Severity.HIGH).effective_severity == Severity.HIGH


def test_llm_can_adjust_severity_without_losing_the_original():
    finding = make(severity=Severity.HIGH)
    finding.llm_annotation = LLMAnnotation(adjusted_severity=Severity.LOW)

    assert finding.effective_severity == Severity.LOW
    # The tool's own verdict is still recorded.
    assert finding.severity == Severity.HIGH


def test_sources_default_to_the_reporting_tool():
    assert make().sources == [Tool.SEMGREP]


def test_findings_are_json_serialisable():
    payload = make().model_dump(mode="json")
    assert payload["tool"] == "semgrep"
    assert payload["severity"] == "high"
    assert payload["verified"] is True
