"""Tests for the LLM client, triage and executive summary.

No model is ever called. A fake backend returns scripted replies, which is the
only way to test the paths that matter most here: the model replying with
broken JSON, inventing finding ids, or putting made-up numbers in a summary.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from qa_agent.config import Settings
from qa_agent.llm.client import (
    InvalidJSONReply,
    LLMClient,
    LLMReply,
    LLMUnavailable,
    PromptTooLarge,
    estimate_tokens,
)
from qa_agent.llm.json_utils import extract_json
from qa_agent.llm.summary import (
    SOURCE_LLM,
    build_facts,
    fallback_summary,
    numbers_are_grounded,
    write_executive_summary,
)
from qa_agent.llm.triage import bound_severity, parse_triage_reply, triage_findings
from qa_agent.models.finding import Category, Finding, LLMAnnotation, Severity, Tool
from qa_agent.models.run import RunSummary, ToolRun, Verdict


# --------------------------------------------------------------------------
# fakes
# --------------------------------------------------------------------------
class FakeBackend:
    """Stands in for the OpenAI client; replays a list of reply strings."""

    def __init__(self, replies: list[str] | None = None, error: Exception | None = None):
        self.replies = list(replies or [])
        self.error = error
        self.calls: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        content = self.replies.pop(0)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content=content))],
            usage=SimpleNamespace(prompt_tokens=100, completion_tokens=20),
        )


class FakeClient:
    """Stands in for LLMClient in the job-level tests."""

    model = "fake-model"

    def __init__(self, replies: list[dict] | None = None, error: Exception | None = None):
        self.replies = list(replies or [])
        self.error = error
        self.prompts: list[str] = []

    def complete_json(self, *, system, user, purpose, max_tokens=None):
        self.prompts.append(user)
        if self.error:
            raise self.error
        data = self.replies.pop(0)
        return LLMReply(data, json.dumps(data), 1, 10, 10, 0.1)


def finding(fid: str, severity: Severity = Severity.HIGH, **overrides) -> Finding:
    defaults = dict(
        id=fid,
        tool=Tool.SEMGREP,
        category=Category.SECURITY,
        severity=severity,
        title=f"issue {fid}",
        location="a.js:1",
        rule_id=f"rule.{fid}",
    )
    defaults.update(overrides)
    return Finding(**defaults)


# --------------------------------------------------------------------------
# json extraction
# --------------------------------------------------------------------------
def test_plain_json_is_parsed():
    assert extract_json('{"a": 1}') == {"a": 1}


def test_json_inside_a_code_fence_is_recovered():
    assert extract_json('```json\n{"a": 1}\n```') == {"a": 1}


def test_json_after_chatty_prose_is_recovered():
    assert extract_json('Sure! Here it is: {"a": {"b": "}"}} hope that helps') == {
        "a": {"b": "}"}
    }


def test_empty_reply_is_rejected_with_a_reason():
    with pytest.raises(ValueError, match="empty"):
        extract_json("   ")


def test_reply_without_json_is_rejected():
    with pytest.raises(ValueError, match="no valid JSON"):
        extract_json("I cannot help with that.")


# --------------------------------------------------------------------------
# the client
# --------------------------------------------------------------------------
def test_client_sends_temperature_zero_a_seed_and_json_mode():
    backend = FakeBackend(['{"ok": true}'])
    client = LLMClient(Settings(), backend=backend)

    reply = client.complete_json(system="s", user="u", purpose="t")

    call = backend.calls[0]
    assert reply.data == {"ok": True}
    assert call["temperature"] == 0.0
    assert call["seed"] == 7
    assert call["response_format"] == {"type": "json_object"}


def test_invalid_json_is_sent_back_once_for_repair():
    backend = FakeBackend(["not json", '{"fixed": true}'])
    client = LLMClient(Settings(), backend=backend)

    reply = client.complete_json(system="s", user="u", purpose="t")

    assert reply.data == {"fixed": True}
    assert reply.attempts == 2
    # The model is shown its own broken reply and the parse error.
    repair_messages = backend.calls[1]["messages"]
    assert repair_messages[-2] == {"role": "assistant", "content": "not json"}
    assert "not valid JSON" in repair_messages[-1]["content"]


def test_the_client_gives_up_after_one_repair():
    backend = FakeBackend(["nope", "still nope"])
    client = LLMClient(Settings(), backend=backend)

    with pytest.raises(InvalidJSONReply):
        client.complete_json(system="s", user="u", purpose="t")
    assert len(backend.calls) == 2  # never loops


def test_a_json_array_at_the_top_level_is_rejected():
    backend = FakeBackend(["[1, 2]", "[3]"])
    with pytest.raises(InvalidJSONReply):
        LLMClient(Settings(), backend=backend).complete_json(system="s", user="u", purpose="t")


def test_an_oversized_prompt_is_refused_before_it_is_sent():
    backend = FakeBackend(['{"ok": true}'])
    client = LLMClient(Settings(llm_context_tokens=500), backend=backend)

    with pytest.raises(PromptTooLarge):
        client.complete_json(system="s", user="x" * 5000, purpose="t")
    # Nothing was sent: a truncated prompt would lose its rules silently.
    assert backend.calls == []


def test_transport_errors_become_llm_unavailable():
    backend = FakeBackend(error=ConnectionError("refused"))
    with pytest.raises(LLMUnavailable):
        LLMClient(Settings(), backend=backend).complete_json(system="s", user="u", purpose="t")


def test_every_attempt_is_written_to_the_audit_log(tmp_path):
    log_path = tmp_path / "llm.jsonl"
    backend = FakeBackend(["bad", '{"ok": true}'])
    LLMClient(Settings(), backend=backend, log_path=log_path).complete_json(
        system="s", user="u", purpose="triage"
    )

    records = [json.loads(line) for line in log_path.read_text(encoding="utf-8").splitlines()]
    assert [r["attempt"] for r in records] == [1, 2]
    assert records[0]["error"] and not records[1]["error"]
    assert records[1]["purpose"] == "triage"
    assert records[1]["seed"] == 7


def test_token_estimate_is_conservative():
    assert estimate_tokens("x" * 300) == 100


def test_availability_check_reports_a_missing_model(monkeypatch):
    import qa_agent.llm.client as client_module

    response = SimpleNamespace(
        raise_for_status=lambda: None, json=lambda: {"models": [{"name": "other:1b"}]}
    )
    monkeypatch.setattr(client_module.httpx, "get", lambda *a, **k: response)

    ok, reason = LLMClient(Settings(), backend=FakeBackend()).check_available()

    assert not ok
    assert "ollama pull" in reason


def test_availability_check_reports_an_unreachable_server(monkeypatch):
    import qa_agent.llm.client as client_module

    def boom(*args, **kwargs):
        raise ConnectionError("refused")

    monkeypatch.setattr(client_module.httpx, "get", boom)

    ok, reason = LLMClient(Settings(), backend=FakeBackend()).check_available()
    assert not ok and "not reachable" in reason


# --------------------------------------------------------------------------
# triage
# --------------------------------------------------------------------------
def test_severity_moves_at_most_one_level():
    assert bound_severity(Severity.CRITICAL, Severity.INFO) == Severity.HIGH
    assert bound_severity(Severity.LOW, Severity.CRITICAL) == Severity.MEDIUM
    assert bound_severity(Severity.HIGH, Severity.MEDIUM) == Severity.MEDIUM


def test_hallucinated_ids_are_ignored():
    batch = [finding("real")]
    data = {"results": [{"id": "invented", "severity": "low"}, {"id": "real", "severity": "high"}]}

    annotations = parse_triage_reply(data, batch, "m")

    assert set(annotations) == {"real"}


def test_the_string_false_is_not_treated_as_true():
    data = {"results": [{"id": "a", "false_positive": "false"}]}
    assert parse_triage_reply(data, [finding("a")], "m")["a"].is_likely_false_positive is False


def test_an_unchanged_severity_is_not_recorded_as_an_adjustment():
    data = {"results": [{"id": "a", "severity": "high"}]}
    annotation = parse_triage_reply(data, [finding("a", Severity.HIGH)], "m")["a"]
    assert annotation.adjusted_severity is None


def test_an_unknown_severity_word_keeps_the_tools_verdict():
    data = {"results": [{"id": "a", "severity": "apocalyptic"}]}
    assert parse_triage_reply(data, [finding("a")], "m")["a"].adjusted_severity is None


def test_a_malformed_reply_yields_no_annotations():
    assert parse_triage_reply({"results": "nope"}, [finding("a")], "m") == {}
    assert parse_triage_reply(None, [finding("a")], "m") == {}


def test_triage_annotates_copies_and_keeps_the_original_severity():
    original = [finding("a", Severity.CRITICAL), finding("b", Severity.LOW)]
    client = FakeClient(
        [
            {
                "results": [
                    {"id": "a", "false_positive": True, "severity": "info", "explanation": "x"},
                    {"id": "b", "severity": "low", "fix": "y"},
                ]
            }
        ]
    )

    annotated, stats = triage_findings(original, client, batch_size=5, max_findings=10)

    first = next(f for f in annotated if f.id == "a")
    assert first.severity == Severity.CRITICAL  # tool data untouched
    assert first.effective_severity == Severity.HIGH  # clamped to one level down
    assert first.llm_annotation.is_likely_false_positive
    assert first.llm_annotation.model == "fake-model"
    assert original[0].llm_annotation is None  # the input list was not mutated
    assert stats.reviewed == 2 and stats.false_positive_flags == 1


def test_triage_only_reviews_the_most_severe_up_to_the_limit():
    findings = [finding("low", Severity.LOW), finding("crit", Severity.CRITICAL)]
    client = FakeClient([{"results": [{"id": "crit"}]}])

    _, stats = triage_findings(findings, client, batch_size=5, max_findings=1)

    assert '"crit"' in client.prompts[0] and '"low"' not in client.prompts[0]
    assert stats.not_reviewed == 1


def test_unverified_findings_are_not_sent_for_triage():
    client = FakeClient([])

    _, stats = triage_findings(
        [finding("a", verified=False)], client, batch_size=5, max_findings=10
    )

    assert client.prompts == [] and stats.eligible == 0


def test_an_oversized_batch_is_split_instead_of_truncated():
    class Splitting(FakeClient):
        def complete_json(self, *, system, user, purpose, max_tokens=None):
            if user.count('"id"') > 1:
                raise PromptTooLarge("too big")
            fid = json.loads(user.split("\n", 1)[1])[0]["id"]
            self.prompts.append(user)
            return LLMReply({"results": [{"id": fid}]}, "", 1, 1, 1, 0.1)

    client = Splitting()
    _, stats = triage_findings([finding("a"), finding("b")], client, batch_size=2, max_findings=10)

    assert stats.reviewed == 2
    assert len(client.prompts) == 2


def test_a_failing_model_leaves_findings_unannotated():
    client = FakeClient(error=LLMUnavailable("down"))

    annotated, stats = triage_findings([finding("a")], client, batch_size=5, max_findings=10)

    assert annotated[0].llm_annotation is None
    assert stats.failed_batches == 1


# --------------------------------------------------------------------------
# executive summary
# --------------------------------------------------------------------------
def summary_with_tools() -> RunSummary:
    summary = RunSummary(run_id="r")
    summary.add(ToolRun(tool="semgrep", verdict=Verdict.OK))
    summary.add(ToolRun(tool="osv", verdict=Verdict.NOT_APPLICABLE))
    return summary


def test_facts_count_only_verified_findings():
    facts = build_facts([finding("a"), finding("b", verified=False)], summary_with_tools())

    assert facts["total_verified_findings"] == 1
    assert facts["not_reproduced"] == 1
    assert facts["tools_that_did_not_run"] == ["osv"]


def test_facts_leave_likely_false_positives_out_of_the_top_list():
    flagged = finding("a").model_copy(
        update={"llm_annotation": LLMAnnotation(is_likely_false_positive=True)}
    )
    facts = build_facts([flagged, finding("b")], summary_with_tools())

    assert [f["title"] for f in facts["most_severe_findings"]] == ["issue b"]
    assert facts["flagged_as_likely_false_positive"] == 1


def test_generated_test_failures_are_counted_but_not_listed_as_top_problems():
    generated = finding("flow", Severity.CRITICAL, tool=Tool.PLAYWRIGHT)
    facts = build_facts([generated, finding("real", Severity.LOW)], summary_with_tools())

    assert [f["title"] for f in facts["most_severe_findings"]] == ["issue real"]
    assert facts["generated_test_failures_awaiting_human_confirmation"] == 1


def test_a_summary_with_only_known_numbers_is_grounded():
    facts = {"total_findings": 12, "by_severity": {"high": 3}}
    assert numbers_are_grounded("There are 12 findings, 3 of them high.", facts)


def test_an_invented_number_is_caught():
    assert not numbers_are_grounded("There are 40 critical findings.", {"total_findings": 12})


def test_fallback_summary_is_built_from_the_facts():
    facts = build_facts([finding("a", Severity.CRITICAL)], summary_with_tools())
    text = fallback_summary(facts)

    assert "1 verified finding" in text
    assert "issue a" in text
    assert "osv" in text  # coverage gaps are mentioned


def test_a_grounded_model_summary_is_used():
    facts = build_facts([finding("a")], summary_with_tools())
    client = FakeClient([{"summary": "One high issue needs attention first."}])

    text, source = write_executive_summary(client, facts)

    assert source == SOURCE_LLM
    assert text.startswith("One high issue")


def test_a_summary_with_invented_numbers_is_replaced_by_the_fallback():
    facts = build_facts([finding("a")], summary_with_tools())
    client = FakeClient([{"summary": "There are 57 critical vulnerabilities."}])

    text, source = write_executive_summary(client, facts)

    assert source.startswith("fallback")
    assert "57" not in text


def test_an_empty_model_summary_falls_back():
    client = FakeClient([{"summary": "   "}])
    _, source = write_executive_summary(client, build_facts([], summary_with_tools()))
    assert source.startswith("fallback")


def test_a_model_failure_falls_back():
    client = FakeClient(error=LLMUnavailable("down"))
    _, source = write_executive_summary(client, build_facts([], summary_with_tools()))
    assert source.startswith("fallback")
