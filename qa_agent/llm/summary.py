"""The executive summary: the one place the model writes free prose.

Free prose is where hallucination is hardest to spot, so this job has the
strictest guard in the project. The model receives only facts computed from
tool output, and its summary is then checked: **every number it writes must
appear in those facts**. A summary that mentions "12 critical issues" when the
facts say 8 is rejected, and a deterministic summary built from the same facts
is used instead. The report states which of the two it is showing.
"""

from __future__ import annotations

import json
import re
from typing import Any

from qa_agent.llm.client import LLMClient, LLMError
from qa_agent.llm.prompts import SUMMARY_SYSTEM, SUMMARY_USER
from qa_agent.logging_setup import get_logger
from qa_agent.models.finding import Finding, Tool
from qa_agent.models.run import RunSummary

log = get_logger(__name__)

TOP_FINDINGS = 8
_NUMBER = re.compile(r"\d+(?:\.\d+)?")

SOURCE_LLM = "llm"
SOURCE_FALLBACK = "fallback"


def _is_flagged(finding: Finding) -> bool:
    return bool(finding.llm_annotation and finding.llm_annotation.is_likely_false_positive)


def _needs_confirmation(finding: Finding) -> bool:
    """A generated-test failure: its expectation was written by the model."""
    return finding.tool == Tool.PLAYWRIGHT


def build_facts(findings: list[Finding], summary: RunSummary) -> dict[str, Any]:
    """Everything the summary may say, computed from tool output only.

    Generated-test failures are counted separately and kept out of the list of
    most severe problems: observed on Juice Shop, all three were the model
    guessing the wrong error wording, and the summary described them as
    functional issues.
    """
    counted = [f for f in findings if f.verified]
    top = [f for f in counted if not _is_flagged(f) and not _needs_confirmation(f)][
        :TOP_FINDINGS
    ]

    # Key names say exactly what each number counts. Observed with the 3B
    # model: given "by_category": {"dependency": 129}, it wrote "vulnerabilities
    # across 129 dependencies" - a real number attached to the wrong noun, which
    # the number check alone cannot catch.
    return {
        "total_verified_findings": len(counted),
        "verified_findings_per_severity": {
            k: v for k, v in summary.counts_by_severity(counted).items() if v
        },
        "verified_findings_per_category": summary.counts_by_category(counted),
        "not_reproduced": len(findings) - len(counted),
        "flagged_as_likely_false_positive": sum(1 for f in counted if _is_flagged(f)),
        "generated_test_failures_awaiting_human_confirmation": sum(
            1 for f in counted if _needs_confirmation(f)
        ),
        "tools_that_ran": sorted({t.tool for t in summary.tool_runs if t.verdict.value == "ok"}),
        "tools_that_did_not_run": sorted(
            {t.tool for t in summary.tool_runs if t.verdict.value != "ok"}
        ),
        "most_severe_findings": [
            {
                "severity": f.effective_severity.value,
                "category": f.category.value,
                "title": f.title,
                "location": f.location,
            }
            for f in top
        ],
    }


def numbers_are_grounded(text: str, facts: dict[str, Any]) -> bool:
    """Every number in *text* must also occur somewhere in *facts*."""
    allowed = set(_NUMBER.findall(json.dumps(facts, ensure_ascii=False)))
    return all(number in allowed for number in _NUMBER.findall(text))


def fallback_summary(facts: dict[str, Any]) -> str:
    """A plain, deterministic summary built from the same facts."""
    severity = facts.get("verified_findings_per_severity", {})
    parts = [f"{count} {name}" for name, count in severity.items()]
    sentences = [
        f"The scan produced {facts.get('total_verified_findings', 0)} verified finding(s)"
        + (f": {', '.join(parts)}." if parts else ".")
    ]
    categories = facts.get("verified_findings_per_category", {})
    if categories:
        biggest = max(categories, key=categories.get)
        sentences.append(f"The largest category is {biggest} ({categories[biggest]}).")
    top = facts.get("most_severe_findings", [])
    if top:
        sentences.append(
            f"The most severe issue is \"{top[0]['title']}\" at {top[0]['location']}; "
            f"start remediation there."
        )
    if facts.get("tools_that_did_not_run"):
        sentences.append(
            "Some tools did not produce results ("
            + ", ".join(facts["tools_that_did_not_run"])
            + "), so coverage in those areas is incomplete."
        )
    return " ".join(sentences)


def write_executive_summary(client: LLMClient, facts: dict[str, Any]) -> tuple[str, str]:
    """Return ``(summary_text, source)`` where source says who wrote it."""
    user = SUMMARY_USER.format(facts=json.dumps(facts, ensure_ascii=False, indent=1))
    try:
        reply = client.complete_json(
            system=SUMMARY_SYSTEM, user=user, purpose="summary", max_tokens=500
        )
    except LLMError as exc:
        log.warning("executive summary fell back to the deterministic version: %s", exc)
        return fallback_summary(facts), f"{SOURCE_FALLBACK}: {exc}"

    text = " ".join(str(reply.data.get("summary", "") or "").split())
    if not text:
        return fallback_summary(facts), f"{SOURCE_FALLBACK}: the model returned no summary"
    if not numbers_are_grounded(text, facts):
        log.warning("executive summary rejected: it contained numbers not in the tool output")
        reason = (
            f"{SOURCE_FALLBACK}: the model's summary contained numbers not present in "
            "the tool output and was discarded"
        )
        return fallback_summary(facts), reason
    return text, SOURCE_LLM
