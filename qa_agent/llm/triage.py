"""Triage: the model reviews tool findings, and only annotates them.

This is the job the spec calls "senior QA engineer": for each finding, is it
likely a false positive, is the severity right, what does it mean in plain
English, and how would you fix it.

The model's answer is treated as untrusted input and checked before use:

* **Unknown ids are discarded.** A reply mentioning an id that was not in the
  batch is a hallucinated finding; it is ignored, never added.
* **Severity moves at most one step.** A 3B model must not be able to turn a
  CRITICAL vulnerability into INFO with one sentence. The tool's own severity
  is kept on the finding either way; the adjusted one is stored beside it.
* **"False positive" is a flag, not a deletion.** The finding stays in the
  report, marked, and a human decides.
* **Nothing is mutated.** Annotated findings are returned as new copies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from qa_agent.llm.client import LLMClient, LLMError, PromptTooLarge
from qa_agent.llm.prompts import TRIAGE_SYSTEM, TRIAGE_USER
from qa_agent.logging_setup import get_logger
from qa_agent.models.finding import Finding, LLMAnnotation, Severity
from qa_agent.parsers.common import truncate

log = get_logger(__name__)

# How far the model may move a severity away from the tool's verdict.
MAX_SEVERITY_SHIFT = 1

_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

# What the model sees per finding. Evidence is cut hard: the context window is
# small, and the first few hundred characters carry the signal.
_DESCRIPTION_CHARS = 300
_EVIDENCE_CHARS = 400


@dataclass(frozen=True)
class TriageStats:
    """What the triage job did, for the run summary."""

    eligible: int = 0
    reviewed: int = 0
    false_positive_flags: int = 0
    severity_changes: int = 0
    batches: int = 0
    failed_batches: int = 0
    not_reviewed: int = 0


def bound_severity(
    original: Severity, proposed: Severity, max_shift: int = MAX_SEVERITY_SHIFT
) -> Severity:
    """Clamp *proposed* to within *max_shift* levels of *original*."""
    start, wanted = _ORDER.index(original), _ORDER.index(proposed)
    clamped = max(start - max_shift, min(start + max_shift, wanted))
    return _ORDER[clamped]


def _parse_severity(value: Any) -> Severity | None:
    try:
        return Severity(str(value).strip().lower())
    except ValueError:
        return None


def _as_bool(value: Any) -> bool:
    """JSON booleans only; the string "false" must not count as true."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def finding_for_prompt(finding: Finding) -> dict[str, str]:
    """The compact view of a finding that is shown to the model."""
    return {
        "id": finding.id,
        "tool": finding.tool.value,
        "category": finding.category.value,
        "severity": finding.severity.value,
        "title": truncate(finding.title, 160),
        "location": truncate(finding.location, 160),
        "rule": truncate(finding.rule_id, 120),
        "description": truncate(finding.description, _DESCRIPTION_CHARS),
        "evidence": truncate(finding.evidence, _EVIDENCE_CHARS),
    }


def parse_triage_reply(data: Any, batch: list[Finding], model: str) -> dict[str, LLMAnnotation]:
    """Turn the model's JSON into annotations, keeping only what can be trusted."""
    by_id = {finding.id: finding for finding in batch}
    results = data.get("results") if isinstance(data, dict) else None
    if not isinstance(results, list):
        return {}

    annotations: dict[str, LLMAnnotation] = {}
    for item in results:
        if not isinstance(item, dict):
            continue
        finding_id = str(item.get("id", "")).strip()
        finding = by_id.get(finding_id)
        if finding is None or finding_id in annotations:
            # Unknown id (hallucinated) or a duplicate answer: ignored.
            continue

        proposed = _parse_severity(item.get("severity")) or finding.severity
        bounded = bound_severity(finding.severity, proposed)
        annotations[finding_id] = LLMAnnotation(
            is_likely_false_positive=_as_bool(item.get("false_positive", False)),
            adjusted_severity=bounded if bounded != finding.severity else None,
            plain_explanation=truncate(str(item.get("explanation", "") or ""), 600),
            suggested_fix=truncate(str(item.get("fix", "") or ""), 600),
            model=model,
        )
    return annotations


def _triage_batch(
    batch: list[Finding], client: LLMClient
) -> tuple[dict[str, LLMAnnotation], int, int]:
    """Review one batch. Returns (annotations, batches sent, batches failed).

    A batch too large for the context window is split in half and retried,
    down to a single finding; a single finding that still does not fit is
    left unreviewed rather than sent truncated.
    """
    user = TRIAGE_USER.format(
        findings=json.dumps([finding_for_prompt(f) for f in batch], ensure_ascii=False, indent=1)
    )
    try:
        reply = client.complete_json(system=TRIAGE_SYSTEM, user=user, purpose="triage")
    except PromptTooLarge:
        if len(batch) == 1:
            log.warning("finding %s is too large to triage; left unreviewed", batch[0].id)
            return {}, 0, 1
        middle = len(batch) // 2
        left, left_sent, left_failed = _triage_batch(batch[:middle], client)
        right, right_sent, right_failed = _triage_batch(batch[middle:], client)
        return {**left, **right}, left_sent + right_sent, left_failed + right_failed
    except LLMError as exc:
        log.warning("triage batch failed: %s", exc)
        return {}, 1, 1

    return parse_triage_reply(reply.data, batch, client.model), 1, 0


def triage_findings(
    findings: list[Finding],
    client: LLMClient,
    *,
    batch_size: int,
    max_findings: int,
) -> tuple[list[Finding], TriageStats]:
    """Annotate the most severe verified findings. Returns new finding objects."""
    # Unverified findings are not worth the model's time: they are already
    # flagged as not reproducible.
    eligible = [f for f in findings if f.verified]
    candidates = sorted(eligible, key=lambda f: f.sort_key)[:max_findings]

    annotations: dict[str, LLMAnnotation] = {}
    sent = failed = 0
    step = max(1, batch_size)
    for start in range(0, len(candidates), step):
        batch = candidates[start : start + step]
        result, batch_sent, batch_failed = _triage_batch(batch, client)
        annotations.update(result)
        sent += batch_sent
        failed += batch_failed

    annotated = [
        f.model_copy(update={"llm_annotation": annotations[f.id]}) if f.id in annotations else f
        for f in findings
    ]
    stats = TriageStats(
        eligible=len(eligible),
        reviewed=len(annotations),
        false_positive_flags=sum(1 for a in annotations.values() if a.is_likely_false_positive),
        severity_changes=sum(1 for a in annotations.values() if a.adjusted_severity is not None),
        batches=sent,
        failed_batches=failed,
        not_reviewed=len(eligible) - len(annotations),
    )
    log.info(
        "triage: %d reviewed, %d flagged as likely false positives, %d re-scored",
        stats.reviewed,
        stats.false_positive_flags,
        stats.severity_changes,
    )
    return annotated, stats
