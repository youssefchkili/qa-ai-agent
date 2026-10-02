"""Precision, recall and run-to-run consistency.

Definitions, stated plainly because they decide what the numbers mean:

* **Recall** = planted bugs detected by at least one finding / all planted bugs.
  "Did the agent find what is there?"
* **Precision** = findings that detect a planted bug / all verified findings.
  "How much of what it reported is on the answer sheet?" This is *strict*: a
  real problem the author did not plant still counts against precision, so
  unmatched findings are listed for manual review rather than silently dropped.
* **Reviewed precision** = (findings that detect a planted bug + findings that
  match a real-but-unplanted issue confirmed by manual review) / all verified
  findings. Reported next to strict precision, never instead of it.
* **Consistency** = mean pairwise Jaccard similarity of the finding-id sets of
  repeated runs (1.0 = identical). Deterministic fingerprints are what make
  this measurable at all.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any

from qa_agent.evaluation.answer_sheet import Bug, matched_bugs
from qa_agent.models.finding import Finding


@dataclass(frozen=True)
class RunScore:
    """How one run scored against the answer sheet."""

    run_id: str
    total_findings: int
    matched_findings: int
    precision: float
    recall: float
    detected: tuple[str, ...]
    missed: tuple[str, ...]
    unmatched: tuple[dict[str, str], ...]
    unverified: int
    flagged_false_positive: int
    real_unplanted: int = 0

    @property
    def reviewed_precision(self) -> float:
        if not self.total_findings:
            return 0.0
        return (self.matched_findings + self.real_unplanted) / self.total_findings


@dataclass
class EvaluationReport:
    """Aggregate over all runs."""

    runs: list[RunScore]
    bugs: list[Bug]
    finding_consistency: float
    detected_every_run: list[str] = field(default_factory=list)
    detected_some_runs: list[str] = field(default_factory=list)
    never_detected: list[str] = field(default_factory=list)
    recall_by_category: dict[str, float] = field(default_factory=dict)

    @property
    def mean_precision(self) -> float:
        return _mean([r.precision for r in self.runs])

    @property
    def mean_recall(self) -> float:
        return _mean([r.recall for r in self.runs])

    @property
    def mean_reviewed_precision(self) -> float:
        return _mean([r.reviewed_precision for r in self.runs])

    def to_dict(self) -> dict[str, Any]:
        titles = {bug.id: bug.title for bug in self.bugs}
        return {
            "planted_bugs": len(self.bugs),
            "runs": [
                {
                    "run_id": r.run_id,
                    "precision": round(r.precision, 4),
                    "reviewed_precision": round(r.reviewed_precision, 4),
                    "recall": round(r.recall, 4),
                    "real_unplanted": r.real_unplanted,
                    "findings": r.total_findings,
                    "matched_findings": r.matched_findings,
                    "unverified": r.unverified,
                    "flagged_false_positive": r.flagged_false_positive,
                    "detected": list(r.detected),
                    "missed": list(r.missed),
                    "unmatched_findings": list(r.unmatched),
                }
                for r in self.runs
            ],
            "mean_precision": round(self.mean_precision, 4),
            "mean_reviewed_precision": round(self.mean_reviewed_precision, 4),
            "mean_recall": round(self.mean_recall, 4),
            "finding_consistency": round(self.finding_consistency, 4),
            "recall_by_category": {k: round(v, 4) for k, v in self.recall_by_category.items()},
            "detected_every_run": [f"{b} {titles[b]}" for b in self.detected_every_run],
            "detected_some_runs": [f"{b} {titles[b]}" for b in self.detected_some_runs],
            "never_detected": [f"{b} {titles[b]}" for b in self.never_detected],
        }


def _mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def jaccard(first: set[str], second: set[str]) -> float:
    """|A intersect B| / |A union B|, defined as 1.0 for two empty sets."""
    union = first | second
    return len(first & second) / len(union) if union else 1.0


def consistency(id_sets: list[set[str]]) -> float:
    """Mean pairwise Jaccard similarity; a single run is trivially consistent."""
    pairs = list(combinations(id_sets, 2))
    return _mean([jaccard(a, b) for a, b in pairs]) if pairs else 1.0


def score_run(
    run_id: str,
    findings: list[Finding],
    bugs: list[Bug],
    known_real: list[Bug] | None = None,
) -> RunScore:
    """Score one run's findings against the answer sheet."""
    verified = [f for f in findings if f.verified]
    detected: set[str] = set()
    matched = 0
    real_unplanted = 0
    unmatched: list[dict[str, str]] = []

    for finding in verified:
        hits = matched_bugs(finding, bugs)
        if hits:
            matched += 1
            detected.update(hits)
        elif known_real and matched_bugs(finding, known_real):
            real_unplanted += 1
        else:
            unmatched.append(
                {
                    "tool": finding.tool.value,
                    "category": finding.category.value,
                    "severity": finding.effective_severity.value,
                    "title": finding.title,
                    "location": finding.location,
                    "rule_id": finding.rule_id,
                }
            )

    all_ids = [bug.id for bug in bugs]
    return RunScore(
        run_id=run_id,
        total_findings=len(verified),
        matched_findings=matched,
        precision=matched / len(verified) if verified else 0.0,
        recall=len(detected) / len(bugs) if bugs else 0.0,
        detected=tuple(b for b in all_ids if b in detected),
        missed=tuple(b for b in all_ids if b not in detected),
        unmatched=tuple(unmatched),
        unverified=len(findings) - len(verified),
        flagged_false_positive=sum(
            1
            for f in verified
            if f.llm_annotation and f.llm_annotation.is_likely_false_positive
        ),
        real_unplanted=real_unplanted,
    )


def summarise(
    scores: list[RunScore], id_sets: list[set[str]], bugs: list[Bug]
) -> EvaluationReport:
    """Combine per-run scores into the evaluation report."""
    detected_counts: dict[str, int] = defaultdict(int)
    for score in scores:
        for bug_id in score.detected:
            detected_counts[bug_id] += 1

    runs = len(scores)
    every = [b.id for b in bugs if runs and detected_counts[b.id] == runs]
    some = [b.id for b in bugs if 0 < detected_counts[b.id] < runs]
    never = [b.id for b in bugs if detected_counts[b.id] == 0]

    by_category: dict[str, list[float]] = defaultdict(list)
    for bug in bugs:
        by_category[bug.category].append(detected_counts[bug.id] / runs if runs else 0.0)

    return EvaluationReport(
        runs=scores,
        bugs=bugs,
        finding_consistency=consistency(id_sets),
        detected_every_run=every,
        detected_some_runs=some,
        never_detected=never,
        recall_by_category={cat: _mean(vals) for cat, vals in sorted(by_category.items())},
    )
