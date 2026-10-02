"""Bookkeeping for a single run: what was scanned, which tools ran, how it went.

The report has to be honest about gaps. If ZAP could not start or the app could
not be launched, the report must say so rather than silently show fewer
findings, because "no findings" and "the scanner never ran" mean opposite
things to whoever reads the report.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from qa_agent.models.finding import Category, Finding, Severity


class Verdict(str, Enum):
    """Outcome of one tool invocation."""

    OK = "ok"
    SKIPPED = "skipped"
    FAILED = "failed"
    TIMEOUT = "timeout"
    NOT_APPLICABLE = "not_applicable"


class ToolRun(BaseModel):
    """Record of one tool invocation, shown in the report's run summary."""

    tool: str
    verdict: Verdict
    duration_s: float = 0.0
    findings_count: int = 0
    detail: str = ""
    raw_output: str = ""

    @property
    def ran(self) -> bool:
        return self.verdict == Verdict.OK


class RunSummary(BaseModel):
    """Everything the report needs to describe the run itself."""

    run_id: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None

    repo_url: str = ""
    app_url: str = ""
    image_ref: str = ""
    commit: str = ""

    pages_crawled: int = 0
    tool_runs: list[ToolRun] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    # --- phase 2 ------------------------------------------------------------
    llm_model: str = ""
    executive_summary: str = ""
    # "llm", or "fallback: <reason>" when the model's text was rejected.
    summary_source: str = ""
    # One entry per generated test flow (see testgen.generator.FlowOutcome).
    flows: list[dict[str, Any]] = Field(default_factory=list)

    @property
    def duration_s(self) -> float:
        end = self.finished_at or datetime.now(UTC)
        return round((end - self.started_at).total_seconds(), 1)

    def add(self, run: ToolRun) -> None:
        self.tool_runs.append(run)

    def note(self, message: str) -> None:
        """Record something the reader must know, e.g. a scan that was skipped."""
        self.notes.append(message)

    def counts_by_severity(self, findings: list[Finding]) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for finding in findings:
            counts[finding.effective_severity.value] += 1
        return counts

    def counts_by_category(self, findings: list[Finding]) -> dict[str, int]:
        counts = {c.value: 0 for c in Category}
        for finding in findings:
            counts[finding.category.value] += 1
        return {name: n for name, n in counts.items() if n}

    def to_report_context(self, findings: list[Finding]) -> dict[str, Any]:
        """Flatten into the dictionary the Jinja2 templates consume.

        Headline numbers count verified findings only: a problem that did not
        reproduce stays visible in the body of the report, but it does not
        inflate the totals a manager reads first.
        """
        verified = [f for f in findings if f.verified]
        flagged = [
            f for f in verified if f.llm_annotation and f.llm_annotation.is_likely_false_positive
        ]
        return {
            "llm_model": self.llm_model,
            "executive_summary": self.executive_summary,
            "summary_source": self.summary_source,
            "flows": self.flows,
            "flows_ran": sum(1 for flow in self.flows if flow.get("status") in ("pass", "fail")),
            "unverified": len(findings) - len(verified),
            "false_positive_flags": len(flagged),
            "total": len(verified),
            "by_severity": self.counts_by_severity(verified),
            "by_category": self.counts_by_category(verified),
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "duration_s": self.duration_s,
            "repo_url": self.repo_url,
            "app_url": self.app_url,
            "image_ref": self.image_ref,
            "commit": self.commit,
            "pages_crawled": self.pages_crawled,
            "tool_runs": [t.model_dump(mode="json") for t in self.tool_runs],
            "notes": self.notes,
        }
