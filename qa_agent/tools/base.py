"""Shared plumbing for tool adapters.

Every adapter follows the same shape:

    run_<tool>(target, ctx) -> ScanOutcome

It invokes the tool, writes the raw output to ``workspace/<run>/raw/<tool>.json``
so the finding can always be traced back to the evidence, hands that raw output
to a pure parser, and returns both the findings and a verdict describing how
the invocation went.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qa_agent.config import Settings
from qa_agent.logging_setup import get_logger
from qa_agent.models.finding import Finding
from qa_agent.models.run import ToolRun, Verdict
from qa_agent.workspace import RunWorkspace

log = get_logger(__name__)


@dataclass(frozen=True)
class ToolContext:
    """Everything an adapter needs, passed as one object."""

    settings: Settings
    workspace: RunWorkspace

    @property
    def command_log(self) -> Path:
        """Where subprocess invocations are recorded for auditing."""
        return self.workspace.command_log


@dataclass(frozen=True)
class ScanOutcome:
    """The result of one adapter: a verdict plus whatever it found."""

    run: ToolRun
    findings: list[Finding]

    @classmethod
    def of(
        cls,
        tool: str,
        verdict: Verdict,
        *,
        findings: list[Finding] | None = None,
        duration_s: float = 0.0,
        detail: str = "",
        raw_output: str = "",
    ) -> ScanOutcome:
        items = findings or []
        return cls(
            run=ToolRun(
                tool=tool,
                verdict=verdict,
                duration_s=round(duration_s, 2),
                findings_count=len(items),
                detail=detail,
                raw_output=raw_output,
            ),
            findings=items,
        )

    @classmethod
    def skipped(cls, tool: str, reason: str) -> ScanOutcome:
        """The tool was deliberately not run; the report must say why."""
        return cls.of(tool, Verdict.SKIPPED, detail=reason)

    @classmethod
    def not_applicable(cls, tool: str, reason: str) -> ScanOutcome:
        """The tool ran but had nothing to analyse, e.g. no lockfile present."""
        return cls.of(tool, Verdict.NOT_APPLICABLE, detail=reason)

    @classmethod
    def failed(cls, tool: str, reason: str, duration_s: float = 0.0) -> ScanOutcome:
        return cls.of(tool, Verdict.FAILED, detail=reason, duration_s=duration_s)


def load_json(path: Path) -> Any:
    """Read a tool's JSON output defensively.

    Two real-world problems are handled here:

    * Some Windows tools emit a UTF-8 byte-order mark, which ``json.loads``
      rejects outright, so ``utf-8-sig`` is used.
    * A scanner quotes source text back in its report, and that source is not
      always valid UTF-8. Semgrep scanning OWASP Juice Shop produces exactly
      this (a stray ``0x97`` byte). Undecodable bytes are replaced rather than
      allowed to throw away an entire scan's results.
    """
    raw = path.read_bytes()
    if not raw.strip():
        return None
    text = raw.decode("utf-8-sig", errors="replace")
    return json.loads(text)
