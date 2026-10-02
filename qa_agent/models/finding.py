"""The unified finding schema: the backbone of the whole project.

Every tool speaks its own dialect. Semgrep reports ``ERROR`` on a file and line,
Trivy reports ``CRITICAL`` on a package, Lighthouse reports a score out of 100.
Each parser translates its tool's output into one :class:`Finding`, and from
that point on nothing else in the pipeline needs to know which tool produced it.

Two rules hold for every finding:

* It always traces back to real tool output. The LLM may annotate a finding but
  never creates one and never deletes the original tool data.
* Its ``id`` is a deterministic fingerprint, not a random UUID. Scanning the
  same code twice produces the same ids, which is what makes deduplication,
  run-to-run consistency and answer-sheet matching possible.
"""

from __future__ import annotations

import hashlib
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Normalised severity. Every tool's own scale is mapped onto this one."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Sort key: 0 is the most severe, so ``sorted`` puts critical first."""
        return _SEVERITY_ORDER[self]


_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Category(str, Enum):
    """What kind of problem this is, used to group the report."""

    CODE = "code"
    DEPENDENCY = "dependency"
    SECURITY = "security"
    ACCESSIBILITY = "accessibility"
    PERFORMANCE = "performance"
    FUNCTIONAL = "functional"


class Tool(str, Enum):
    """The deterministic source that produced a finding."""

    SEMGREP = "semgrep"
    TRIVY = "trivy"
    OSV = "osv"
    ZAP = "zap"
    AXE = "axe"
    LIGHTHOUSE = "lighthouse"
    PLAYWRIGHT = "playwright"
    CRAWLER = "crawler"


class LLMAnnotation(BaseModel):
    """What the local model added to a finding. Never replaces tool data."""

    is_likely_false_positive: bool = False
    adjusted_severity: Severity | None = None
    plain_explanation: str = ""
    suggested_fix: str = ""
    # Which model wrote this, so a reader can weigh it and an auditor can
    # find the matching exchange in llm.jsonl.
    model: str = ""


def normalize_location(location: str) -> str:
    """Canonicalise a location so the same place always fingerprints the same.

    Windows and POSIX disagree about separators, and the same page URL may be
    seen with and without a trailing slash. Without this, one problem could be
    reported twice simply because two tools spelled its location differently.
    """
    text = location.strip().replace("\\", "/")

    # Collapse duplicate slashes without destroying a URL scheme's "://".
    if "://" in text:
        scheme, _, rest = text.partition("://")
        while "//" in rest:
            rest = rest.replace("//", "/")
        text = f"{scheme}://{rest}"
    else:
        while "//" in text:
            text = text.replace("//", "/")

    text = text.removeprefix("./")
    if len(text) > 1 and text.endswith("/"):
        text = text[:-1]
    return text


class Finding(BaseModel):
    """One problem reported by one deterministic tool."""

    id: str = ""
    tool: Tool
    category: Category
    severity: Severity
    title: str
    location: str = ""
    description: str = ""
    evidence: str = ""

    # True when the finding comes straight from deterministic tool output.
    # Phase 2 re-confirms flaky sources (browser errors, generated tests) and
    # sets this to False when a re-run does not reproduce the problem.
    verified: bool = True
    verification_method: str = "tool-output"

    # The tool's own stable rule identifier (semgrep check_id, CVE, axe rule).
    # Part of the fingerprint, because titles get reworded between versions but
    # rule ids do not.
    rule_id: str = ""
    references: list[str] = Field(default_factory=list)

    # Every tool that reported this same problem. Two independent scanners
    # agreeing is a strong signal that a finding is real.
    sources: list[Tool] = Field(default_factory=list)

    # Tool-specific extras kept for the report and for phase 3 scoring
    # (package name, CWE, score, failing audits...).
    metadata: dict[str, Any] = Field(default_factory=dict)

    llm_annotation: LLMAnnotation | None = None

    def model_post_init(self, __context: Any) -> None:
        """Fill in the fingerprint and the source list when not supplied."""
        if not self.sources:
            self.sources = [self.tool]
        if not self.id:
            self.id = self.fingerprint()

    def fingerprint(self) -> str:
        """Stable identity of this finding.

        Deliberately excludes the description, evidence and severity: a tool
        upgrade that rewords a message or re-scores a rule must not turn one
        finding into two.
        """
        parts = [
            self.tool.value,
            self.category.value,
            self.rule_id or self.title,
            normalize_location(self.location),
        ]
        digest = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
        return digest[:16]

    @property
    def effective_severity(self) -> Severity:
        """Severity after LLM triage, falling back to the tool's own verdict."""
        if self.llm_annotation and self.llm_annotation.adjusted_severity:
            return self.llm_annotation.adjusted_severity
        return self.severity

    @property
    def sort_key(self) -> tuple[int, str, str]:
        """Order findings by severity, then category, then title."""
        return (self.effective_severity.rank, self.category.value, self.title)
