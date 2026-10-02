"""Translate axe-core accessibility results into unified findings.

axe reports its own four-level impact scale. It is mapped down one step
relative to the security scale on purpose: a "critical" contrast problem is a
real defect, but placing it beside a remote code execution flaw would make the
severity column meaningless. The original axe impact is preserved in metadata.
"""

from __future__ import annotations

from typing import Any

from qa_agent.models.finding import Category, Finding, Severity, Tool
from qa_agent.parsers.common import truncate

_IMPACT = {
    "critical": Severity.HIGH,
    "serious": Severity.MEDIUM,
    "moderate": Severity.LOW,
    "minor": Severity.INFO,
}

# How many offending elements to quote as evidence for one violation.
MAX_NODES_QUOTED = 3


def _wcag_tags(tags: list[str]) -> list[str]:
    """Keep the WCAG success criteria, which is what an auditor asks for."""
    return [t for t in tags if t.startswith(("wcag", "best-practice", "section508"))]


def parse_axe(
    results: dict[str, Any] | None,
    page_url: str,
    *,
    screenshot: str = "",
) -> list[Finding]:
    """Convert one page's axe-core results into findings."""
    if not results:
        return []

    findings: list[Finding] = []
    for violation in results.get("violations", []) or []:
        rule_id = str(violation.get("id", ""))
        nodes = violation.get("nodes", []) or []

        quoted = []
        for node in nodes[:MAX_NODES_QUOTED]:
            target = ", ".join(str(t) for t in (node.get("target") or []))
            snippet = " ".join(str(node.get("html", "")).split())[:200]
            quoted.append(f"{target}\n    {snippet}")

        evidence = f"{len(nodes)} element(s) affected on this page:\n  " + "\n  ".join(quoted)
        if screenshot:
            evidence += f"\n  screenshot: {screenshot}"

        findings.append(
            Finding(
                tool=Tool.AXE,
                category=Category.ACCESSIBILITY,
                severity=_IMPACT.get(str(violation.get("impact") or "").lower(), Severity.LOW),
                title=truncate(violation.get("help") or rule_id, 160),
                location=page_url,
                description=truncate(violation.get("description")),
                evidence=evidence,
                rule_id=rule_id,
                references=[str(violation["helpUrl"])] if violation.get("helpUrl") else [],
                metadata={
                    "axe_impact": violation.get("impact", ""),
                    "wcag": _wcag_tags([str(t) for t in (violation.get("tags") or [])]),
                    "node_count": len(nodes),
                    "page": page_url,
                },
            )
        )
    return findings
