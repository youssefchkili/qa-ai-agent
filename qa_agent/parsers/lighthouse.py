"""Translate a Lighthouse JSON report into unified findings.

Lighthouse scores each category from 0 to 1. A finding is raised when a
category falls below its configured budget, and the audits that cost the most
points are attached as evidence, so the report says *why* the score is low
rather than only that it is.
"""

from __future__ import annotations

from typing import Any

from qa_agent.models.finding import Category, Finding, Severity, Tool
from qa_agent.parsers.common import truncate

# Which Lighthouse categories become findings, and under which unified category.
_CATEGORY_MAP = {
    "performance": Category.PERFORMANCE,
    "best-practices": Category.CODE,
    "seo": Category.CODE,
}

# Metrics worth quoting verbatim: these are the Core Web Vitals plus TTI.
_KEY_METRICS = (
    "first-contentful-paint",
    "largest-contentful-paint",
    "total-blocking-time",
    "cumulative-layout-shift",
    "speed-index",
    "interactive",
)

MAX_OPPORTUNITIES = 5

# Google's published "poor" boundaries for the Core Web Vitals that can be
# measured in a lab (web.dev/articles/vitals). A category score blends many
# metrics: the evaluation app's home page scored 71/100 while its largest
# paint took 4.7 s, so the score alone let a clearly slow page through.
POOR_LCP_MS = 4000
POOR_CLS = 0.25


def _web_vitals_findings(payload: dict[str, Any], page_url: str) -> list[Finding]:
    """One finding per Core Web Vital that is in Google's "poor" range."""
    audits = payload.get("audits", {}) or {}
    findings: list[Finding] = []

    lcp = (audits.get("largest-contentful-paint") or {}).get("numericValue")
    if isinstance(lcp, (int, float)) and lcp > POOR_LCP_MS:
        findings.append(
            Finding(
                tool=Tool.LIGHTHOUSE,
                category=Category.PERFORMANCE,
                severity=Severity.MEDIUM,
                title=f"Largest Contentful Paint of {lcp / 1000:.1f} s is in the poor range",
                location=page_url,
                description=truncate(
                    "The main content of this page takes longer than 4 seconds to appear, "
                    "which Google classifies as a poor user experience."
                ),
                evidence=f"LCP {lcp / 1000:.2f} s (poor above {POOR_LCP_MS / 1000:.1f} s)",
                rule_id="lighthouse:performance:lcp",
                metadata={"page": page_url, "lcp_ms": round(lcp)},
            )
        )

    cls = (audits.get("cumulative-layout-shift") or {}).get("numericValue")
    if isinstance(cls, (int, float)) and cls > POOR_CLS:
        findings.append(
            Finding(
                tool=Tool.LIGHTHOUSE,
                category=Category.PERFORMANCE,
                severity=Severity.MEDIUM,
                title=f"Cumulative Layout Shift of {cls:.2f} is in the poor range",
                location=page_url,
                description=truncate(
                    "Content on this page moves while it loads, which Google classifies as a "
                    "poor user experience."
                ),
                evidence=f"CLS {cls:.3f} (poor above {POOR_CLS})",
                rule_id="lighthouse:performance:cls",
                metadata={"page": page_url, "cls": round(cls, 3)},
            )
        )
    return findings


def _severity_for(score: int, budget: int) -> Severity:
    """How far below budget the score fell decides how loudly to report it."""
    shortfall = budget - score
    if score < budget / 2:
        return Severity.HIGH
    if shortfall > 15:
        return Severity.MEDIUM
    return Severity.LOW


def _failing_audits(payload: dict[str, Any], category_key: str) -> list[str]:
    """Audit titles that lost the most points in this category."""
    audits = payload.get("audits", {}) or {}
    category = (payload.get("categories", {}) or {}).get(category_key, {}) or {}

    scored: list[tuple[float, str]] = []
    for ref in category.get("auditRefs", []) or []:
        audit = audits.get(ref.get("id", ""), {}) or {}
        score = audit.get("score")
        weight = float(ref.get("weight", 0) or 0)
        if score is None or score >= 0.9 or weight <= 0:
            continue
        lost = (1.0 - float(score)) * weight
        title = str(audit.get("title", ref.get("id", "")))
        display = str(audit.get("displayValue", "") or "")
        scored.append((lost, f"{title}{f' ({display})' if display else ''}"))

    scored.sort(key=lambda item: item[0], reverse=True)
    return [label for _, label in scored[:MAX_OPPORTUNITIES]]


def _metrics(payload: dict[str, Any]) -> dict[str, str]:
    audits = payload.get("audits", {}) or {}
    out: dict[str, str] = {}
    for key in _KEY_METRICS:
        audit = audits.get(key) or {}
        if audit.get("displayValue"):
            out[key] = str(audit["displayValue"])
    return out


def parse_lighthouse(
    payload: dict[str, Any] | None,
    page_url: str,
    *,
    budgets: dict[str, int],
) -> list[Finding]:
    """Convert one Lighthouse report into findings for categories under budget."""
    if not payload:
        return []

    categories = payload.get("categories", {}) or {}
    metrics = _metrics(payload)
    findings: list[Finding] = _web_vitals_findings(payload, page_url)

    for key, unified_category in _CATEGORY_MAP.items():
        entry = categories.get(key)
        if not entry or entry.get("score") is None:
            continue

        score = round(float(entry["score"]) * 100)
        budget = int(budgets.get(key, 50))
        if score >= budget:
            continue

        failing = _failing_audits(payload, key)
        evidence_lines = [f"Lighthouse {key} score: {score}/100 (budget {budget})."]
        if key == "performance" and metrics:
            evidence_lines.append(
                "Metrics: " + ", ".join(f"{name}={value}" for name, value in metrics.items())
            )
        if failing:
            evidence_lines.append("Biggest contributors:")
            evidence_lines.extend(f"  - {item}" for item in failing)

        findings.append(
            Finding(
                tool=Tool.LIGHTHOUSE,
                category=unified_category,
                severity=_severity_for(score, budget),
                title=f"Lighthouse {entry.get('title', key)} score {score}/100 "
                f"is below the budget of {budget}",
                location=page_url,
                description=truncate(
                    f"Lighthouse scored the {key} category at {score} out of 100 for this page, "
                    f"below the configured budget of {budget}."
                ),
                evidence="\n".join(evidence_lines),
                rule_id=f"lighthouse:{key}",
                metadata={
                    "page": page_url,
                    "lighthouse_category": key,
                    "score": score,
                    "budget": budget,
                    "metrics": metrics,
                    "failing_audits": failing,
                },
            )
        )
    return findings
