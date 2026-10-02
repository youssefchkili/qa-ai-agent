"""Translate an OWASP ZAP baseline report into unified findings.

The baseline scan is passive: it spiders the application and inspects the
traffic, but does not attack it. That keeps it safe to run against a local
instance while still catching missing security headers, cookie flags,
information disclosure and similar issues.
"""

from __future__ import annotations

import re
from typing import Any

from qa_agent.models.finding import Category, Finding, Severity, Tool
from qa_agent.parsers.common import truncate

# ZAP's numeric risk scale.
_RISK = {
    "3": Severity.HIGH,
    "2": Severity.MEDIUM,
    "1": Severity.LOW,
    "0": Severity.INFO,
}

MAX_INSTANCES_QUOTED = 3


def _severity(alert: dict[str, Any]) -> Severity:
    code = str(alert.get("riskcode", "")).strip()
    return _RISK.get(code, Severity.INFO)


def _strip_html(text: str) -> str:
    """ZAP wraps its prose in <p> tags; the report renders plain text."""
    return re.sub(r"<[^>]+>", " ", str(text or ""))


def parse_zap(payload: dict[str, Any] | None, *, target_url: str = "") -> list[Finding]:
    """Convert a parsed ``zap-baseline.py -J`` document into findings."""
    if not payload:
        return []

    findings: list[Finding] = []
    for site in payload.get("site", []) or []:
        site_name = str(site.get("@name", target_url))

        for alert in site.get("alerts", []) or []:
            instances = alert.get("instances", []) or []
            plugin_id = str(alert.get("pluginid", ""))

            quoted = []
            for instance in instances[:MAX_INSTANCES_QUOTED]:
                method = str(instance.get("method", "GET"))
                uri = str(instance.get("uri", ""))
                param = str(instance.get("param", "") or "")
                evidence_text = " ".join(str(instance.get("evidence", "") or "").split())[:160]
                line = f"{method} {uri}"
                if param:
                    line += f" (parameter: {param})"
                if evidence_text:
                    line += f"\n    evidence: {evidence_text}"
                quoted.append(line)

            count = alert.get("count", len(instances))
            evidence = f"{count} instance(s) reported by ZAP:\n  " + "\n  ".join(quoted)

            references = [
                str(r).strip()
                for r in str(alert.get("reference", "")).split("\n")
                if str(r).strip().startswith("http")
            ]

            findings.append(
                Finding(
                    tool=Tool.ZAP,
                    category=Category.SECURITY,
                    severity=_severity(alert),
                    title=truncate(alert.get("alert") or alert.get("name") or plugin_id, 160),
                    # ZAP alerts are site-wide, so the site is the location and
                    # the individual URLs live in the evidence.
                    location=site_name,
                    description=truncate(_strip_html(alert.get("desc", ""))),
                    evidence=evidence,
                    rule_id=f"zap:{plugin_id}" if plugin_id else str(alert.get("alertRef", "")),
                    references=references[:4],
                    metadata={
                        "solution": truncate(_strip_html(alert.get("solution", "")), 600),
                        "cwe_id": alert.get("cweid", ""),
                        "wasc_id": alert.get("wascid", ""),
                        "confidence": alert.get("confidence", ""),
                        "instance_count": count,
                        "risk": alert.get("riskdesc", ""),
                    },
                )
            )
    return findings
