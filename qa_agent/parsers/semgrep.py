"""Translate Semgrep JSON into unified findings.

Verified against Semgrep 1.177.0 running offline with local rule packs.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from qa_agent.models.finding import Category, Finding, Severity, Tool
from qa_agent.parsers.common import read_snippet, relative_location, truncate

# Semgrep's own scale. It has no "critical": ERROR is its most severe level.
_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}


def canonical_check_id(check_id: str, rules_dir: Path | None, metadata: dict[str, Any]) -> str:
    """Strip the local rules path that Semgrep prepends to every rule id.

    Running with ``--config <directory>`` produces ids such as::

        C.Users.youss..qa-agent.rules.semgrep.javascript.browser.security.eval-detected

    The machine-specific prefix would make the same rule fingerprint
    differently on every machine, so it has to go. The rule's registry URL is
    the most reliable source of the canonical id; deriving the prefix from the
    rules directory is the fallback.
    """
    source = str(metadata.get("source") or "")
    if "/r/" in source:
        candidate = source.rsplit("/r/", 1)[1].strip()
        if candidate:
            return candidate

    if rules_dir is not None:
        # Semgrep turns path separators and the drive colon into dots.
        prefix = re.sub(r"[:\\/]+", ".", str(rules_dir)).strip(".")
        if prefix and check_id.startswith(prefix + "."):
            return check_id[len(prefix) + 1 :]

    return check_id


def _category(metadata: dict[str, Any]) -> Category:
    """Security rules become security findings; everything else is code."""
    if str(metadata.get("category", "")).lower() == "security":
        return Category.SECURITY
    return Category.CODE


def parse_semgrep(
    payload: dict[str, Any] | None,
    *,
    repo_root: Path | None = None,
    rules_dir: Path | None = None,
) -> list[Finding]:
    """Convert a parsed ``semgrep --json`` document into findings."""
    if not payload:
        return []

    findings: list[Finding] = []
    for item in payload.get("results", []) or []:
        extra = item.get("extra", {}) or {}
        metadata = extra.get("metadata", {}) or {}

        absolute = Path(item.get("path", ""))
        relative = relative_location(item.get("path", ""), repo_root)
        start_line = int((item.get("start") or {}).get("line", 0) or 0)
        end_line = int((item.get("end") or {}).get("line", start_line) or start_line)

        rule_id = canonical_check_id(item.get("check_id", ""), rules_dir, metadata)

        # extra.lines is the literal string "requires login" on the free tier,
        # so the real evidence is read from the file on disk.
        reported = str(extra.get("lines") or "")
        evidence = "" if reported.strip().lower() == "requires login" else reported.strip()
        if not evidence:
            evidence = read_snippet(absolute, start_line, end_line)

        references = [str(r) for r in (metadata.get("references") or [])]
        if metadata.get("source"):
            references.append(str(metadata["source"]))

        findings.append(
            Finding(
                tool=Tool.SEMGREP,
                category=_category(metadata),
                severity=_SEVERITY.get(str(extra.get("severity", "")).upper(), Severity.MEDIUM),
                title=rule_id.split(".")[-1].replace("-", " ").replace("_", " ").strip()
                or rule_id,
                location=f"{relative}:{start_line}" if relative else rule_id,
                description=truncate(extra.get("message")),
                evidence=evidence,
                rule_id=rule_id,
                references=references[:6],
                metadata={
                    "cwe": metadata.get("cwe") or [],
                    "owasp": metadata.get("owasp") or [],
                    "confidence": metadata.get("confidence", ""),
                    "impact": metadata.get("impact", ""),
                    "likelihood": metadata.get("likelihood", ""),
                    "technology": metadata.get("technology") or [],
                    "file": relative,
                    "line": start_line,
                },
            )
        )
    return findings
