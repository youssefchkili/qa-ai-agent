"""Translate OSV-Scanner JSON into unified findings.

OSV groups several advisory ids that describe the same underlying flaw (a CVE
and its GitHub GHSA alias, for example). One group is one finding; reporting
each alias separately would inflate the numbers for no benefit.

Verified against OSV-Scanner 2.6.0.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from qa_agent.models.finding import Category, Finding, Severity, Tool
from qa_agent.parsers.common import relative_location, truncate

# GitHub advisory wording, used when no numeric CVSS score is available.
_NAMED_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def severity_from_cvss(score: str | float | None) -> Severity | None:
    """Map a CVSS base score onto the unified scale using the standard bands."""
    if score is None or score == "":
        return None
    try:
        value = float(score)
    except (TypeError, ValueError):
        return None
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    if value > 0:
        return Severity.LOW
    return Severity.INFO


def _group_severity(group: dict[str, Any], vulns: list[dict[str, Any]]) -> Severity:
    """Prefer the group's numeric CVSS, then the advisory's own wording."""
    from_score = severity_from_cvss(group.get("max_severity"))
    if from_score is not None:
        return from_score
    for vuln in vulns:
        named = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
        if named in _NAMED_SEVERITY:
            return _NAMED_SEVERITY[named]
    # A real advisory with no score is still a real advisory: do not bury it.
    return Severity.MEDIUM


def _canonical_id(ids: list[str], vulns: list[dict[str, Any]]) -> str:
    """Prefer a CVE id so findings can be matched against Trivy's output."""
    aliases: set[str] = set(ids)
    for vuln in vulns:
        aliases.update(str(a) for a in (vuln.get("aliases") or []))
    for alias in sorted(aliases):
        if alias.upper().startswith("CVE-"):
            return alias
    return ids[0] if ids else ""


def parse_osv(payload: dict[str, Any] | None, *, repo_root: Path | None = None) -> list[Finding]:
    """Convert a parsed ``osv-scanner --format json`` document into findings."""
    if not payload:
        return []

    findings: list[Finding] = []
    for result in payload.get("results", []) or []:
        source = relative_location(str((result.get("source") or {}).get("path", "")), repo_root)

        for package_entry in result.get("packages", []) or []:
            package = package_entry.get("package", {}) or {}
            name = str(package.get("name", ""))
            version = str(package.get("version", ""))
            ecosystem = str(package.get("ecosystem", ""))
            by_id = {str(v.get("id")): v for v in (package_entry.get("vulnerabilities") or [])}

            groups = package_entry.get("groups") or []
            if not groups:
                # No grouping information: fall back to one finding per advisory.
                groups = [{"ids": [vid]} for vid in by_id]

            for group in groups:
                ids = [str(i) for i in (group.get("ids") or [])]
                vulns = [by_id[i] for i in ids if i in by_id]
                primary = vulns[0] if vulns else {}
                canonical = _canonical_id(ids, vulns)

                aliases = sorted({a for v in vulns for a in (v.get("aliases") or [])} | set(ids))
                findings.append(
                    Finding(
                        tool=Tool.OSV,
                        category=Category.DEPENDENCY,
                        severity=_group_severity(group, vulns),
                        title=f"{canonical} in {name} {version}".strip(),
                        location=f"{source}: {name}@{version}" if source else f"{name}@{version}",
                        description=truncate(
                            primary.get("summary") or primary.get("details") or canonical
                        ),
                        evidence=f"{ecosystem} package {name}@{version} matches {', '.join(ids)}.",
                        rule_id=canonical,
                        references=[f"https://osv.dev/vulnerability/{i}" for i in ids[:3]],
                        metadata={
                            "package": name,
                            "installed_version": version,
                            "ecosystem": ecosystem,
                            "aliases": aliases,
                            "vulnerability_id": canonical,
                            "manifest": source,
                        },
                    )
                )
    return findings
