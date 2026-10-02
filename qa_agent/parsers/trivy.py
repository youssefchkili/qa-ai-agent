"""Translate Trivy JSON into unified findings.

Trivy emits three different kinds of result inside one document, and each maps
to a different category:

* ``Vulnerabilities``   a known CVE in a dependency        -> dependency
* ``Secrets``           a credential committed to the code -> security
* ``Misconfigurations`` an unsafe Dockerfile/Terraform     -> security

Verified against Trivy 0.74.0.
"""

from __future__ import annotations

from typing import Any

from qa_agent.models.finding import Category, Finding, Severity, Tool
from qa_agent.parsers.common import severity_from_name, truncate

_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


def _vulnerability_findings(target: str, items: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for item in items:
        vuln_id = str(item.get("VulnerabilityID", "")).strip()
        package = str(item.get("PkgName", "")).strip()
        installed = str(item.get("InstalledVersion", "")).strip()
        fixed = str(item.get("FixedVersion", "")).strip()

        findings.append(
            Finding(
                tool=Tool.TRIVY,
                category=Category.DEPENDENCY,
                severity=severity_from_name(item.get("Severity"), _SEVERITY, Severity.MEDIUM),
                title=f"{vuln_id} in {package} {installed}".strip(),
                location=f"{target}: {package}@{installed}",
                description=truncate(item.get("Title") or item.get("Description")),
                evidence=(
                    f"{package} {installed} is affected by {vuln_id}. "
                    + (f"Fixed in {fixed}." if fixed else "No fixed version is published yet.")
                ),
                rule_id=vuln_id,
                references=[str(item["PrimaryURL"])] if item.get("PrimaryURL") else [],
                metadata={
                    "package": package,
                    "installed_version": installed,
                    "fixed_version": fixed,
                    "vulnerability_id": vuln_id,
                    "manifest": target,
                },
            )
        )
    return findings


def _secret_findings(target: str, items: list[dict[str, Any]]) -> list[Finding]:
    """Secrets are reported by location and kind only.

    The secret value itself is deliberately never copied into the finding: the
    report is a document that gets shared, and re-publishing a live credential
    inside it would turn the QA report into the leak.
    """
    findings: list[Finding] = []
    for item in items:
        rule_id = str(item.get("RuleID", "")).strip()
        line = int(item.get("StartLine", 0) or 0)
        title = str(item.get("Title") or rule_id)
        findings.append(
            Finding(
                tool=Tool.TRIVY,
                category=Category.SECURITY,
                severity=severity_from_name(item.get("Severity"), _SEVERITY, Severity.HIGH),
                title=f"Hardcoded secret: {title}",
                location=f"{target}:{line}",
                description=truncate(
                    f"A {title} was found committed in the repository. "
                    f"Anything committed to version control must be treated as public: "
                    f"rotate this credential and load it from the environment instead."
                ),
                evidence=f"{title} ({item.get('Category', '')}) at {target}:{line}. "
                f"Value withheld from this report on purpose.",
                rule_id=rule_id,
                metadata={"secret_category": item.get("Category", ""), "line": line},
            )
        )
    return findings


def _misconfiguration_findings(target: str, items: list[dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for item in items:
        check_id = str(item.get("ID", "")).strip()
        cause = item.get("CauseMetadata") or {}
        line = int(cause.get("StartLine", 0) or 0)
        location = f"{target}:{line}" if line else target

        findings.append(
            Finding(
                tool=Tool.TRIVY,
                category=Category.SECURITY,
                severity=severity_from_name(item.get("Severity"), _SEVERITY, Severity.MEDIUM),
                title=f"{check_id}: {item.get('Title', '')}".strip(": "),
                location=location,
                description=truncate(item.get("Description") or item.get("Message")),
                evidence=truncate(item.get("Message"), 500),
                rule_id=check_id,
                references=[str(item["PrimaryURL"])] if item.get("PrimaryURL") else [],
                metadata={
                    "resolution": truncate(item.get("Resolution"), 300),
                    "misconfig_type": item.get("Type", ""),
                    "line": line,
                },
            )
        )
    return findings


def parse_trivy(payload: dict[str, Any] | None) -> list[Finding]:
    """Convert a parsed ``trivy --format json`` document into findings."""
    if not payload:
        return []

    findings: list[Finding] = []
    for result in payload.get("Results", []) or []:
        target = str(result.get("Target", "")).replace("\\", "/")
        findings.extend(_vulnerability_findings(target, result.get("Vulnerabilities") or []))
        findings.extend(_secret_findings(target, result.get("Secrets") or []))
        findings.extend(_misconfiguration_findings(target, result.get("Misconfigurations") or []))
    return findings
