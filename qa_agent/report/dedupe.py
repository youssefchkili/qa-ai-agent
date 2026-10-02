"""Turn a pile of raw findings into a report-ready list.

Three different kinds of duplication occur, and each needs its own treatment:

1. **The same tool reports the same thing twice.** Collapsed by fingerprint.
2. **Two tools report the same vulnerability.** Trivy says ``CVE-2021-23337``
   and OSV says ``GHSA-35jh-r3h4-6jhm`` for the identical package. These are
   merged through advisory aliases, and the merged finding records that both
   tools agreed, which is a strong confidence signal.
3. **One page-level rule fires on every page.** A contrast violation present
   on twenty pages is one defect, not twenty. It is reported once with the
   list of affected pages attached.
"""

from __future__ import annotations

from collections import defaultdict

from qa_agent.models.finding import Category, Finding, Severity, Tool, normalize_location

# Tools whose findings describe a rule observed on a page rather than a
# distinct defect per page.
PAGE_LEVEL_TOOLS = {Tool.AXE, Tool.LIGHTHOUSE}


def _worst(first: Severity, second: Severity) -> Severity:
    """Return the more severe of two severities."""
    return first if first.rank <= second.rank else second


def _absorb(primary: Finding, other: Finding) -> Finding:
    """Fold *other* into *primary*, keeping the strongest information."""
    primary.sources = list(dict.fromkeys([*primary.sources, *other.sources]))
    primary.severity = _worst(primary.severity, other.severity)
    if not primary.description:
        primary.description = other.description
    if not primary.evidence:
        primary.evidence = other.evidence
    primary.references = list(dict.fromkeys([*primary.references, *other.references]))[:8]
    return primary


def dedupe_exact(findings: list[Finding]) -> list[Finding]:
    """Collapse findings sharing a fingerprint, preserving first-seen order."""
    by_id: dict[str, Finding] = {}
    order: list[str] = []
    for finding in findings:
        existing = by_id.get(finding.id)
        if existing is None:
            by_id[finding.id] = finding
            order.append(finding.id)
        else:
            _absorb(existing, finding)
    return [by_id[key] for key in order]


def _alias_set(finding: Finding) -> set[str]:
    """Every advisory identifier this finding is known by, upper-cased."""
    ids: set[str] = set()
    if finding.rule_id:
        ids.add(finding.rule_id.upper())
    for alias in finding.metadata.get("aliases", []) or []:
        ids.add(str(alias).upper())
    if finding.metadata.get("vulnerability_id"):
        ids.add(str(finding.metadata["vulnerability_id"]).upper())
    return {item for item in ids if item}


def merge_dependency_findings(findings: list[Finding]) -> list[Finding]:
    """Merge Trivy and OSV reports of the same vulnerability in the same package."""
    dependencies = [f for f in findings if f.category == Category.DEPENDENCY]
    others = [f for f in findings if f.category != Category.DEPENDENCY]

    grouped: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for finding in dependencies:
        key = (
            str(finding.metadata.get("package", "")).lower(),
            str(finding.metadata.get("installed_version", "")),
        )
        grouped[key].append(finding)

    merged: list[Finding] = []
    for items in grouped.values():
        remaining = list(items)
        while remaining:
            primary = remaining.pop(0)
            aliases = _alias_set(primary)
            index = 0
            while index < len(remaining):
                if aliases & _alias_set(remaining[index]):
                    other = remaining.pop(index)
                    _absorb(primary, other)
                    aliases |= _alias_set(other)
                else:
                    index += 1
            if len(primary.sources) > 1:
                primary.metadata["confirmed_by"] = [t.value for t in primary.sources]
            primary.metadata["advisory_ids"] = sorted(aliases)
            merged.append(primary)

    return others + merged


def _is_secret(finding: Finding) -> bool:
    """A committed-credential finding, from either scanner."""
    if finding.tool == Tool.TRIVY and "secret_category" in finding.metadata:
        return True
    return finding.tool == Tool.SEMGREP and ".secrets." in finding.rule_id.lower()


def _code_position(finding: Finding) -> tuple[str, str] | None:
    """(last two path segments, line) for a ``path:line`` location.

    Only the tail of the path is compared: the same file is reported as
    ``frontend/src/app/x.spec.ts`` from the repository and as
    ``/juice-shop/frontend/src/app/x.spec.ts`` from the container image.
    """
    path, _, line = normalize_location(finding.location).rpartition(":")
    if not path or not line.isdigit():
        return None
    parts = [part for part in path.split("/") if part]
    return "/".join(parts[-2:]).lower(), line


def merge_colocated_secrets(findings: list[Finding]) -> list[Finding]:
    """One committed secret is one finding, however many scanners saw it.

    Observed on Juice Shop: a JWT in a unit-test file was reported by Semgrep,
    by Trivy's filesystem scan and again by Trivy's image scan. Three findings
    for one line inflate the count and deflate precision.
    """
    grouped: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    passthrough: list[Finding] = []
    for finding in findings:
        position = _code_position(finding) if _is_secret(finding) else None
        if position is None:
            passthrough.append(finding)
        else:
            grouped[position].append(finding)

    for items in grouped.values():
        primary = items[0]
        for other in items[1:]:
            _absorb(primary, other)
        if len(primary.sources) > 1:
            primary.metadata["confirmed_by"] = [t.value for t in primary.sources]
        passthrough.append(primary)
    return passthrough


def collapse_page_findings(findings: list[Finding]) -> list[Finding]:
    """Report a page-level rule once, listing every page it affected."""
    grouped: dict[tuple[Tool, str], list[Finding]] = defaultdict(list)
    passthrough: list[Finding] = []

    for finding in findings:
        if finding.tool in PAGE_LEVEL_TOOLS and finding.rule_id:
            grouped[(finding.tool, finding.rule_id)].append(finding)
        else:
            passthrough.append(finding)

    for items in grouped.values():
        primary = items[0]
        pages = list(
            dict.fromkeys(str(item.metadata.get("page") or item.location) for item in items)
        )
        for other in items[1:]:
            primary.severity = _worst(primary.severity, other.severity)
        if len(pages) > 1:
            # The location (and therefore the fingerprint) stays the first
            # page, so the identity of this finding is stable across runs.
            primary.metadata["affected_pages"] = pages
            primary.metadata["affected_page_count"] = len(pages)
        passthrough.append(primary)

    return passthrough


def deduplicate(findings: list[Finding], *, collapse_pages: bool = True) -> list[Finding]:
    """Full pipeline: exact, cross-tool and page-level, then sorted."""
    result = dedupe_exact(findings)
    result = merge_dependency_findings(result)
    result = merge_colocated_secrets(result)
    if collapse_pages:
        result = collapse_page_findings(result)
    return sorted(result, key=lambda finding: finding.sort_key)
