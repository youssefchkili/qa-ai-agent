"""The answer sheet: the planted defects, and how a correct detection looks.

Matching is deliberately simple and declarative, so a reader can check by eye
why a finding was or was not counted, and so the matchers can be written
before seeing any results rather than tuned afterwards.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from qa_agent.models.finding import Finding, normalize_location


@dataclass(frozen=True)
class Matcher:
    """How to recognise a correct detection of one planted defect."""

    categories: tuple[str, ...]
    keywords: tuple[str, ...]
    location_any: tuple[str, ...] = ()
    evidence_keywords: tuple[str, ...] = ()


@dataclass(frozen=True)
class Bug:
    """One planted defect."""

    id: str
    title: str
    category: str
    matcher: Matcher


def _lower_tuple(values: Any) -> tuple[str, ...]:
    return tuple(str(v).lower() for v in (values or []))


def load_answer_sheet(path: Path) -> list[Bug]:
    """Read and validate the planted defects."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return _parse_entries(data.get("bugs", []), path)


def load_known_real_issues(path: Path) -> list[Bug]:
    """Real problems the agent found that were not planted (manual review)."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return _parse_entries(data.get("known_real_issues", []), path)


def _parse_entries(entries: list[dict[str, Any]], path: Path) -> list[Bug]:
    bugs: list[Bug] = []
    seen: set[str] = set()
    for entry in entries:
        bug_id = str(entry["id"])
        if bug_id in seen:
            raise ValueError(f"duplicate bug id {bug_id} in {path}")
        seen.add(bug_id)
        match = entry.get("match", {})
        if not match.get("categories") or not match.get("keywords"):
            raise ValueError(f"bug {bug_id} needs match.categories and match.keywords")
        bugs.append(
            Bug(
                id=bug_id,
                title=str(entry.get("title", bug_id)),
                category=str(entry.get("category", "")),
                matcher=Matcher(
                    categories=_lower_tuple(match["categories"]),
                    keywords=_lower_tuple(match["keywords"]),
                    location_any=_lower_tuple(match.get("location_any")),
                    evidence_keywords=_lower_tuple(match.get("evidence_keywords")),
                ),
            )
        )
    return bugs


def finding_matches(finding: Finding, bug: Bug) -> bool:
    """Whether *finding* is a correct detection of *bug*."""
    matcher = bug.matcher
    if finding.category.value not in matcher.categories:
        return False

    if matcher.location_any:
        where = " ".join(
            [
                normalize_location(finding.location),
                str(finding.metadata.get("page", "")),
                " ".join(str(p) for p in finding.metadata.get("affected_pages", []) or []),
            ]
        ).lower()
        if not any(fragment in where for fragment in matcher.location_any):
            return False

    identity = f"{finding.rule_id} {finding.title}".lower()
    if not any(keyword in identity for keyword in matcher.keywords):
        return False

    if matcher.evidence_keywords:
        evidence = f"{finding.evidence} {finding.description}".lower()
        if not any(keyword in evidence for keyword in matcher.evidence_keywords):
            return False

    return True


def matched_bugs(finding: Finding, bugs: list[Bug]) -> list[str]:
    """Ids of every planted bug this finding correctly detects."""
    return [bug.id for bug in bugs if finding_matches(finding, bug)]
