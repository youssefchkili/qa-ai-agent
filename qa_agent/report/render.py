"""Render findings into Markdown and HTML with Jinja2."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from qa_agent.logging_setup import get_logger
from qa_agent.models.finding import Category, Finding
from qa_agent.models.run import RunSummary
from qa_agent.workspace import RunWorkspace

log = get_logger(__name__)

TEMPLATE_DIR = Path(__file__).parent / "templates"

# Report order: the categories a reader acts on first come first.
CATEGORY_ORDER = [
    Category.SECURITY,
    Category.DEPENDENCY,
    Category.FUNCTIONAL,
    Category.CODE,
    Category.ACCESSIBILITY,
    Category.PERFORMANCE,
]

CATEGORY_TITLES = {
    Category.SECURITY: "Security",
    Category.DEPENDENCY: "Vulnerable dependencies",
    Category.FUNCTIONAL: "Broken functionality",
    Category.CODE: "Code quality",
    Category.ACCESSIBILITY: "Accessibility",
    Category.PERFORMANCE: "Performance",
}


def _autoescape(template_name: str | None) -> bool:
    """Escape HTML templates, leave Markdown alone.

    Written explicitly rather than with ``select_autoescape``: the templates
    are named ``report.html.j2``, whose extension is ``.j2``, so an
    extension-based rule silently leaves escaping *off* - which would let a
    scanned application inject script into the report through a crafted page
    title or error message.
    """
    return bool(template_name) and template_name.endswith((".html", ".html.j2", ".xml"))


def _environment() -> Environment:
    """Jinja2 environment used for both report formats."""
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=_autoescape,
        trim_blocks=True,
        lstrip_blocks=True,
    )


def group_by_category(findings: list[Finding]) -> list[dict[str, Any]]:
    """Group findings into the report's section order, skipping empty sections."""
    groups: list[dict[str, Any]] = []
    for category in CATEGORY_ORDER:
        items = [f for f in findings if f.category == category]
        if not items:
            continue
        groups.append(
            {
                "key": category.value,
                "title": CATEGORY_TITLES[category],
                "findings": items,
                "count": len(items),
            }
        )
    return groups


def build_context(findings: list[Finding], summary: RunSummary) -> dict[str, Any]:
    """Assemble everything both templates need."""
    context = summary.to_report_context(findings)
    context["groups"] = group_by_category(findings)
    context["findings"] = findings
    context["has_findings"] = bool(findings)
    # Distinguishing "clean" from "never ran" is the whole point of verdicts.
    context["tools_that_ran"] = [t for t in context["tool_runs"] if t["verdict"] == "ok"]
    context["tools_that_did_not_run"] = [t for t in context["tool_runs"] if t["verdict"] != "ok"]
    return context


def render_reports(
    findings: list[Finding],
    summary: RunSummary,
    workspace: RunWorkspace,
) -> tuple[Path, Path]:
    """Write ``findings.json``, ``report.md`` and ``report.html``.

    The JSON is written too: it is the machine-readable artefact that phase 2
    annotates and phase 3 scores against the answer sheet.
    """
    context = build_context(findings, summary)
    environment = _environment()

    workspace.findings_path.write_text(
        json.dumps([f.model_dump(mode="json") for f in findings], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    markdown = environment.get_template("report.md.j2").render(**context)
    workspace.report_md_path.write_text(markdown, encoding="utf-8")

    html = environment.get_template("report.html.j2").render(**context)
    workspace.report_html_path.write_text(html, encoding="utf-8")

    log.info("report written to %s", workspace.report_html_path)
    return workspace.report_md_path, workspace.report_html_path
