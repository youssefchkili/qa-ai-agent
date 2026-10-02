"""Command line interface.

Three commands:

``check_env``
    verify that every external dependency is installed and usable.
``seed``
    download rule packs and vulnerability databases once, while online.
``run``
    scan a repository and/or a running application, fully offline.
"""

from __future__ import annotations

import json

import typer
from rich.console import Console
from rich.table import Table

from qa_agent import __version__
from qa_agent.config import get_settings
from qa_agent.env.checks import CheckResult, run_all_checks
from qa_agent.logging_setup import setup_logging
from qa_agent.pipeline import run_pipeline
from qa_agent.seed import seed_all

# Stages that --skip accepts, so a typo is rejected instead of silently
# disabling nothing.
SKIPPABLE = (
    "semgrep",
    "trivy",
    "osv",
    "crawler",
    "axe",
    "lighthouse",
    "zap",
    "image",
    "testgen",
    "verify",
    "triage",
)

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Local on-premise AI QA testing agent.",
)
console = Console()

_STATUS_STYLE = {"ok": "bold green", "missing": "bold red", "degraded": "bold yellow"}


@app.callback()
def main() -> None:
    """Local on-premise AI QA testing agent."""


@app.command("check_env")
def check_env(
    deep: bool = typer.Option(
        False, "--deep", help="Also send a real prompt to the local model (slower)."
    ),
    as_json: bool = typer.Option(False, "--json", help="Emit machine-readable JSON instead."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Verify that every required tool is installed and that Ollama answers."""
    setup_logging(verbose=verbose)
    settings = get_settings()
    results = run_all_checks(settings, deep=deep)

    blocking = [r for r in results if r.required and not r.passed]

    if as_json:
        console.print_json(
            json.dumps({"ok": not blocking, "checks": [r.to_dict() for r in results]})
        )
        raise typer.Exit(code=1 if blocking else 0)

    _render_table(results)
    _render_summary(results, blocking)
    raise typer.Exit(code=1 if blocking else 0)


def _render_table(results: list[CheckResult]) -> None:
    """Print one row per check, grouped by pipeline stage."""
    table = Table(title=f"qa-agent {__version__} environment check", header_style="bold")
    table.add_column("Stage", style="dim", no_wrap=True)
    table.add_column("Check", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail", overflow="fold")

    previous_group = None
    for result in results:
        group = result.group if result.group != previous_group else ""
        previous_group = result.group
        label = result.status.upper()
        if not result.required and result.status != "ok":
            label += " (optional)"
        detail = result.detail
        if result.hint and not result.passed:
            detail = f"{detail}\n-> fix: {result.hint}"
        table.add_row(group, result.name, f"[{_STATUS_STYLE[result.status]}]{label}[/]", detail)

    console.print(table)


def _render_summary(results: list[CheckResult], blocking: list[CheckResult]) -> None:
    """Print the pass/fail verdict and what to do next."""
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    if not blocking:
        console.print(f"\n[bold green]PASS[/] {passed}/{total} checks ok. Environment is ready.")
        return
    names = ", ".join(r.name for r in blocking)
    console.print(
        f"\n[bold red]FAIL[/] {passed}/{total} checks ok. "
        f"Blocking: {names}.\nApply the 'fix:' lines above, then re-run this command."
    )


@app.command("seed")
def seed(
    force: bool = typer.Option(False, "--force", help="Re-download even if already present."),
    component: list[str] = typer.Option(
        [], "--component", help="Only this component (repeatable): semgrep, trivy, osv, "
        "lighthouse, zap."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Download rule packs and vulnerability databases for offline scanning.

    This is the only command that uses the public internet. Run it once on a
    connected machine; ``run`` then works fully offline. For an air-gapped
    deployment, run it elsewhere and copy the data directory across.
    """
    setup_logging(verbose=verbose)
    settings = get_settings()
    console.print(f"Provisioning offline data into [bold]{settings.data_dir}[/]\n")

    try:
        steps = seed_all(settings, force=force, components=tuple(component))
    except ValueError as exc:
        console.print(f"[bold red]{exc}[/]")
        raise typer.Exit(code=2) from exc

    table = Table(header_style="bold")
    table.add_column("Component", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Detail", overflow="fold")
    for step in steps:
        style = "bold green" if step.ok else "bold red"
        label = "OK" if step.ok else "FAILED"
        table.add_row(step.name, f"[{style}]{label}[/]", step.detail)
    console.print(table)

    failed = [step for step in steps if not step.ok]
    if failed:
        console.print(f"\n[bold red]{len(failed)} component(s) failed.[/] Scans may be degraded.")
        raise typer.Exit(code=1)
    console.print("\n[bold green]Ready.[/] Scans can now run offline.")


@app.command("run")
def run(
    url: str = typer.Option(
        "", "--url", help="Git repository URL, local path, or a live application URL."
    ),
    app_url: str = typer.Option(
        "", "--app-url", help="URL of an already-running instance to test dynamically."
    ),
    image: str = typer.Option(
        "", "--image", help="Container image to scan for vulnerable installed packages."
    ),
    max_pages: int = typer.Option(0, "--max-pages", help="Override the crawl page limit."),
    no_launch: bool = typer.Option(
        False, "--no-launch", help="Never start the app from its Dockerfile or compose file."
    ),
    skip: list[str] = typer.Option(
        [], "--skip", help=f"Stage to skip (repeatable). One of: {', '.join(SKIPPABLE)}."
    ),
    run_id: str = typer.Option("", "--run-id", help="Use a fixed run id instead of a new one."),
    no_llm: bool = typer.Option(
        False, "--no-llm", help="Run the deterministic pipeline only (no local model)."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Scan a repository and/or a running application and write a QA report."""
    if not url and not app_url and not image:
        console.print("[bold red]Nothing to scan.[/] Pass --url, --app-url or --image.")
        raise typer.Exit(code=2)

    unknown = sorted(set(skip) - set(SKIPPABLE))
    if unknown:
        console.print(
            f"[bold red]Unknown --skip value(s): {', '.join(unknown)}.[/] "
            f"Valid values: {', '.join(SKIPPABLE)}."
        )
        raise typer.Exit(code=2)

    setup_logging(verbose=verbose)
    settings = get_settings()
    if max_pages > 0:
        settings = settings.model_copy(update={"max_pages": max_pages})

    result = run_pipeline(
        settings=settings,
        url=url,
        app_url=app_url,
        image=image,
        run_id=run_id or None,
        launch=not no_launch,
        skip=frozenset(skip),
        verbose=verbose,
        use_llm=not no_llm,
    )

    _render_run_summary(result)


@app.command("evaluate")
def evaluate(
    runs: int = typer.Option(3, "--runs", min=1, help="Repeat the full scan this many times."),
    no_llm: bool = typer.Option(False, "--no-llm", help="Evaluate the deterministic pipeline only."),
    skip: list[str] = typer.Option([], "--skip", help="Stage to skip (repeatable)."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    """Score the agent against the private evaluation app: precision, recall, consistency."""
    from qa_agent.evaluation.harness import DEFAULT_ANSWER_SHEET, run_evaluation

    if not DEFAULT_ANSWER_SHEET.is_file():
        console.print(f"[bold red]No answer sheet at {DEFAULT_ANSWER_SHEET}.[/]")
        raise typer.Exit(code=2)
    unknown = sorted(set(skip) - set(SKIPPABLE))
    if unknown:
        console.print(f"[bold red]Unknown --skip value(s): {', '.join(unknown)}.[/]")
        raise typer.Exit(code=2)

    setup_logging(verbose=verbose)
    report, path = run_evaluation(
        get_settings(), runs=runs, use_llm=not no_llm, skip=frozenset(skip)
    )

    table = Table(title="evaluation against the private app", header_style="bold")
    for column in ("Run", "Findings", "Matched", "Precision", "Reviewed", "Recall"):
        table.add_column(column, justify="right" if column != "Run" else "left")
    for score in report.runs:
        table.add_row(
            score.run_id,
            str(score.total_findings),
            str(score.matched_findings),
            f"{score.precision:.1%}",
            f"{score.reviewed_precision:.1%}",
            f"{score.recall:.1%}",
        )
    console.print(table)
    console.print(
        f"\n[bold]Mean precision[/] {report.mean_precision:.1%} strict, "
        f"{report.mean_reviewed_precision:.1%} after manual review   "
        f"[bold]Mean recall[/] {report.mean_recall:.1%}   "
        f"[bold]Run-to-run consistency[/] {report.finding_consistency:.1%} "
        f"(over {len(report.runs)} run(s))"
    )
    console.print(
        "Recall by category: "
        + ", ".join(f"{k} {v:.0%}" for k, v in report.recall_by_category.items())
    )
    if report.never_detected:
        console.print("Never detected: " + ", ".join(report.never_detected))
    console.print(f"\nFull results: {path}")


def _render_run_summary(result) -> None:
    """Print what the run found and where the artefacts are."""
    summary = result.summary
    counts = summary.counts_by_severity(result.findings)

    table = Table(title=f"run {summary.run_id}", header_style="bold")
    table.add_column("Tool", no_wrap=True)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Findings", justify="right", no_wrap=True)
    table.add_column("Detail", overflow="fold")
    for tool in summary.tool_runs:
        style = "bold green" if tool.verdict.value == "ok" else "bold yellow"
        table.add_row(
            tool.tool,
            f"[{style}]{tool.verdict.value}[/]",
            str(tool.findings_count),
            tool.detail,
        )
    console.print(table)

    severity_line = "  ".join(
        f"[bold]{name}[/] {count}" for name, count in counts.items() if count
    )
    console.print(
        f"\n[bold]{len(result.findings)} finding(s)[/] after deduplication"
        + (f"\n{severity_line}" if severity_line else "")
    )
    console.print(f"\nReport:    {result.report_html}")
    console.print(f"Markdown:  {result.report_md}")
    console.print(f"Findings:  {result.workspace.findings_path}")
    console.print(f"Raw output:{result.workspace.raw_dir}")


if __name__ == "__main__":
    app()
