"""Run the full agent against the private evaluation app and score it.

The harness starts the planted-defect app itself, bound to 127.0.0.1 only and
never with Flask's debugger, runs the complete agent (static and dynamic, with
or without the model) N times, and scores every run against the answer sheet.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from qa_agent.config import PROJECT_ROOT, Settings
from qa_agent.evaluation.answer_sheet import load_answer_sheet, load_known_real_issues
from qa_agent.evaluation.metrics import EvaluationReport, score_run, summarise
from qa_agent.input.launcher import wait_for_http
from qa_agent.logging_setup import get_logger
from qa_agent.pipeline import run_pipeline

log = get_logger(__name__)

EVAL_DIR = PROJECT_ROOT / "eval"
DEFAULT_APP_DIR = EVAL_DIR / "target_app"
DEFAULT_ANSWER_SHEET = EVAL_DIR / "answer_sheet.json"
DEFAULT_RESULTS_DIR = EVAL_DIR / "results"
DEFAULT_PORT = 5055
APP_START_TIMEOUT_S = 60


@contextmanager
def target_app(app_dir: Path, port: int) -> Iterator[str]:
    """Run the evaluation app for the duration of the block; yield its URL."""
    env = dict(os.environ)
    # No __pycache__ inside the scanned tree: it would change between runs.
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    argv = [
        sys.executable, "-m", "flask", "--app", "app", "run",
        "--host", "127.0.0.1", "--port", str(port),
    ]
    process = subprocess.Popen(
        argv,
        cwd=str(app_dir),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = f"http://127.0.0.1:{port}"
    try:
        if not wait_for_http(url, APP_START_TIMEOUT_S):
            raise RuntimeError(f"the evaluation app did not start on {url}")
        yield url
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()


def run_evaluation(
    settings: Settings,
    *,
    runs: int = 3,
    app_dir: Path = DEFAULT_APP_DIR,
    answer_sheet: Path = DEFAULT_ANSWER_SHEET,
    results_dir: Path = DEFAULT_RESULTS_DIR,
    port: int = DEFAULT_PORT,
    use_llm: bool = True,
    skip: frozenset[str] = frozenset(),
) -> tuple[EvaluationReport, Path]:
    """Evaluate the agent *runs* times; return the report and where it was saved."""
    bugs = load_answer_sheet(answer_sheet)
    known_real = load_known_real_issues(answer_sheet)
    scores = []
    id_sets: list[set[str]] = []

    with target_app(app_dir, port) as url:
        for number in range(1, runs + 1):
            log.info("evaluation run %d of %d", number, runs)
            result = run_pipeline(
                settings=settings,
                url=str(app_dir),
                app_url=url,
                launch=False,
                skip=skip,
                use_llm=use_llm,
            )
            scores.append(
                score_run(result.workspace.run_id, result.findings, bugs, known_real)
            )
            id_sets.append({f.id for f in result.findings if f.verified})

    report = summarise(scores, id_sets, bugs)

    results_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC)
    path = results_dir / f"{stamp.strftime('%Y%m%d-%H%M%S')}.json"
    payload = {
        "created_at": stamp.isoformat(timespec="seconds"),
        "model": settings.llm_model if use_llm else None,
        "skipped_stages": sorted(skip),
        **report.to_dict(),
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return report, path
