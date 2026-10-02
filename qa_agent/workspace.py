"""Per-run workspace layout.

Every run of the agent owns one directory under ``workspace/``. Everything the
run produces - the clone, raw tool output, screenshots, logs and the rendered
report - stays inside it, so a run is self-contained, inspectable and
reproducible, and no scan data ever leaves the machine.

Layout::

    workspace/<run_id>/
        repo/            cloned repository under test
        raw/             raw tool output, one JSON file per tool
        pages/           per-page screenshots and page models
        tests/           LLM-generated Playwright tests (phase 2)
        logs/            run.log, commands.jsonl, llm.jsonl
        findings.json    unified findings
        report.md
        report.html
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

# e.g. 20260917-100411-a3f9c1
RUN_ID_TIME_FORMAT = "%Y%m%d-%H%M%S"

_SUBDIRS = ("repo", "raw", "pages", "tests", "logs")


def new_run_id() -> str:
    """Return a sortable, collision-resistant identifier for a run."""
    stamp = datetime.now().strftime(RUN_ID_TIME_FORMAT)
    return f"{stamp}-{secrets.token_hex(3)}"


@dataclass(frozen=True)
class RunWorkspace:
    """Filesystem paths for a single run."""

    root: Path
    run_id: str

    @classmethod
    def create(cls, base_dir: Path, run_id: str | None = None) -> RunWorkspace:
        """Create the directory tree for a new run and return it."""
        run_id = run_id or new_run_id()
        root = Path(base_dir).expanduser().resolve() / run_id
        for sub in _SUBDIRS:
            (root / sub).mkdir(parents=True, exist_ok=True)
        return cls(root=root, run_id=run_id)

    # --- directories -------------------------------------------------------
    @property
    def repo_dir(self) -> Path:
        return self.root / "repo"

    @property
    def raw_dir(self) -> Path:
        return self.root / "raw"

    @property
    def pages_dir(self) -> Path:
        return self.root / "pages"

    @property
    def tests_dir(self) -> Path:
        return self.root / "tests"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    # --- well-known files --------------------------------------------------
    @property
    def run_log(self) -> Path:
        return self.logs_dir / "run.log"

    @property
    def command_log(self) -> Path:
        """JSON-lines audit trail of every subprocess the run invoked."""
        return self.logs_dir / "commands.jsonl"

    @property
    def llm_log(self) -> Path:
        """JSON-lines audit trail of every prompt sent to the local model."""
        return self.logs_dir / "llm.jsonl"

    @property
    def findings_path(self) -> Path:
        return self.root / "findings.json"

    @property
    def report_md_path(self) -> Path:
        return self.root / "report.md"

    @property
    def report_html_path(self) -> Path:
        return self.root / "report.html"

    # --- helpers -----------------------------------------------------------
    def raw_path(self, tool: str) -> Path:
        """Path of the raw output file for *tool*, e.g. ``raw/semgrep.json``."""
        return self.raw_dir / f"{tool}.json"

    def save_json(self, path: Path, data: Any) -> Path:
        """Write *data* as indented UTF-8 JSON, creating parent directories."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return path
