"""Logging configuration: pretty console output plus a full log file per run.

Auditability is a project requirement, so anything written to the console is
also persisted verbatim to ``workspace/<run_id>/logs/run.log``.
"""

from __future__ import annotations

import logging
from pathlib import Path

from rich.logging import RichHandler

_CONFIGURED = False


def setup_logging(verbose: bool = False, log_file: Path | None = None) -> None:
    """Install the console handler and, when given, a per-run file handler.

    Safe to call more than once; handlers are not duplicated.
    """
    global _CONFIGURED

    root = logging.getLogger()
    level = logging.DEBUG if verbose else logging.INFO

    if not _CONFIGURED:
        root.setLevel(logging.DEBUG)
        console = RichHandler(rich_tracebacks=True, show_path=False, markup=False)
        console.setLevel(level)
        console.setFormatter(logging.Formatter("%(message)s", datefmt="%H:%M:%S"))
        root.addHandler(console)
        # Third-party libraries are chatty at DEBUG; keep them at WARNING.
        # The OpenAI SDK ships its own copies as httpx2/httpcore2; without them
        # listed, every model call writes a dozen DEBUG lines into run.log.
        noisy_loggers = ("httpx", "httpx2", "httpcore", "httpcore2", "openai", "urllib3", "git")
        for noisy in noisy_loggers:
            logging.getLogger(noisy).setLevel(logging.WARNING)
        _CONFIGURED = True

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        already = any(
            isinstance(h, logging.FileHandler)
            and Path(getattr(h, "baseFilename", "")) == log_file.resolve()
            for h in root.handlers
        )
        if not already:
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(
                logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
            )
            root.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Return a module-scoped logger."""
    return logging.getLogger(name)
