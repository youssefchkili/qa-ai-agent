"""Run one compiled flow in a separate, time-limited process.

The isolation here is deliberately modest and stated honestly: a separate
process, a hard timeout, a working directory inside the run's workspace, and an
environment stripped down to what a browser needs (so API keys or tokens in the
parent's environment are not visible to the test). Because the script is
compiled by the agent from a validated plan rather than written by the model,
this is enough; running model-written code would need a container.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path

from qa_agent.testgen.compiler import MARKER
from qa_agent.tools.process import run_command

# The only variables passed to a test process. Everything else, including any
# credentials in the parent environment, is withheld.
SAFE_ENV_KEYS = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "LOCALAPPDATA",
    "APPDATA",
    "PLAYWRIGHT_BROWSERS_PATH",
)


@dataclass(frozen=True)
class FlowRun:
    """The outcome of executing one compiled flow once."""

    status: str  # "pass", "fail" (assertion) or "error" (could not execute)
    step: int | None = None
    action: str | None = None
    message: str = ""
    screenshot: str = ""
    duration_s: float = 0.0
    # Messages visible on the page when a step failed.
    observed: tuple[str, ...] = ()


def sandbox_env() -> dict[str, str]:
    """A minimal environment for the test process."""
    env = {key: os.environ[key] for key in SAFE_ENV_KEYS if key in os.environ}
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def parse_result(stdout: str) -> dict | None:
    """The last ``QA_RESULT`` line the script printed, decoded."""
    for line in reversed(stdout.splitlines()):
        if line.startswith(MARKER):
            try:
                return json.loads(line[len(MARKER) :])
            except json.JSONDecodeError:
                return None
    return None


def run_flow_script(script: Path, *, timeout_s: float, log_path: Path | None = None) -> FlowRun:
    """Execute *script* with this interpreter and interpret its result line."""
    result = run_command(
        [sys.executable, str(script)],
        cwd=script.parent,
        timeout=timeout_s,
        env=sandbox_env(),
        log_path=log_path,
    )
    if result.timed_out:
        return FlowRun(
            status="error",
            message=f"the test did not finish within {timeout_s:.0f}s",
            duration_s=result.duration_s,
        )

    payload = parse_result(result.stdout)
    if payload is None:
        tail = (result.stderr or result.stdout).strip()[-400:]
        return FlowRun(
            status="error",
            message=f"the test produced no result (exit {result.returncode}): {tail}",
            duration_s=result.duration_s,
        )

    status = str(payload.get("status", "error"))
    return FlowRun(
        status=status if status in ("pass", "fail", "error") else "error",
        step=payload.get("step"),
        action=payload.get("action"),
        message=str(payload.get("message", "")),
        screenshot=str(payload.get("screenshot", "")),
        duration_s=result.duration_s,
        observed=tuple(str(text) for text in (payload.get("observed") or [])[:5]),
    )
