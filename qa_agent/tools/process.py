"""Safe subprocess execution with timeouts and an audit trail.

Every external tool the agent runs goes through :func:`run_command`, which
never uses a shell, always bounds execution with a timeout, and can append a
JSON-lines record of the invocation to the run's command log.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from qa_agent.logging_setup import get_logger

log = get_logger(__name__)


class CommandTimeout(RuntimeError):
    """Raised by :func:`run_command` when ``check=True`` and the tool timed out."""


class CommandFailed(RuntimeError):
    """Raised by :func:`run_command` when ``check=True`` and the tool exited non-zero."""


@dataclass(frozen=True)
class CommandResult:
    """Outcome of a single subprocess invocation."""

    argv: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def resolve_executable(name: str, extra_dirs: Sequence[Path] = ()) -> str | None:
    """Locate *name* on PATH, falling back to *extra_dirs* (e.g. ``vendor/bin``).

    ``shutil.which`` applies PATHEXT on Windows, so a bare name such as
    ``"trivy"`` resolves to ``trivy.exe`` without special-casing the platform.

    The directory holding the running interpreter is always searched as well.
    Console scripts installed into a virtual environment (semgrep is one) live
    in that directory, and it is only on PATH while the environment is
    activated - but the agent is routinely launched as
    ``.venv\\Scripts\\python.exe -m qa_agent`` without activation.
    """
    search_dirs = [*extra_dirs, Path(sys.executable).parent]

    found = shutil.which(name)
    if found:
        return found
    for directory in search_dirs:
        directory = Path(directory)
        if not directory.is_dir():
            continue
        found = shutil.which(name, path=str(directory))
        if found:
            return found
    return None


def run_command(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float = 300.0,
    env: Mapping[str, str] | None = None,
    log_path: Path | None = None,
    check: bool = False,
) -> CommandResult:
    """Run *argv* without a shell and return its result.

    Args:
        argv: Program and arguments. Never a single string, so no shell quoting
            issues and no command injection through crafted repository paths.
        cwd: Working directory for the child process.
        timeout: Hard wall-clock limit in seconds.
        env: Full environment for the child. ``None`` inherits the parent's.
        log_path: When given, append a JSON-lines audit record here.
        check: Raise on non-zero exit or timeout instead of returning.
    """
    argv = [str(a) for a in argv]
    started = time.perf_counter()
    timed_out = False

    log.debug("run: %s (cwd=%s, timeout=%ss)", " ".join(argv), cwd, timeout)
    try:
        completed = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            env=dict(env) if env is not None else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        returncode = completed.returncode
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        returncode = -1
        stdout = _as_text(exc.stdout)
        stderr = _as_text(exc.stderr)
    except FileNotFoundError as exc:
        timed_out = False
        returncode = 127
        stdout = ""
        stderr = str(exc)

    duration = time.perf_counter() - started
    result = CommandResult(
        argv=tuple(argv),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_s=round(duration, 3),
        timed_out=timed_out,
    )

    if log_path is not None:
        _append_audit_record(log_path, result, cwd)

    if check:
        if timed_out:
            raise CommandTimeout(f"{argv[0]} timed out after {timeout}s")
        if returncode != 0:
            raise CommandFailed(f"{argv[0]} exited with {returncode}: {stderr.strip()[:500]}")

    return result


def _as_text(value: bytes | str | None) -> str:
    """Normalise partial output captured from a timed-out process."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _append_audit_record(log_path: Path, result: CommandResult, cwd: Path | None) -> None:
    """Append one audit line. Logging must never break a scan, so errors are swallowed."""
    record = {
        "ts": datetime.now(UTC).isoformat(),
        "argv": list(result.argv),
        "cwd": str(cwd) if cwd else None,
        "returncode": result.returncode,
        "duration_s": result.duration_s,
        "timed_out": result.timed_out,
    }
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        log.warning("could not write command audit record to %s", log_path)
