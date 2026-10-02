"""Getting the source code onto disk so the static analysers can read it."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from qa_agent.logging_setup import get_logger
from qa_agent.tools.process import resolve_executable, run_command

log = get_logger(__name__)


class CloneFailed(RuntimeError):
    """Raised when the repository could not be fetched."""


@dataclass(frozen=True)
class SourceTree:
    """A local directory of source code, ready to be scanned."""

    path: Path
    commit: str = ""
    detail: str = ""


def clone_repo(
    url: str,
    dest: Path,
    *,
    git_bin: str = "git",
    timeout: float = 600.0,
    log_path: Path | None = None,
) -> SourceTree:
    """Shallow-clone *url* into *dest* and return the resulting source tree.

    Three flags matter more than they look:

    ``-c core.longpaths=true``
        Repositories such as OWASP Juice Shop contain paths longer than
        Windows' legacy 260-character limit, and the clone fails halfway
        through without it.
    ``--depth 1``
        Only the current snapshot is analysed, so fetching the full history
        would waste time and disk for no benefit.
    ``GIT_TERMINAL_PROMPT=0``
        A private repository would otherwise block forever on an invisible
        username prompt. This turns that hang into an immediate, clear error.
    """
    git = resolve_executable(git_bin)
    if git is None:
        raise CloneFailed("git was not found; run 'python -m qa_agent check_env'")

    dest.parent.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"

    log.info("cloning %s", url)
    result = run_command(
        [
            git,
            "-c",
            "core.longpaths=true",
            "clone",
            "--depth",
            "1",
            "--single-branch",
            "--no-tags",
            url,
            str(dest),
        ],
        timeout=timeout,
        env=env,
        log_path=log_path,
    )

    if result.timed_out:
        raise CloneFailed(f"cloning {url} timed out after {timeout}s")
    if not result.ok:
        raise CloneFailed(f"cloning {url} failed: {result.stderr.strip()[:400]}")

    commit = _head_commit(git, dest, log_path)
    log.info("cloned %s at %s", url, commit[:8] or "unknown")
    return SourceTree(path=dest, commit=commit, detail=f"shallow clone of {url}")


def use_local_path(path: Path, *, git_bin: str = "git") -> SourceTree:
    """Use an existing directory as the source tree, without copying it.

    Nothing in the pipeline writes to the source tree, so scanning it in place
    is safe and avoids duplicating a large project on a disk-constrained
    machine.
    """
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_dir():
        raise CloneFailed(f"{resolved} is not a directory")
    git = resolve_executable(git_bin)
    commit = _head_commit(git, resolved, None) if git else ""
    return SourceTree(path=resolved, commit=commit, detail=f"local directory {resolved}")


def _head_commit(git: str | None, repo: Path, log_path: Path | None) -> str:
    """Return the checked-out commit, or an empty string if it is not a repo."""
    if git is None:
        return ""
    result = run_command([git, "-C", str(repo), "rev-parse", "HEAD"], timeout=60, log_path=log_path)
    return result.stdout.strip() if result.ok else ""
