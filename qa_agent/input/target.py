"""Decide what the user handed us: a Git repository or a live web application.

The CLI takes a single ``--url`` and has to route it correctly, because the two
kinds of target drive completely different halves of the pipeline. Getting this
wrong is cheap to avoid and expensive to debug, so the rules are explicit and
unit-tested rather than guessed at runtime.
"""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse


class TargetKind(str, Enum):
    """What a target string refers to."""

    GIT_REPO = "git_repo"
    LOCAL_PATH = "local_path"
    WEB_APP = "web_app"


# Hosts whose URLs are repositories rather than pages to crawl.
_FORGE_HOSTS = {
    "github.com",
    "www.github.com",
    "gitlab.com",
    "www.gitlab.com",
    "bitbucket.org",
    "www.bitbucket.org",
    "codeberg.org",
    "git.sr.ht",
}

# scp-style remote, e.g. git@github.com:owner/repo.git
_SCP_LIKE = re.compile(r"^[\w.+-]+@[\w.-]+:[^/].*$")


def classify_target(value: str) -> TargetKind:
    """Classify *value* as a repository, a local path, or a web application."""
    text = value.strip()
    if not text:
        raise ValueError("target is empty")

    # An existing directory on disk wins over any URL interpretation.
    candidate = Path(text).expanduser()
    if candidate.exists() and candidate.is_dir():
        return TargetKind.LOCAL_PATH

    if _SCP_LIKE.match(text):
        return TargetKind.GIT_REPO

    parsed = urlparse(text if "://" in text else f"http://{text}")
    scheme = parsed.scheme.lower()
    if scheme in {"git", "ssh", "git+ssh"}:
        return TargetKind.GIT_REPO

    path = parsed.path.rstrip("/")
    if path.lower().endswith(".git"):
        return TargetKind.GIT_REPO

    # A forge URL with exactly owner/repo is a repository; anything deeper is a
    # page on that site (an issue, a pull request) and not something to clone.
    if parsed.hostname and parsed.hostname.lower() in _FORGE_HOSTS:
        segments = [s for s in path.split("/") if s]
        if len(segments) == 2:
            return TargetKind.GIT_REPO

    return TargetKind.WEB_APP


def repo_name(url: str) -> str:
    """Short, filesystem-safe name for a repository, used in logs and reports."""
    text = url.strip().rstrip("/")
    if text.lower().endswith(".git"):
        text = text[:-4]
    tail = re.split(r"[/:]", text)[-1] if text else "repo"
    safe = re.sub(r"[^A-Za-z0-9._-]", "-", tail)
    return safe or "repo"
