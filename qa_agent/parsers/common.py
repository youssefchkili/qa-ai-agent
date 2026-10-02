"""Helpers shared by the parsers: paths, snippets and severity mapping."""

from __future__ import annotations

from pathlib import Path

from qa_agent.models.finding import Severity

# A snippet is evidence, not a code listing. Keep it short enough to read.
MAX_SNIPPET_LINES = 12
MAX_SNIPPET_CHARS = 2000
# Never read a whole huge file into memory just to quote a few lines.
MAX_READABLE_BYTES = 5_000_000


def relative_location(raw_path: str, root: Path | None) -> str:
    """Express *raw_path* relative to the scanned root, using forward slashes.

    Tools report absolute paths that embed the temporary run directory. Since
    the run directory changes every time, leaving them absolute would make
    fingerprints differ between runs and leak local paths into the report.
    """
    text = (raw_path or "").strip()
    if not text:
        return ""
    if root is None:
        return text.replace("\\", "/")
    try:
        relative = Path(text).resolve().relative_to(Path(root).resolve())
        return relative.as_posix()
    except (ValueError, OSError):
        # Not under the root (or not a real path): return it as given.
        return text.replace("\\", "/")


def read_snippet(
    file_path: Path,
    start_line: int,
    end_line: int | None = None,
    *,
    context: int = 2,
) -> str:
    """Return the offending lines with a little surrounding context.

    Semgrep's free tier replaces the matched source with the literal string
    "requires login", so the agent reads the evidence from disk itself.
    """
    if start_line <= 0:
        return ""
    try:
        if not file_path.is_file() or file_path.stat().st_size > MAX_READABLE_BYTES:
            return ""
        lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""

    last = end_line or start_line
    first_index = max(0, start_line - 1 - context)
    last_index = min(len(lines), last + context)
    selected = lines[first_index:last_index][:MAX_SNIPPET_LINES]

    numbered = [f"{first_index + offset + 1:>5} | {line}" for offset, line in enumerate(selected)]
    return "\n".join(numbered)[:MAX_SNIPPET_CHARS]


def severity_from_name(
    name: str | None,
    mapping: dict[str, Severity],
    default: Severity = Severity.MEDIUM,
) -> Severity:
    """Map a tool's severity word onto the unified scale, case-insensitively."""
    if not name:
        return default
    return mapping.get(str(name).strip().upper(), default)


def truncate(text: str | None, limit: int = 1200) -> str:
    """Shorten long tool prose so one finding cannot dominate the report."""
    clean = " ".join((text or "").split())
    if len(clean) <= limit:
        return clean
    return clean[: limit - 1].rstrip() + "…"
