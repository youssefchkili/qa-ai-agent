"""Pull a JSON value out of whatever the model actually replied with.

Even in JSON mode, small models sometimes wrap their answer in Markdown code
fences or add a sentence before it. This module recovers the JSON when it is
there, and raises ``ValueError`` with a precise reason when it is not, so the
reason can be sent back to the model for one repair attempt.
"""

from __future__ import annotations

import json
import re
from typing import Any

_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)


def _first_balanced(text: str, opener: str, closer: str) -> str | None:
    """Return the first balanced ``opener ... closer`` span, respecting strings."""
    start = text.find(opener)
    if start < 0:
        return None

    depth = 0
    in_string = False
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return text[start : index + 1]
    return None


def extract_json(text: str) -> Any:
    """Parse the JSON value contained in *text*.

    Tries, in order: the whole reply, the contents of a code fence, and the
    first balanced object or array found anywhere in the reply.
    """
    if text is None or not str(text).strip():
        raise ValueError("the reply was empty")
    stripped = str(text).strip()

    candidates = [stripped]
    fenced = _FENCE.search(stripped)
    if fenced:
        candidates.append(fenced.group(1).strip())
    for opener, closer in (("{", "}"), ("[", "]")):
        span = _first_balanced(stripped, opener, closer)
        if span:
            candidates.append(span)

    last_error = ""
    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError as exc:
            last_error = f"{exc.msg} at line {exc.lineno} column {exc.colno}"
    raise ValueError(f"no valid JSON found ({last_error or 'no object or array present'})")
