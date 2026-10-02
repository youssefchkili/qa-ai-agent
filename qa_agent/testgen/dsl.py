"""The restricted language the model uses to describe a test flow.

A flow is a list of steps drawn from seven actions. Anything outside that
vocabulary, any selector the crawler never saw, and any URL on another origin is
rejected *before* a browser is started. Rejection reasons are precise, because
they are sent back to the model for one repair attempt.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlparse

from pydantic import BaseModel, ConfigDict, ValidationError

ACTIONS = (
    "goto",
    "fill",
    "click",
    "press",
    "expect_visible",
    "expect_text",
    "expect_url",
    "expect_disabled",
    "expect_enabled",
)
ASSERTIONS = frozenset(
    {"expect_visible", "expect_text", "expect_url", "expect_disabled", "expect_enabled"}
)
# Assertions that check the *outcome* of submitting a form.
OUTCOME_ASSERTIONS = frozenset({"expect_text", "expect_url"})
SUBMIT_ACTIONS = frozenset({"click", "press"})
SELECTOR_ASSERTIONS = frozenset({"expect_visible", "expect_disabled", "expect_enabled"})
ALLOWED_KEYS = frozenset({"Enter", "Tab", "Escape"})

MIN_STEPS = 2
MAX_STEPS = 15
MAX_FIELD_CHARS = 200


class Step(BaseModel):
    """One action in a flow."""

    model_config = ConfigDict(extra="ignore")

    action: str
    target: str = ""
    value: str = ""


class Flow(BaseModel):
    """A named user journey, as proposed by the model."""

    model_config = ConfigDict(extra="ignore")

    name: str
    description: str = ""
    page_url: str = ""
    steps: list[Step]


def _normalise(step: Step) -> Step:
    """Trim fields, and accept the key of a ``press`` in either field.

    Observed: the model writes ``{"action": "press", "target": "Enter"}``.
    The intent is unambiguous, so it is accepted rather than rejected.
    """
    action = step.action.strip().lower()
    target = str(step.target or "").strip()
    value = str(step.value or "").strip()
    if action == "press" and not value and target:
        target, value = "", target
    return Step(action=action, target=target, value=value)


def parse_flows(data: Any, page_url: str) -> tuple[list[Flow], list[str]]:
    """Read ``{"flows": [...]}`` into Flow objects; collect what could not be read."""
    raw = data.get("flows") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        return [], ["the reply had no 'flows' list"]

    flows: list[Flow] = []
    problems: list[str] = []
    for index, item in enumerate(raw, start=1):
        try:
            flow = Flow.model_validate(item)
        except ValidationError as exc:
            problems.append(f"flow {index} is malformed: {exc.errors()[0].get('msg', exc)}")
            continue
        # Normalise the model's free-text fields before they go anywhere.
        steps = [_normalise(step) for step in flow.steps]
        flows.append(
            flow.model_copy(
                update={
                    "name": " ".join(flow.name.split())[:120] or f"flow {index}",
                    "page_url": page_url,
                    "steps": steps,
                }
            )
        )
    return flows, problems


def resolve_url(target: str, base_url: str) -> str | None:
    """Absolute URL for a goto target, or None if it leaves the application."""
    if not target:
        return None
    absolute = urljoin(base_url if base_url.endswith("/") else base_url + "/", target)
    base, candidate = urlparse(base_url), urlparse(absolute)
    if (candidate.scheme, candidate.netloc.lower()) != (base.scheme, base.netloc.lower()):
        return None
    return absolute


def _selector_ok(selector: str, known: frozenset[str], *, allow_text: bool) -> bool:
    if not selector or len(selector) > MAX_FIELD_CHARS or "\n" in selector:
        return False
    if selector in known:
        return True
    return allow_text and selector.startswith('text="') and selector.endswith('"')


def validate_flow(flow: Flow, *, base_url: str, known_selectors: frozenset[str]) -> list[str]:
    """Every reason this flow must not run. An empty list means it is safe to compile."""
    problems: list[str] = []
    steps = flow.steps

    if not MIN_STEPS <= len(steps) <= MAX_STEPS:
        problems.append(f"a flow needs {MIN_STEPS} to {MAX_STEPS} steps, got {len(steps)}")
    if not steps or steps[0].action != "goto":
        problems.append("the first step must be goto")
    if not any(step.action in ASSERTIONS for step in steps):
        problems.append("the flow has no expect_ step, so it would test nothing")

    for number, step in enumerate(steps, start=1):
        where = f"step {number} ({step.action})"
        if step.action not in ACTIONS:
            problems.append(f"{where}: unknown action; allowed: {', '.join(ACTIONS)}")
            continue
        if len(step.value) > MAX_FIELD_CHARS:
            problems.append(f"{where}: value is longer than {MAX_FIELD_CHARS} characters")

        if step.action == "goto" and resolve_url(step.target, base_url) is None:
            problems.append(f"{where}: '{step.target}' is not a path inside the application")
        elif step.action == "fill":
            if not _selector_ok(step.target, known_selectors, allow_text=False):
                problems.append(
                    f"{where}: '{step.target}' is not one of the listed inputs; "
                    f"copy an input selector exactly as listed"
                )
        elif step.action == "click" or step.action in SELECTOR_ASSERTIONS:
            if not _selector_ok(step.target, known_selectors, allow_text=True):
                problems.append(
                    f"{where}: '{step.target}' is not a listed selector; copy a selector "
                    f'exactly as listed, or use text="Exact visible text" with the quotes'
                )
        elif step.action == "press" and step.value not in ALLOWED_KEYS:
            problems.append(f"{where}: key must be one of {', '.join(sorted(ALLOWED_KEYS))}")
        elif step.action in ("expect_text", "expect_url") and not step.value:
            problems.append(f"{where}: needs a non-empty value")

    problems.extend(_unsubmitted_form_problems(steps))
    return problems


def _unsubmitted_form_problems(steps: list[Step]) -> list[str]:
    """Reject flows that check a form's result without ever submitting it.

    Observed on Juice Shop: the model filled the login form, never clicked
    "Log in", then expected "Invalid email or password". Such a test fails
    every time, re-running confirms it, and it reports a bug that does not
    exist. Structurally, typing into a form and then checking for its outcome
    requires a click or a key press in between.
    """
    problems: list[str] = []
    pending_fill = False
    for number, step in enumerate(steps, start=1):
        if step.action == "fill":
            pending_fill = True
        elif step.action in SUBMIT_ACTIONS or step.action == "goto":
            pending_fill = False
        elif step.action in OUTCOME_ASSERTIONS and pending_fill:
            problems.append(
                f"step {number} ({step.action}) checks the result of a form that was never "
                "submitted: click its submit button or press Enter after the last fill"
            )
            pending_fill = False
    return problems


def describe_steps(flow: Flow) -> list[str]:
    """Human-readable step list for the report."""
    lines = []
    for number, step in enumerate(flow.steps, start=1):
        parts = [step.action, step.target, repr(step.value) if step.value else ""]
        lines.append(f"{number}. " + " ".join(p for p in parts if p))
    return lines
