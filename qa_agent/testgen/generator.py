"""Plan, validate, compile, run - with exactly one repair attempt per flow.

For each interesting page the model proposes flows. Each flow then goes through:

    validate ──bad──> ask the model to fix it (once) ──bad again──> not testable
       │
    compile + run
       ├── pass   -> recorded as a passing flow
       ├── fail   -> an expect_ step did not hold: a candidate functional finding
       └── error  -> the test could not execute (element missing, timeout):
                     send the error back once; if it errors again -> not testable

The loop is bounded twice over: one repair per flow, and a hard cap on the
number of flows per run. It can never spin indefinitely.

A failure here is weaker evidence than a scanner finding: the *expectation*
was written by the model and may simply be wrong. Such findings are labelled
accordingly and must reproduce in a fresh browser before they count.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from urllib.parse import urlparse

from qa_agent.config import Settings
from qa_agent.llm.client import LLMClient, LLMError
from qa_agent.llm.prompts import TESTGEN_REPAIR, TESTGEN_SYSTEM, TESTGEN_USER
from qa_agent.logging_setup import get_logger
from qa_agent.models.finding import Category, Finding, Severity, Tool
from qa_agent.testgen.compiler import compile_flow, slugify
from qa_agent.testgen.dsl import Flow, describe_steps, parse_flows, validate_flow
from qa_agent.testgen.runner import run_flow_script
from qa_agent.web.page_model import PageObservation
from qa_agent.workspace import RunWorkspace

log = get_logger(__name__)

FLOWS_PER_PAGE = 3
MAX_ELEMENTS_SHOWN = 20

STATUS_PASS = "pass"
STATUS_FAIL = "fail"
STATUS_NOT_TESTABLE = "not_testable"


@dataclass
class FlowOutcome:
    """What happened to one proposed flow, for the report and the verifier."""

    name: str
    page_url: str
    description: str = ""
    status: str = STATUS_NOT_TESTABLE
    attempts: int = 0
    steps: list[str] = field(default_factory=list)
    message: str = ""
    script: str = ""
    screenshot: str = ""
    failed_step: int | None = None
    failed_action: str | None = None
    observed: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "page_url": self.page_url,
            "description": self.description,
            "status": self.status,
            "attempts": self.attempts,
            "steps": self.steps,
            "message": self.message,
            "script": self.script,
            "screenshot": self.screenshot,
            "failed_step": self.failed_step,
            "observed": self.observed,
        }


# --------------------------------------------------------------------------
# inputs for the model
# --------------------------------------------------------------------------
def select_pages(pages: list[PageObservation], limit: int) -> list[PageObservation]:
    """Pages with something to fill in come first; pages that failed are skipped."""
    usable = [p for p in pages if not p.load_error and p.structure]
    with_inputs = [p for p in usable if p.structure.get("inputs")]
    return with_inputs[:limit]


def known_selectors(pages: list[PageObservation]) -> frozenset[str]:
    """Every usable selector the crawler saw: the only ones a flow may use.

    Disabled inputs are excluded, since nothing can be typed into them.
    Disabled *buttons* stay: a submit button is disabled until its form is
    valid, which is exactly what many flows test.
    """
    selectors: set[str] = set()
    for page in pages:
        for element in page.structure.get("inputs", []) or []:
            if element.get("selector") and not element.get("disabled"):
                selectors.add(element["selector"])
        for element in page.structure.get("buttons", []) or []:
            if element.get("selector"):
                selectors.add(element["selector"])
    return frozenset(selectors)


def page_path(url: str) -> str:
    """The part of *url* after the origin, e.g. ``/#/login``."""
    parsed = urlparse(url)
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    return path + query + fragment


def build_page_prompt(page: PageObservation, max_flows: int) -> str:
    structure = page.structure
    inputs = [
        f"{i['selector']} | {i.get('type', '')} | {i.get('label', '')}"
        + (" (disabled: cannot be filled)" if i.get("disabled") else "")
        for i in (structure.get("inputs") or [])[:MAX_ELEMENTS_SHOWN]
    ]
    # Disabled buttons are listed too: a form's submit button is typically
    # disabled until its fields are valid. Hiding it made the model invent one.
    buttons = [
        f"{b['selector']} | {b.get('text', '')}"
        + (" (disabled until the form is valid)" if b.get("disabled") else "")
        for b in (structure.get("buttons") or [])[:MAX_ELEMENTS_SHOWN]
        if b.get("selector")
    ]
    return TESTGEN_USER.format(
        path=page_path(page.url),
        title=page.title or structure.get("title", ""),
        headings=", ".join((structure.get("headings") or [])[:6]) or "-",
        inputs="\n".join(inputs) or "-",
        buttons="\n".join(buttons) or "-",
        max_flows=max_flows,
    )


# --------------------------------------------------------------------------
# the plan -> run -> repair loop
# --------------------------------------------------------------------------
def _repair(
    flow: Flow, problem: str, client: LLMClient, page: PageObservation
) -> Flow | None:
    """Ask the model to correct one flow. Returns None if it cannot.

    The page description is sent again with the error: without the list of
    real selectors, the model cannot fix a "not a listed selector" problem
    and simply invents another one.
    """
    payload = {
        "name": flow.name,
        "description": flow.description,
        "steps": [s.model_dump() for s in flow.steps],
    }
    user = (
        build_page_prompt(page, 1)
        + "\n\n"
        + TESTGEN_REPAIR.format(
            name=flow.name,
            problem=problem,
            flow=json.dumps(payload, ensure_ascii=False, indent=1),
        )
    )
    try:
        reply = client.complete_json(system=TESTGEN_SYSTEM, user=user, purpose="testgen-repair")
    except LLMError as exc:
        log.warning("repair of flow %r failed: %s", flow.name, exc)
        return None
    flows, _ = parse_flows(reply.data, page.url)
    return flows[0] if flows else None


def _run_with_one_repair(
    flow: Flow,
    *,
    page: PageObservation,
    index: int,
    client: LLMClient,
    settings: Settings,
    workspace: RunWorkspace,
    base_url: str,
    known: frozenset[str],
) -> FlowOutcome:
    current = flow
    problem = ""
    outcome = FlowOutcome(name=flow.name, page_url=flow.page_url, description=flow.description)

    for attempt in (1, 2):
        outcome.attempts = attempt
        outcome.steps = describe_steps(current)
        problems = validate_flow(current, base_url=base_url, known_selectors=known)

        if problems:
            problem = "; ".join(problems)
        else:
            name = f"flow_{index:02d}_{slugify(current.name)}_a{attempt}.py"
            script = workspace.tests_dir / name
            script.write_text(
                compile_flow(
                    current, base_url=base_url, step_timeout_ms=settings.testgen_step_timeout_ms
                ),
                encoding="utf-8",
            )
            run = run_flow_script(
                script, timeout_s=settings.testgen_run_timeout_s, log_path=workspace.command_log
            )
            outcome.script = script.name
            outcome.screenshot = run.screenshot
            if run.status in (STATUS_PASS, STATUS_FAIL):
                outcome.status = run.status
                outcome.message = run.message
                outcome.failed_step = run.step
                outcome.failed_action = run.action
                outcome.observed = list(run.observed)
                return outcome
            problem = f"step {run.step} ({run.action}) could not be executed: {run.message}"

        if attempt == 2:
            break
        repaired = _repair(current, problem, client, page)
        if repaired is None:
            break
        current = repaired

    outcome.status = STATUS_NOT_TESTABLE
    outcome.message = problem
    return outcome


def generate_and_run(
    pages: list[PageObservation],
    *,
    client: LLMClient,
    settings: Settings,
    workspace: RunWorkspace,
    base_url: str,
) -> list[FlowOutcome]:
    """Plan flows for the most interesting pages, then run each one."""
    known = known_selectors(pages)
    outcomes: list[FlowOutcome] = []

    for page in select_pages(pages, settings.testgen_pages):
        remaining = settings.testgen_max_flows - len(outcomes)
        if remaining <= 0:
            break
        per_page = min(FLOWS_PER_PAGE, remaining)
        try:
            reply = client.complete_json(
                system=TESTGEN_SYSTEM,
                user=build_page_prompt(page, per_page),
                purpose="testgen-plan",
            )
        except LLMError as exc:
            log.warning("could not plan flows for %s: %s", page.url, exc)
            continue

        flows, problems = parse_flows(reply.data, page.url)
        for problem in problems:
            log.info("discarded a proposed flow for %s: %s", page.url, problem)

        for flow in flows[:per_page]:
            outcome = _run_with_one_repair(
                flow,
                page=page,
                index=len(outcomes) + 1,
                client=client,
                settings=settings,
                workspace=workspace,
                base_url=base_url,
                known=known,
            )
            log.info(
                "flow %r: %s after %d attempt(s)", outcome.name, outcome.status, outcome.attempts
            )
            outcomes.append(outcome)

    return outcomes


def outcome_to_finding(outcome: FlowOutcome) -> Finding:
    """A failed flow becomes a functional finding, clearly labelled as generated."""
    evidence = "\n".join(
        [
            "Steps (planned by the local model, compiled by the agent):",
            *[f"  {line}" for line in outcome.steps],
            f"Failed at step {outcome.failed_step} ({outcome.failed_action}): {outcome.message}",
        ]
        + (
            ["The page was actually showing: " + " | ".join(outcome.observed)]
            if outcome.observed
            else []
        )
        + [f"Test script: {outcome.script}"]
        + ([f"Screenshot: {outcome.screenshot}"] if outcome.screenshot else [])
    )
    return Finding(
        tool=Tool.PLAYWRIGHT,
        category=Category.FUNCTIONAL,
        # LOW, deliberately. Observed on Juice Shop: the model expected
        # "Invalid email address" where the app correctly shows "Invalid email
        # or password". Re-running reproduces such a failure perfectly, so
        # verification cannot catch it; only a human can. Low severity keeps
        # a wrong expectation from outranking a real scanner finding.
        severity=Severity.LOW,
        title=f"Generated test flow failed (needs human confirmation): {outcome.name}",
        location=outcome.page_url,
        description=(
            f"{outcome.description} The page did not behave as the flow expected. "
            "The expectation was written by the local model, so confirm the intended "
            "behaviour before treating this as a defect."
        ).strip(),
        evidence=evidence,
        rule_id=f"flow:{slugify(outcome.name, 60)}",
        verification_method="pending: re-run in a fresh browser",
        metadata={
            "flow": outcome.name,
            "script": outcome.script,
            "failed_step": outcome.failed_step,
            "failed_action": outcome.failed_action,
            "authored_by": "llm-planned, agent-compiled",
            "confidence": "low: the expected behaviour was written by the model",
            "observed_messages": outcome.observed,
            "page": outcome.page_url,
        },
    )
