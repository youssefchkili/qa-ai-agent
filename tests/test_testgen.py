"""Tests for LLM-planned test generation: the plan language, the compiler,
the sandboxed runner and the bounded plan/run/repair loop."""

from __future__ import annotations

import ast
import json

import pytest

from qa_agent.config import Settings
from qa_agent.llm.client import LLMReply, LLMUnavailable
from qa_agent.models.finding import Category, Severity, Tool
from qa_agent.testgen import generator
from qa_agent.testgen.compiler import compile_flow, slugify
from qa_agent.testgen.dsl import Flow, Step, parse_flows, resolve_url, validate_flow
from qa_agent.testgen.runner import FlowRun, parse_result, run_flow_script, sandbox_env
from qa_agent.web.page_model import PageObservation
from qa_agent.workspace import RunWorkspace

BASE = "http://localhost:3000"
KNOWN = frozenset({"#email", "#password", "#loginButton"})


def flow(*steps: tuple[str, str, str], name: str = "login") -> Flow:
    return Flow(
        name=name,
        page_url=f"{BASE}/#/login",
        steps=[Step(action=a, target=t, value=v) for a, t, v in steps],
    )


GOOD = flow(
    ("goto", "/#/login", ""),
    ("fill", "#email", "test@example.com"),
    ("click", "#loginButton", ""),
    ("expect_text", "", "Invalid email or password"),
)


# --------------------------------------------------------------------------
# the plan language
# --------------------------------------------------------------------------
def test_a_well_formed_flow_passes_validation():
    assert validate_flow(GOOD, base_url=BASE, known_selectors=KNOWN) == []


def test_an_invented_selector_is_rejected_with_a_hint():
    bad = flow(("goto", "/", ""), ("click", "#submit-button", ""), ("expect_text", "", "x"))
    problems = validate_flow(bad, base_url=BASE, known_selectors=KNOWN)
    assert any("#submit-button" in p and "copy a selector" in p for p in problems)


def test_a_flow_without_an_assertion_is_rejected():
    bad = flow(("goto", "/", ""), ("click", "#loginButton", ""))
    assert any("expect_" in p for p in validate_flow(bad, base_url=BASE, known_selectors=KNOWN))


def test_a_flow_must_start_with_goto():
    bad = flow(("click", "#loginButton", ""), ("expect_text", "", "x"))
    assert any("goto" in p for p in validate_flow(bad, base_url=BASE, known_selectors=KNOWN))


def test_navigation_off_the_application_is_rejected():
    bad = flow(("goto", "https://evil.example/", ""), ("expect_text", "", "x"))
    problems = validate_flow(bad, base_url=BASE, known_selectors=KNOWN)
    assert any("not a path inside" in p for p in problems)


def test_unknown_actions_and_keys_are_rejected():
    bad = flow(
        ("goto", "/", ""), ("eval", "", "alert(1)"), ("press", "", "F12"), ("expect_url", "", "")
    )
    problems = " ".join(validate_flow(bad, base_url=BASE, known_selectors=KNOWN))
    assert "unknown action" in problems
    assert "key must be one of" in problems
    assert "non-empty value" in problems


def test_fill_only_accepts_listed_inputs_not_text_selectors():
    bad = flow(("goto", "/", ""), ("fill", 'text="Email"', "x"), ("expect_text", "", "y"))
    assert validate_flow(bad, base_url=BASE, known_selectors=KNOWN)


def test_checking_a_form_result_without_submitting_it_is_rejected():
    # Observed live: fill the login form, never click "Log in", expect the
    # error text. That test can only ever fail, and re-running confirms it.
    never_submitted = flow(
        ("goto", "/#/login", ""),
        ("fill", "#email", "test@example.com"),
        ("expect_visible", "#loginButton", ""),
        ("expect_text", "", "Invalid email or password"),
    )
    problems = validate_flow(never_submitted, base_url=BASE, known_selectors=KNOWN)
    assert any("never submitted" in p for p in problems)


def test_pressing_enter_counts_as_submitting():
    submitted = flow(
        ("goto", "/#/login", ""),
        ("fill", "#email", "x"),
        ("press", "", "Enter"),
        ("expect_url", "", "login"),
    )
    assert validate_flow(submitted, base_url=BASE, known_selectors=KNOWN) == []


def test_a_disabled_submit_button_can_be_asserted_instead_of_clicked():
    invalid_input = flow(
        ("goto", "/#/login", ""),
        ("fill", "#email", "not-an-email"),
        ("expect_disabled", "#loginButton", ""),
    )
    assert validate_flow(invalid_input, base_url=BASE, known_selectors=KNOWN) == []
    source = compile_flow(invalid_input, base_url=BASE, step_timeout_ms=1000)
    assert "to_be_disabled" in source


def test_expect_enabled_compiles():
    source = compile_flow(
        flow(("goto", "/", ""), ("expect_enabled", "#loginButton", "")),
        base_url=BASE,
        step_timeout_ms=1000,
    )
    assert "to_be_enabled" in source


def test_click_accepts_a_quoted_text_selector():
    ok = flow(("goto", "/", ""), ("click", 'text="Log in"', ""), ("expect_text", "", "y"))
    assert validate_flow(ok, base_url=BASE, known_selectors=KNOWN) == []


def test_resolve_url_keeps_hash_routes_on_the_same_origin():
    assert resolve_url("/#/login", BASE) == f"{BASE}/#/login"
    assert resolve_url("//evil.example/x", BASE) is None
    assert resolve_url("", BASE) is None


def test_parse_flows_moves_a_press_key_out_of_target():
    # Observed from the model: {"action": "press", "target": "Enter"}.
    data = {"flows": [{"name": "f", "steps": [{"action": "press", "target": "Enter"}]}]}
    flows, _ = parse_flows(data, BASE)
    assert flows[0].steps[0].value == "Enter" and flows[0].steps[0].target == ""


def test_parse_flows_reports_malformed_entries():
    flows, problems = parse_flows({"flows": [{"steps": []}, "junk"]}, BASE)
    assert flows == []
    assert len(problems) == 2


def test_parse_flows_without_a_list():
    assert parse_flows({"nope": 1}, BASE) == ([], ["the reply had no 'flows' list"])


# --------------------------------------------------------------------------
# the compiler
# --------------------------------------------------------------------------
def test_compiled_script_is_valid_python():
    source = compile_flow(GOOD, base_url=BASE, step_timeout_ms=5000)
    ast.parse(source)
    assert "page.goto('http://localhost:3000/#/login'" in source
    assert "expect(page.get_by_text('Invalid email or password')" in source


def test_model_text_cannot_inject_code_into_the_script():
    hostile = flow(
        ("goto", "/", ""),
        ("fill", "#email", "'); import os; os.system('calc'); ('"),
        ("expect_text", "", '"""\nimport os\n"""'),
    )
    tree = ast.parse(compile_flow(hostile, base_url=BASE, step_timeout_ms=5000))

    # The only plain imports are the ones the agent itself wrote.
    imported = {
        alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    }
    assert imported == {"json", "re", "sys"}
    # The hostile text survives only as string literals, never as code.
    calls = {ast.unparse(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)}
    assert "os.system" not in calls


def test_unknown_actions_cannot_be_compiled():
    with pytest.raises(ValueError):
        compile_flow(flow(("goto", "/", ""), ("eval", "", "")), base_url=BASE, step_timeout_ms=1)


def test_slugify_is_filesystem_safe():
    assert slugify("Login: invalid / e-mail!") == "login-invalid-e-mail"
    assert slugify("!!!") == "flow"


# --------------------------------------------------------------------------
# the runner
# --------------------------------------------------------------------------
def test_parse_result_reads_the_last_marker_line():
    out = 'noise\nQA_RESULT {"status": "fail", "step": 3}\n'
    assert parse_result(out) == {"status": "fail", "step": 3}
    assert parse_result("no marker here") is None
    assert parse_result("QA_RESULT {broken") is None


def test_the_sandbox_withholds_secrets_from_the_test_process(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-secret")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "shh")
    env = sandbox_env()
    assert "OPENAI_API_KEY" not in env
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert env["PYTHONIOENCODING"] == "utf-8"


def test_run_flow_script_reports_the_result_line(tmp_path):
    script = tmp_path / "t.py"
    script.write_text(
        "import json\n"
        'print("QA_RESULT " + json.dumps({"status": "fail", "step": 2, '
        '"action": "expect_text", "message": "not visible"}))\n',
        encoding="utf-8",
    )
    run = run_flow_script(script, timeout_s=60)
    assert run.status == "fail" and run.step == 2 and run.message == "not visible"


def test_a_script_that_prints_nothing_is_an_error(tmp_path):
    script = tmp_path / "t.py"
    script.write_text("import sys; sys.exit(3)", encoding="utf-8")
    run = run_flow_script(script, timeout_s=60)
    assert run.status == "error" and "no result" in run.message


def test_a_script_that_hangs_is_stopped(tmp_path):
    script = tmp_path / "t.py"
    script.write_text("import time; time.sleep(30)", encoding="utf-8")
    run = run_flow_script(script, timeout_s=1)
    assert run.status == "error" and "did not finish" in run.message


# --------------------------------------------------------------------------
# the plan -> run -> repair loop
# --------------------------------------------------------------------------
def login_page() -> PageObservation:
    return PageObservation(
        url=f"{BASE}/#/login",
        title="Juice",
        structure={
            "inputs": [
                {"selector": "#email", "type": "input", "label": "Email"},
                {"selector": "#password", "type": "password", "label": "Password"},
                {"selector": "#author", "type": "text", "label": "Author", "disabled": True},
            ],
            "buttons": [{"selector": "#loginButton", "text": "Log in", "disabled": True}],
            "headings": ["Login"],
        },
    )


class ScriptedClient:
    model = "fake-model"

    def __init__(self, replies):
        self.replies = list(replies)
        self.prompts: list[str] = []

    def complete_json(self, *, system, user, purpose, max_tokens=None):
        self.prompts.append(user)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        return LLMReply(reply, json.dumps(reply), 1, 1, 1, 0.1)


def as_plan(*flows_: Flow) -> dict:
    return {
        "flows": [{"name": f.name, "steps": [s.model_dump() for s in f.steps]} for f in flows_]
    }


@pytest.fixture
def workspace(tmp_path) -> RunWorkspace:
    return RunWorkspace.create(tmp_path)


def test_disabled_inputs_are_not_offered_for_fill_but_disabled_buttons_are():
    known = generator.known_selectors([login_page()])
    assert "#author" not in known
    assert "#loginButton" in known  # a submit button disabled until the form is valid


def test_the_prompt_marks_disabled_elements():
    prompt = generator.build_page_prompt(login_page(), 2)
    assert "#author | text | Author (disabled: cannot be filled)" in prompt
    assert "(disabled until the form is valid)" in prompt


def test_only_pages_with_inputs_are_planned_from():
    empty = PageObservation(url=f"{BASE}/", structure={"inputs": []})
    broken = PageObservation(url=f"{BASE}/x", load_error="boom", structure={"inputs": [{}]})
    assert generator.select_pages([empty, broken, login_page()], 3) == [login_page()]


def test_a_passing_flow_is_recorded(monkeypatch, workspace):
    monkeypatch.setattr(generator, "run_flow_script", lambda *a, **k: FlowRun(status="pass"))
    client = ScriptedClient([as_plan(GOOD)])

    outcomes = generator.generate_and_run(
        [login_page()], client=client, settings=Settings(), workspace=workspace, base_url=BASE
    )

    assert [o.status for o in outcomes] == ["pass"]
    assert outcomes[0].attempts == 1
    assert (workspace.tests_dir / outcomes[0].script).is_file()


def test_an_invalid_flow_gets_exactly_one_repair_with_the_page_context(monkeypatch, workspace):
    monkeypatch.setattr(generator, "run_flow_script", lambda *a, **k: FlowRun(status="pass"))
    bad = flow(("goto", "/#/login", ""), ("click", "#nope", ""), ("expect_text", "", "x"))
    client = ScriptedClient([as_plan(bad), as_plan(GOOD)])

    outcomes = generator.generate_and_run(
        [login_page()], client=client, settings=Settings(), workspace=workspace, base_url=BASE
    )

    assert outcomes[0].status == "pass" and outcomes[0].attempts == 2
    # The repair prompt repeats the real selectors, or the model cannot fix it.
    assert "#loginButton" in client.prompts[1] and "#nope" in client.prompts[1]


def test_a_flow_that_errors_twice_becomes_not_testable(monkeypatch, workspace):
    monkeypatch.setattr(
        generator,
        "run_flow_script",
        lambda *a, **k: FlowRun(status="error", step=2, action="fill", message="timeout"),
    )
    client = ScriptedClient([as_plan(GOOD), as_plan(GOOD)])

    outcomes = generator.generate_and_run(
        [login_page()], client=client, settings=Settings(), workspace=workspace, base_url=BASE
    )

    assert outcomes[0].status == "not_testable"
    assert outcomes[0].attempts == 2
    assert "could not be executed" in outcomes[0].message
    assert client.replies == []  # plan + one repair, never a third call


def test_the_number_of_flows_is_capped(monkeypatch, workspace):
    monkeypatch.setattr(generator, "run_flow_script", lambda *a, **k: FlowRun(status="pass"))
    client = ScriptedClient([as_plan(GOOD, GOOD, GOOD)])

    outcomes = generator.generate_and_run(
        [login_page()],
        client=client,
        settings=Settings(testgen_max_flows=1),
        workspace=workspace,
        base_url=BASE,
    )
    assert len(outcomes) == 1


def test_a_planning_failure_skips_the_page(workspace):
    client = ScriptedClient([LLMUnavailable("down")])
    outcomes = generator.generate_and_run(
        [login_page()], client=client, settings=Settings(), workspace=workspace, base_url=BASE
    )
    assert outcomes == []


def test_a_failed_flow_becomes_a_low_severity_functional_finding():
    outcome = generator.FlowOutcome(
        name="Login with fake email",
        page_url=f"{BASE}/#/login",
        status="fail",
        steps=["1. goto /#/login"],
        message="text not visible",
        script="flow_01_login_a1.py",
        failed_step=4,
        failed_action="expect_text",
    )

    finding = generator.outcome_to_finding(outcome)

    assert finding.tool == Tool.PLAYWRIGHT
    assert finding.category == Category.FUNCTIONAL
    # The expectation was written by the model, so it must not outrank
    # real scanner findings until a human confirms it.
    assert finding.severity == Severity.LOW
    assert "needs human confirmation" in finding.title
    assert finding.metadata["failed_step"] == 4


def test_what_the_page_actually_said_is_part_of_the_evidence():
    # Observed live: the model expected "Invalid password" while the app
    # (correctly) showed "Invalid email or password.". Showing both makes a
    # wrong expectation obvious to the human confirming the failure.
    outcome = generator.FlowOutcome(
        name="Login with a wrong password",
        page_url=f"{BASE}/#/login",
        status="fail",
        failed_step=8,
        failed_action="expect_text",
        observed=["Invalid email or password."],
    )
    finding = generator.outcome_to_finding(outcome)
    assert "The page was actually showing: Invalid email or password." in finding.evidence
    assert finding.metadata["observed_messages"] == ["Invalid email or password."]


def test_observed_messages_are_read_from_the_result_line(tmp_path):
    script = tmp_path / "t.py"
    script.write_text(
        "import json\n"
        'print("QA_RESULT " + json.dumps({"status": "fail", "step": 3, '
        '"observed": ["Invalid email or password."]}))\n',
        encoding="utf-8",
    )
    assert run_flow_script(script, timeout_s=60).observed == ("Invalid email or password.",)


def test_the_compiled_script_reports_visible_messages_on_failure():
    source = compile_flow(GOOD, base_url=BASE, step_timeout_ms=1000)
    assert "observed = visible_messages(page)" in source
    assert '"observed": observed' in source


def test_outcome_serialises_for_the_report():
    outcome = generator.FlowOutcome(name="n", page_url=BASE, status="pass", attempts=1)
    assert outcome.to_dict()["status"] == "pass"
