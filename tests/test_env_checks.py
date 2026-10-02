"""Tests for the subprocess helper and the environment preflight checks.

These tests deliberately avoid requiring any scanner to be installed: the goal
is to prove the check *logic*, not the machine it runs on.
"""

from __future__ import annotations

import json
import sys

from qa_agent.config import Settings
from qa_agent.env.checks import (
    CheckResult,
    _binary_check,
    _first_line,
    check_ollama_api,
    check_ollama_model,
    check_python,
)
from qa_agent.tools.process import resolve_executable, run_command


# --------------------------------------------------------------------------
# process helpers
# --------------------------------------------------------------------------
def test_run_command_captures_stdout():
    result = run_command([sys.executable, "-c", "print('hello')"], timeout=60)

    assert result.ok
    assert result.returncode == 0
    assert "hello" in result.stdout


def test_run_command_reports_non_zero_exit():
    result = run_command([sys.executable, "-c", "raise SystemExit(3)"], timeout=60)

    assert not result.ok
    assert result.returncode == 3


def test_run_command_flags_a_timeout():
    result = run_command([sys.executable, "-c", "import time; time.sleep(10)"], timeout=1)

    assert result.timed_out
    assert not result.ok


def test_run_command_handles_a_missing_executable():
    result = run_command(["definitely-not-a-real-binary-xyz"], timeout=10)

    assert not result.ok
    assert result.returncode == 127


def test_run_command_writes_one_audit_line_per_invocation(tmp_path):
    log_path = tmp_path / "commands.jsonl"

    run_command([sys.executable, "-c", "pass"], timeout=60, log_path=log_path)
    run_command([sys.executable, "-c", "pass"], timeout=60, log_path=log_path)

    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    record = json.loads(lines[0])
    assert set(record) == {"ts", "argv", "cwd", "returncode", "duration_s", "timed_out"}
    assert record["returncode"] == 0


def test_resolve_executable_finds_something_on_path():
    assert resolve_executable("python") or resolve_executable("python3")


def test_resolve_executable_returns_none_when_absent():
    assert resolve_executable("definitely-not-a-real-binary-xyz") is None


# --------------------------------------------------------------------------
# check helpers
# --------------------------------------------------------------------------
def test_first_line_skips_blank_lines():
    assert _first_line("\n\n  trivy 0.58.0 \nextra") == "trivy 0.58.0"


def test_first_line_of_empty_text_is_empty():
    assert _first_line("   \n  ") == ""


def test_check_result_to_dict_is_json_serialisable():
    result = CheckResult("git", "core", "ok", "git version 2.52.0")

    assert json.dumps(result.to_dict())
    assert result.passed


# --------------------------------------------------------------------------
# individual checks
# --------------------------------------------------------------------------
def test_check_python_passes_on_the_running_interpreter():
    # The test suite itself requires >=3.11, so this must hold.
    assert check_python().passed


def test_binary_check_reports_missing_with_a_hint():
    settings = Settings()

    result = _binary_check(
        "ghost", "static analysis", "definitely-not-a-real-binary-xyz", settings, hint="install it"
    )

    assert result.status == "missing"
    assert result.hint == "install it"
    assert not result.passed


def test_check_ollama_api_is_missing_when_unreachable():
    result = check_ollama_api(Settings(), None, "connection refused")

    assert result.status == "missing"
    assert "connection refused" in result.detail


def test_check_ollama_api_is_ok_when_tags_are_returned():
    result = check_ollama_api(Settings(), ["qwen2.5-coder:3b"], "")

    assert result.passed
    assert "1 model" in result.detail


def test_check_ollama_model_matches_the_configured_model():
    settings = Settings(llm_model="qwen2.5-coder:3b")

    result = check_ollama_model(settings, ["llama3:latest", "qwen2.5-coder:3b"])

    assert result.passed


def test_check_ollama_model_accepts_an_implicit_latest_tag():
    settings = Settings(llm_model="llama3")

    result = check_ollama_model(settings, ["llama3:latest"])

    assert result.passed


def test_check_ollama_model_is_missing_when_not_pulled():
    settings = Settings(llm_model="qwen2.5-coder:32b")

    result = check_ollama_model(settings, ["qwen2.5-coder:3b"])

    assert result.status == "missing"
    assert result.hint == "ollama pull qwen2.5-coder:32b"


def test_check_ollama_model_is_degraded_when_the_api_is_down():
    result = check_ollama_model(Settings(), None)

    assert result.status == "degraded"
