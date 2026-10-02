"""Preflight checks for every external dependency the agent needs.

Each check answers one question and returns a :class:`CheckResult` carrying a
status and, when something is wrong, a copy-pasteable remediation hint. The
checks are grouped by the pipeline stage they unblock, so a partial environment
still tells you exactly which stage will not run.

Statuses:
    ok         the dependency is present and usable
    missing    the dependency was not found at all
    degraded   the dependency exists but is not usable right now
               (for example Docker installed but its daemon is stopped)
"""

from __future__ import annotations

import platform
import sys
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Literal

import httpx

from qa_agent.config import MIN_PYTHON, Settings
from qa_agent.tools.process import resolve_executable, run_command

Status = Literal["ok", "missing", "degraded"]

GROUP_CORE = "core"
GROUP_STATIC = "static analysis"
GROUP_DYNAMIC = "dynamic analysis"
GROUP_LLM = "local llm"


@dataclass(frozen=True)
class CheckResult:
    """Outcome of a single environment check."""

    name: str
    group: str
    status: Status
    detail: str
    hint: str = ""
    required: bool = True

    @property
    def passed(self) -> bool:
        return self.status == "ok"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _first_line(text: str) -> str:
    """First non-empty line of *text*, used to summarise ``--version`` output."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _probe(
    binary: str,
    extra_dirs: Sequence[Path],
    args: Sequence[str] = ("--version",),
    timeout: float = 30.0,
) -> tuple[str | None, str]:
    """Resolve *binary* and capture its version banner.

    Returns ``(resolved_path, banner)``; ``(None, "")`` when not found.
    """
    path = resolve_executable(binary, extra_dirs)
    if path is None:
        return None, ""
    result = run_command([path, *args], timeout=timeout)
    banner = _first_line(result.stdout) or _first_line(result.stderr)
    return path, banner


def _binary_check(
    name: str,
    group: str,
    binary: str,
    settings: Settings,
    *,
    hint: str,
    required: bool = True,
    args: Sequence[str] = ("--version",),
) -> CheckResult:
    """Generic 'is this executable installed and does it answer' check."""
    path, banner = _probe(binary, [settings.vendor_bin_dir], args)
    if path is None:
        return CheckResult(name, group, "missing", f"'{binary}' not found on PATH", hint, required)
    if not banner:
        return CheckResult(
            name, group, "degraded", f"found at {path} but did not report a version", hint, required
        )
    return CheckResult(name, group, "ok", banner, "", required)


# --------------------------------------------------------------------------
# core
# --------------------------------------------------------------------------
def check_python() -> CheckResult:
    """The interpreter running the agent must satisfy the minimum version."""
    current = sys.version_info[:3]
    wanted = ".".join(str(p) for p in MIN_PYTHON)
    detail = f"{platform.python_implementation()} {'.'.join(str(p) for p in current)}"
    if current >= MIN_PYTHON:
        return CheckResult("python", GROUP_CORE, "ok", detail)
    return CheckResult(
        "python",
        GROUP_CORE,
        "missing",
        f"{detail} is older than the required {wanted}",
        f"install Python {wanted} or newer and recreate the virtual environment",
    )


def check_docker_daemon(settings: Settings) -> CheckResult:
    """Docker must be installed *and* its daemon reachable.

    The daemon is what actually matters: ZAP, Juice Shop and auto-launching a
    repository under test all run as containers.
    """
    hint = "start Docker Desktop and wait for the whale icon to stop animating"
    path = resolve_executable(settings.docker_bin, [settings.vendor_bin_dir])
    if path is None:
        return CheckResult(
            "docker daemon",
            GROUP_CORE,
            "missing",
            "'docker' not found on PATH",
            "install Docker Desktop: https://docs.docker.com/desktop/install/windows-install/",
        )
    result = run_command([path, "info", "--format", "{{.ServerVersion}}"], timeout=60.0)
    version = _first_line(result.stdout)
    if result.ok and version:
        return CheckResult("docker daemon", GROUP_CORE, "ok", f"server {version}")
    return CheckResult(
        "docker daemon",
        GROUP_CORE,
        "degraded",
        "docker CLI present but the daemon is not responding",
        hint,
    )


# --------------------------------------------------------------------------
# dynamic analysis
# --------------------------------------------------------------------------
def check_playwright_browser() -> CheckResult:
    """The Playwright Python package and its Chromium build must both exist."""
    hint = "python -m playwright install chromium"
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return CheckResult(
            "playwright chromium",
            GROUP_DYNAMIC,
            "missing",
            "the 'playwright' package is not installed",
            "pip install -e .",
        )

    try:
        driver = sync_playwright().start()
    except Exception as exc:  # noqa: BLE001 - surfaced to the user as a hint
        return CheckResult(
            "playwright chromium", GROUP_DYNAMIC, "degraded", f"driver failed: {exc}", hint
        )

    try:
        executable = driver.chromium.executable_path
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "playwright chromium", GROUP_DYNAMIC, "missing", f"no browser build: {exc}", hint
        )
    finally:
        driver.stop()

    if executable and Path(executable).exists():
        return CheckResult("playwright chromium", GROUP_DYNAMIC, "ok", executable)
    return CheckResult(
        "playwright chromium", GROUP_DYNAMIC, "missing", "Chromium build not downloaded", hint
    )


# --------------------------------------------------------------------------
# local LLM
# --------------------------------------------------------------------------
def _fetch_ollama_tags(settings: Settings) -> tuple[list[str] | None, str]:
    """Return the list of locally installed model names, or ``(None, error)``."""
    url = settings.ollama_host.rstrip("/") + "/api/tags"
    try:
        response = httpx.get(url, timeout=10.0)
        response.raise_for_status()
        payload = response.json()
    except Exception as exc:  # noqa: BLE001 - any failure means "not usable"
        return None, str(exc)
    names = [model.get("name", "") for model in payload.get("models", [])]
    return names, ""


def check_ollama_api(settings: Settings, names: list[str] | None, error: str) -> CheckResult:
    """The Ollama HTTP server must be answering on localhost."""
    if names is None:
        return CheckResult(
            "ollama api",
            GROUP_LLM,
            "missing",
            f"{settings.ollama_host} unreachable ({error})",
            "start the server with: ollama serve",
        )
    return CheckResult(
        "ollama api", GROUP_LLM, "ok", f"{settings.ollama_host} responding, {len(names)} model(s)"
    )


def check_ollama_model(settings: Settings, names: list[str] | None) -> CheckResult:
    """The configured model must already be pulled, since scans run offline."""
    wanted = settings.llm_model
    hint = f"ollama pull {wanted}"
    if names is None:
        return CheckResult(
            "llm model", GROUP_LLM, "degraded", "cannot verify while the API is down", hint
        )
    # Ollama reports an implicit ':latest' tag, so accept both spellings.
    candidates = {wanted, f"{wanted}:latest"}
    if candidates & set(names):
        return CheckResult("llm model", GROUP_LLM, "ok", wanted)
    return CheckResult(
        "llm model", GROUP_LLM, "missing", f"'{wanted}' is not installed locally", hint
    )


def check_llm_generation(settings: Settings) -> CheckResult:
    """Deep check: the model must actually answer through the OpenAI-shaped API.

    This is the endpoint the whole phase 2 layer uses, so proving it end to end
    is worth the few seconds it costs.
    """
    url = settings.llm_base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": settings.llm_model,
        "temperature": settings.llm_temperature,
        "messages": [{"role": "user", "content": "Reply with the single word: ready"}],
    }
    try:
        response = httpx.post(url, json=payload, timeout=float(settings.llm_timeout_s))
        response.raise_for_status()
        content = response.json()["choices"][0]["message"]["content"]
    except Exception as exc:  # noqa: BLE001
        return CheckResult(
            "llm generation",
            GROUP_LLM,
            "degraded",
            f"generation failed: {exc}",
            "check that the model fits in VRAM, or pick a smaller QA_AGENT_LLM_MODEL",
            required=False,
        )
    preview = " ".join(str(content).split())[:60]
    return CheckResult("llm generation", GROUP_LLM, "ok", f'answered "{preview}"', required=False)


# --------------------------------------------------------------------------
# orchestration
# --------------------------------------------------------------------------
def run_all_checks(settings: Settings, deep: bool = False) -> list[CheckResult]:
    """Run every check and return the results in reporting order."""
    results: list[CheckResult] = [
        check_python(),
        _binary_check(
            "git", GROUP_CORE, settings.git_bin, settings, hint="install Git for Windows"
        ),
        check_docker_daemon(settings),
        _binary_check(
            "semgrep",
            GROUP_STATIC,
            settings.semgrep_bin,
            settings,
            hint='pip install -e ".[scanners]"',
        ),
        _binary_check(
            "trivy",
            GROUP_STATIC,
            settings.trivy_bin,
            settings,
            hint="powershell -File scripts/install_tools.ps1",
        ),
        _binary_check(
            "osv-scanner",
            GROUP_STATIC,
            settings.osv_bin,
            settings,
            hint="powershell -File scripts/install_tools.ps1",
        ),
        _binary_check(
            "node",
            GROUP_DYNAMIC,
            settings.node_bin,
            settings,
            hint="install Node.js LTS (required by Lighthouse)",
        ),
        check_playwright_browser(),
    ]

    # One HTTP round trip serves both Ollama checks.
    names, error = _fetch_ollama_tags(settings)
    results.append(check_ollama_api(settings, names, error))
    results.append(check_ollama_model(settings, names))
    if deep:
        results.append(check_llm_generation(settings))

    return results
