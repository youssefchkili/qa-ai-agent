"""Tests for the command line interface and the offline provisioning step.

The CLI's contract is its *exit code*: 0 means usable, non-zero means not.
Scripts, CI and the phase 3 container health check depend on that, so it is
tested explicitly rather than by reading the printed text.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from qa_agent import cli as cli_module
from qa_agent import seed as seed_module
from qa_agent.config import Settings
from qa_agent.env.checks import CheckResult
from qa_agent.models.run import RunSummary
from qa_agent.pipeline import PipelineResult
from qa_agent.tools.process import CommandResult
from qa_agent.workspace import RunWorkspace

runner = CliRunner()


def command_result(returncode: int = 0, stdout: str = "", stderr: str = ""):
    return CommandResult(
        argv=("fake",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_s=0.1,
        timed_out=False,
    )


# --------------------------------------------------------------------------
# check_env
# --------------------------------------------------------------------------
def test_check_env_exits_zero_when_everything_passes(monkeypatch):
    monkeypatch.setattr(
        cli_module,
        "run_all_checks",
        lambda settings, deep=False: [CheckResult("git", "core", "ok", "git 2.52")],
    )

    outcome = runner.invoke(cli_module.app, ["check_env"])

    assert outcome.exit_code == 0
    assert "PASS" in outcome.stdout


def test_check_env_exits_non_zero_when_a_required_tool_is_missing(monkeypatch):
    monkeypatch.setattr(
        cli_module,
        "run_all_checks",
        lambda settings, deep=False: [
            CheckResult("trivy", "static analysis", "missing", "not found", "install it")
        ],
    )

    outcome = runner.invoke(cli_module.app, ["check_env"])

    assert outcome.exit_code == 1
    assert "FAIL" in outcome.stdout
    assert "install it" in outcome.stdout  # the fix hint must be shown


def test_check_env_ignores_a_failing_optional_check(monkeypatch):
    monkeypatch.setattr(
        cli_module,
        "run_all_checks",
        lambda settings, deep=False: [
            CheckResult("llm generation", "local llm", "degraded", "slow", "", required=False)
        ],
    )

    assert runner.invoke(cli_module.app, ["check_env"]).exit_code == 0


def test_check_env_can_emit_json(monkeypatch):
    monkeypatch.setattr(
        cli_module,
        "run_all_checks",
        lambda settings, deep=False: [CheckResult("git", "core", "ok", "git 2.52")],
    )

    outcome = runner.invoke(cli_module.app, ["check_env", "--json"])

    assert outcome.exit_code == 0
    assert '"ok"' in outcome.stdout


# --------------------------------------------------------------------------
# run
# --------------------------------------------------------------------------
def test_run_without_a_target_is_a_usage_error():
    outcome = runner.invoke(cli_module.app, ["run"])

    assert outcome.exit_code == 2
    assert "Nothing to scan" in outcome.stdout


def test_run_rejects_an_unknown_skip_value():
    outcome = runner.invoke(cli_module.app, ["run", "--app-url", "http://x", "--skip", "nope"])

    assert outcome.exit_code == 2
    assert "Unknown --skip" in outcome.stdout


def test_run_prints_where_the_artefacts_landed(tmp_path, monkeypatch):
    workspace = RunWorkspace.create(tmp_path, run_id="20260923-101112-abcdef")
    summary = RunSummary(run_id=workspace.run_id)

    def fake_pipeline(**kwargs):
        return PipelineResult(
            workspace=workspace,
            summary=summary,
            findings=[],
            report_md=workspace.report_md_path,
            report_html=workspace.report_html_path,
        )

    monkeypatch.setattr(cli_module, "run_pipeline", fake_pipeline)

    outcome = runner.invoke(cli_module.app, ["run", "--app-url", "http://localhost:3000"])

    assert outcome.exit_code == 0
    assert "report.html" in outcome.stdout
    assert "0 finding(s)" in outcome.stdout


def test_run_forwards_its_options_to_the_pipeline(monkeypatch, tmp_path):
    captured: dict = {}
    workspace = RunWorkspace.create(tmp_path, run_id="20260923-101112-abcdef")

    def fake_pipeline(**kwargs):
        captured.update(kwargs)
        return PipelineResult(
            workspace=workspace,
            summary=RunSummary(run_id=workspace.run_id),
            findings=[],
            report_md=workspace.report_md_path,
            report_html=workspace.report_html_path,
        )

    monkeypatch.setattr(cli_module, "run_pipeline", fake_pipeline)
    runner.invoke(
        cli_module.app,
        [
            "run",
            "--url",
            "https://example.com/x.git",
            "--app-url",
            "http://localhost:3000",
            "--image",
            "some/image",
            "--max-pages",
            "7",
            "--no-launch",
            "--skip",
            "zap",
        ],
    )

    assert captured["url"] == "https://example.com/x.git"
    assert captured["image"] == "some/image"
    assert captured["launch"] is False
    assert captured["skip"] == frozenset({"zap"})
    assert captured["settings"].max_pages == 7


# --------------------------------------------------------------------------
# seed command
# --------------------------------------------------------------------------
def test_seed_reports_success(monkeypatch):
    monkeypatch.setattr(
        cli_module,
        "seed_all",
        lambda settings, **kwargs: [seed_module.SeedStep("x", True, "ok")],
    )

    outcome = runner.invoke(cli_module.app, ["seed"])

    assert outcome.exit_code == 0
    assert "Ready" in outcome.stdout


def test_seed_exits_non_zero_when_a_component_fails(monkeypatch):
    monkeypatch.setattr(
        cli_module,
        "seed_all",
        lambda settings, **kwargs: [seed_module.SeedStep("trivy database", False, "no disk")],
    )

    outcome = runner.invoke(cli_module.app, ["seed"])

    assert outcome.exit_code == 1
    assert "failed" in outcome.stdout.lower()


# --------------------------------------------------------------------------
# seed internals
# --------------------------------------------------------------------------
class FakeResponse:
    def __init__(self, text: str = "rules: []"):
        self.text = text

    def raise_for_status(self) -> None:
        return None


def test_semgrep_packs_are_downloaded_once(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")
    calls: list[str] = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return FakeResponse()

    monkeypatch.setattr(seed_module.httpx, "get", fake_get)

    step = seed_module.seed_semgrep_rules(settings)

    assert step.ok
    assert len(calls) == len(seed_module.SEMGREP_PACKS)
    assert (settings.semgrep_rules_dir / "default.yml").is_file()


def test_existing_semgrep_packs_are_not_re_downloaded(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")
    settings.semgrep_rules_dir.mkdir(parents=True)
    for pack in seed_module.SEMGREP_PACKS:
        (settings.semgrep_rules_dir / f"{pack}.yml").write_text("rules: []", encoding="utf-8")

    def fail(*args, **kwargs):
        raise AssertionError("should not download an existing pack")

    monkeypatch.setattr(seed_module.httpx, "get", fail)

    assert seed_module.seed_semgrep_rules(settings).ok


def test_force_re_downloads_semgrep_packs(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")
    settings.semgrep_rules_dir.mkdir(parents=True)
    (settings.semgrep_rules_dir / "default.yml").write_text("old", encoding="utf-8")
    monkeypatch.setattr(seed_module.httpx, "get", lambda url, **k: FakeResponse("new"))

    seed_module.seed_semgrep_rules(settings, force=True)

    assert (settings.semgrep_rules_dir / "default.yml").read_text(encoding="utf-8") == "new"


def test_a_download_failure_is_reported(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")

    def boom(url, **kwargs):
        raise RuntimeError("network down")

    monkeypatch.setattr(seed_module.httpx, "get", boom)

    step = seed_module.seed_semgrep_rules(settings)

    assert not step.ok
    assert "network down" in step.detail


def test_trivy_database_download_is_reported(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")

    def fake_run(argv, **kwargs):
        (settings.trivy_cache_dir / "db").mkdir(parents=True, exist_ok=True)
        (settings.trivy_cache_dir / "db" / "trivy.db").write_bytes(b"x" * 2048)
        return command_result()

    monkeypatch.setattr(seed_module, "resolve_executable", lambda *a, **k: "trivy")
    monkeypatch.setattr(seed_module, "run_command", fake_run)

    step = seed_module.seed_trivy_db(settings)

    assert step.ok
    assert "MB" in step.detail


def test_trivy_seed_fails_without_the_binary(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")
    monkeypatch.setattr(seed_module, "resolve_executable", lambda *a, **k: None)

    assert not seed_module.seed_trivy_db(settings).ok


def test_osv_databases_are_seeded_per_ecosystem(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")
    seen: list[Path] = []

    def fake_run(argv, **kwargs):
        # OSV only downloads the ecosystems it actually encounters, so the
        # seed writes a synthetic manifest for each one.
        seen.append(Path(argv[-1]))
        return command_result(returncode=1)  # 1 = vulnerabilities found

    monkeypatch.setattr(seed_module, "resolve_executable", lambda *a, **k: "osv-scanner")
    monkeypatch.setattr(seed_module, "run_command", fake_run)

    step = seed_module.seed_osv_db(settings, ecosystems=("npm", "PyPI"))

    assert step.ok
    assert len(seen) == 2


def test_osv_seed_reports_a_failing_ecosystem(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")
    monkeypatch.setattr(seed_module, "resolve_executable", lambda *a, **k: "osv-scanner")
    monkeypatch.setattr(seed_module, "run_command", lambda *a, **k: command_result(returncode=127))

    step = seed_module.seed_osv_db(settings, ecosystems=("npm",))

    assert not step.ok
    assert "npm" in step.detail


def test_lighthouse_seed_is_skipped_when_already_installed(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")
    settings.lighthouse_cli.parent.mkdir(parents=True)
    settings.lighthouse_cli.write_text("// lighthouse", encoding="utf-8")

    monkeypatch.setattr(
        seed_module, "resolve_executable", lambda *a, **k: pytest.fail("npm should not run")
    )

    assert seed_module.seed_lighthouse(settings).ok


def test_lighthouse_seed_fails_when_npm_is_missing(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")
    monkeypatch.setattr(seed_module, "resolve_executable", lambda *a, **k: None)

    step = seed_module.seed_lighthouse(settings)

    assert not step.ok
    assert "npm" in step.detail


def test_zap_image_is_not_pulled_when_present(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")
    calls: list[list[str]] = []

    def fake_run(argv, **kwargs):
        calls.append(list(argv))
        return command_result()  # 'image inspect' succeeds

    monkeypatch.setattr(seed_module, "resolve_executable", lambda *a, **k: "docker")
    monkeypatch.setattr(seed_module, "run_command", fake_run)

    step = seed_module.seed_zap_image(settings)

    assert step.ok
    assert len(calls) == 1  # inspect only, no pull


def test_zap_image_is_pulled_when_absent(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")
    responses = iter([command_result(1), command_result(0)])

    monkeypatch.setattr(seed_module, "resolve_executable", lambda *a, **k: "docker")
    monkeypatch.setattr(seed_module, "run_command", lambda *a, **k: next(responses))

    step = seed_module.seed_zap_image(settings)

    assert step.ok
    assert "pulled" in step.detail


def test_seed_can_provision_selected_components_only(tmp_path, monkeypatch):
    # The container build bakes in rules and databases but cannot pull the ZAP
    # image, so it seeds only the components it can.
    settings = Settings(data_dir=tmp_path / "data")
    monkeypatch.setattr(seed_module.httpx, "get", lambda url, **k: FakeResponse())

    steps = seed_module.seed_all(settings, components=("semgrep",))

    assert [step.name for step in steps] == ["semgrep rules"]


def test_seed_rejects_an_unknown_component(tmp_path):
    with pytest.raises(ValueError, match="unknown component"):
        seed_module.seed_all(Settings(data_dir=tmp_path / "data"), components=("nope",))


def test_seed_command_reports_an_unknown_component():
    outcome = runner.invoke(cli_module.app, ["seed", "--component", "nope"])
    assert outcome.exit_code == 2


def test_seed_all_continues_past_individual_failures(tmp_path, monkeypatch):
    settings = Settings(data_dir=tmp_path / "data")
    monkeypatch.setattr(seed_module, "resolve_executable", lambda *a, **k: None)
    monkeypatch.setattr(seed_module.httpx, "get", lambda url, **k: FakeResponse())

    steps = seed_module.seed_all(settings)

    # Every component is attempted even though most cannot succeed here.
    assert len(steps) == 5
    assert any(step.ok for step in steps)
    assert any(not step.ok for step in steps)
