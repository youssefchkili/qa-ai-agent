"""Tests for the tool adapters, the launcher and the pipeline.

No scanner, browser, container or network is used. Every subprocess is
replaced with a fake that returns a chosen exit code and writes chosen output,
which is what lets these paths be tested at all: the interesting behaviour of
an adapter is how it reacts to *failure*, and real tools are hard to make fail
on demand.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from qa_agent.config import Settings
from qa_agent.models.run import Verdict
from qa_agent.tools import lighthouse as lighthouse_tool
from qa_agent.tools import osv as osv_tool
from qa_agent.tools import semgrep as semgrep_tool
from qa_agent.tools import trivy as trivy_tool
from qa_agent.tools import zap as zap_tool
from qa_agent.tools.base import ScanOutcome, ToolContext, load_json
from qa_agent.tools.process import CommandResult
from qa_agent.web.page_model import is_hash_route, normalize_url, same_origin, strip_fragment
from qa_agent.workspace import RunWorkspace


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------
def result(returncode: int = 0, stdout: str = "", stderr: str = "", timed_out: bool = False):
    return CommandResult(
        argv=("fake",),
        returncode=returncode,
        stdout=stdout,
        stderr=stderr,
        duration_s=0.1,
        timed_out=timed_out,
    )


@pytest.fixture
def context(tmp_path) -> ToolContext:
    """A tool context whose data directory is an empty temporary tree."""
    settings = Settings(data_dir=tmp_path / "data")
    workspace = RunWorkspace.create(settings.workspace_dir, run_id="20260923-101112-abcdef")
    return ToolContext(settings=settings, workspace=workspace)


@pytest.fixture
def provisioned(context) -> ToolContext:
    """A context where seed has 'already run', so offline data exists."""
    context.settings.semgrep_rules_dir.mkdir(parents=True, exist_ok=True)
    (context.settings.semgrep_rules_dir / "default.yml").write_text("rules: []", encoding="utf-8")
    context.settings.trivy_cache_dir.mkdir(parents=True, exist_ok=True)
    context.settings.osv_db_dir.mkdir(parents=True, exist_ok=True)
    return context


# --------------------------------------------------------------------------
# shared plumbing
# --------------------------------------------------------------------------
def test_load_json_tolerates_a_byte_order_mark(tmp_path):
    path = tmp_path / "a.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"ok": True}).encode("utf-8"))

    assert load_json(path) == {"ok": True}


def test_load_json_survives_invalid_utf8_in_tool_output(tmp_path):
    # Semgrep quoting non-UTF-8 source produced exactly this in a real run.
    path = tmp_path / "a.json"
    path.write_bytes(b'{"msg": "caf\x97"}')

    assert "caf" in load_json(path)["msg"]


def test_load_json_of_an_empty_file_is_none(tmp_path):
    path = tmp_path / "a.json"
    path.write_text("   ", encoding="utf-8")

    assert load_json(path) is None


def test_scan_outcome_helpers_carry_the_right_verdicts():
    assert ScanOutcome.skipped("x", "why").run.verdict == Verdict.SKIPPED
    assert ScanOutcome.not_applicable("x", "why").run.verdict == Verdict.NOT_APPLICABLE
    assert ScanOutcome.failed("x", "why").run.verdict == Verdict.FAILED
    assert ScanOutcome.skipped("x", "why").findings == []


def test_scan_outcome_counts_its_findings():
    from qa_agent.models.finding import Category, Finding, Severity, Tool

    finding = Finding(
        tool=Tool.SEMGREP, category=Category.CODE, severity=Severity.LOW, title="t", rule_id="r"
    )
    outcome = ScanOutcome.of("semgrep", Verdict.OK, findings=[finding])
    assert outcome.run.findings_count == 1


# --------------------------------------------------------------------------
# semgrep adapter
# --------------------------------------------------------------------------
def test_semgrep_is_skipped_when_not_installed(context, monkeypatch):
    monkeypatch.setattr(semgrep_tool, "resolve_executable", lambda *a, **k: None)

    outcome = semgrep_tool.run_semgrep(Path("."), context)

    assert outcome.run.verdict == Verdict.SKIPPED
    assert "not installed" in outcome.run.detail


def test_semgrep_is_skipped_without_offline_rules(context, monkeypatch):
    monkeypatch.setattr(semgrep_tool, "resolve_executable", lambda *a, **k: "semgrep")

    outcome = semgrep_tool.run_semgrep(Path("."), context)

    assert outcome.run.verdict == Verdict.SKIPPED
    assert "seed" in outcome.run.detail


def test_semgrep_parses_findings_it_produced(provisioned, monkeypatch, tmp_path):
    payload = {
        "results": [
            {
                "check_id": "rule.id",
                "path": "a.js",
                "start": {"line": 3},
                "end": {"line": 3},
                "extra": {"severity": "ERROR", "message": "bad", "metadata": {}},
            }
        ],
        "errors": [],
    }

    def fake_run(argv, **kwargs):
        provisioned.workspace.raw_path("semgrep").write_text(json.dumps(payload), encoding="utf-8")
        return result(returncode=1)  # semgrep exits 1 simply because it found something

    monkeypatch.setattr(semgrep_tool, "resolve_executable", lambda *a, **k: "semgrep")
    monkeypatch.setattr(semgrep_tool, "run_command", fake_run)

    outcome = semgrep_tool.run_semgrep(tmp_path, provisioned)

    assert outcome.run.verdict == Verdict.OK
    assert len(outcome.findings) == 1


def test_semgrep_reports_a_timeout(provisioned, monkeypatch, tmp_path):
    monkeypatch.setattr(semgrep_tool, "resolve_executable", lambda *a, **k: "semgrep")
    monkeypatch.setattr(semgrep_tool, "run_command", lambda *a, **k: result(timed_out=True))

    assert semgrep_tool.run_semgrep(tmp_path, provisioned).run.verdict == Verdict.TIMEOUT


def test_semgrep_fails_when_it_writes_nothing(provisioned, monkeypatch, tmp_path):
    monkeypatch.setattr(semgrep_tool, "resolve_executable", lambda *a, **k: "semgrep")
    monkeypatch.setattr(semgrep_tool, "run_command", lambda *a, **k: result(2, stderr="boom"))

    outcome = semgrep_tool.run_semgrep(tmp_path, provisioned)

    assert outcome.run.verdict == Verdict.FAILED
    assert "boom" in outcome.run.detail


def test_semgrep_fails_on_malformed_json(provisioned, monkeypatch, tmp_path):
    def fake_run(argv, **kwargs):
        provisioned.workspace.raw_path("semgrep").write_text("{not json", encoding="utf-8")
        return result()

    monkeypatch.setattr(semgrep_tool, "resolve_executable", lambda *a, **k: "semgrep")
    monkeypatch.setattr(semgrep_tool, "run_command", fake_run)

    assert semgrep_tool.run_semgrep(tmp_path, provisioned).run.verdict == Verdict.FAILED


def test_semgrep_runs_offline_and_without_telemetry(provisioned, monkeypatch, tmp_path):
    captured: list[list[str]] = []

    def fake_run(argv, **kwargs):
        captured.append(list(argv))
        provisioned.workspace.raw_path("semgrep").write_text("{}", encoding="utf-8")
        return result()

    monkeypatch.setattr(semgrep_tool, "resolve_executable", lambda *a, **k: "semgrep")
    monkeypatch.setattr(semgrep_tool, "run_command", fake_run)
    semgrep_tool.run_semgrep(tmp_path, provisioned)

    argv = captured[0]
    assert "--metrics=off" in argv
    assert "--disable-version-check" in argv
    assert "auto" not in argv  # never the online registry


# --------------------------------------------------------------------------
# trivy adapter
# --------------------------------------------------------------------------
def test_trivy_is_skipped_when_not_installed(context, monkeypatch):
    monkeypatch.setattr(trivy_tool, "resolve_executable", lambda *a, **k: None)
    assert trivy_tool.run_trivy_fs(Path("."), context).run.verdict == Verdict.SKIPPED


def test_trivy_is_skipped_without_a_local_database(context, monkeypatch):
    monkeypatch.setattr(trivy_tool, "resolve_executable", lambda *a, **k: "trivy")
    outcome = trivy_tool.run_trivy_fs(Path("."), context)
    assert outcome.run.verdict == Verdict.SKIPPED
    assert "seed" in outcome.run.detail


def test_trivy_parses_its_output(provisioned, monkeypatch, tmp_path):
    payload = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {"ID": "DS-0001", "Title": "latest tag", "Severity": "MEDIUM"}
                ],
            }
        ]
    }

    def fake_run(argv, **kwargs):
        provisioned.workspace.raw_path("trivy").write_text(json.dumps(payload), encoding="utf-8")
        return result()

    monkeypatch.setattr(trivy_tool, "resolve_executable", lambda *a, **k: "trivy")
    monkeypatch.setattr(trivy_tool, "run_command", fake_run)

    outcome = trivy_tool.run_trivy_fs(tmp_path, provisioned)

    assert outcome.run.verdict == Verdict.OK
    assert len(outcome.findings) == 1


def test_trivy_offline_flags_disable_updates_and_telemetry(provisioned, monkeypatch, tmp_path):
    captured: list[list[str]] = []

    def fake_run(argv, **kwargs):
        captured.append(list(argv))
        provisioned.workspace.raw_path("trivy").write_text("{}", encoding="utf-8")
        return result()

    monkeypatch.setattr(trivy_tool, "resolve_executable", lambda *a, **k: "trivy")
    monkeypatch.setattr(trivy_tool, "run_command", fake_run)
    trivy_tool.run_trivy_fs(tmp_path, provisioned)

    argv = captured[0]
    assert "--skip-db-update" in argv
    assert "--disable-telemetry" in argv
    assert "--offline-scan" in argv
    # Found on a real project: Trivy crashed walking a Python virtualenv.
    skipped = [argv[i + 1] for i, arg in enumerate(argv) if arg == "--skip-dirs"]
    assert "**/.venv" in skipped and "**/node_modules" in skipped


def test_trivy_image_scan_writes_its_own_raw_file(provisioned, monkeypatch):
    def fake_run(argv, **kwargs):
        provisioned.workspace.raw_path("trivy-image").write_text("{}", encoding="utf-8")
        return result()

    monkeypatch.setattr(trivy_tool, "resolve_executable", lambda *a, **k: "trivy")
    monkeypatch.setattr(trivy_tool, "run_command", fake_run)

    outcome = trivy_tool.run_trivy_image("some/image", provisioned)

    assert outcome.run.verdict == Verdict.OK
    assert provisioned.workspace.raw_path("trivy-image").is_file()


# --------------------------------------------------------------------------
# osv adapter
# --------------------------------------------------------------------------
def test_osv_treats_exit_128_as_no_manifest_found(provisioned, monkeypatch, tmp_path):
    monkeypatch.setattr(osv_tool, "resolve_executable", lambda *a, **k: "osv-scanner")
    monkeypatch.setattr(osv_tool, "run_command", lambda *a, **k: result(128))

    outcome = osv_tool.run_osv_source(tmp_path, provisioned)

    # Not a failure: there was simply no lockfile to analyse.
    assert outcome.run.verdict == Verdict.NOT_APPLICABLE
    assert "lockfile" in outcome.run.detail


def test_osv_exit_1_means_vulnerabilities_found(provisioned, monkeypatch, tmp_path):
    monkeypatch.setattr(osv_tool, "resolve_executable", lambda *a, **k: "osv-scanner")
    monkeypatch.setattr(
        osv_tool, "run_command", lambda *a, **k: result(1, stdout=json.dumps({"results": []}))
    )

    assert osv_tool.run_osv_source(tmp_path, provisioned).run.verdict == Verdict.OK


def test_osv_other_exit_codes_are_failures(provisioned, monkeypatch, tmp_path):
    monkeypatch.setattr(osv_tool, "resolve_executable", lambda *a, **k: "osv-scanner")
    monkeypatch.setattr(osv_tool, "run_command", lambda *a, **k: result(127, stderr="bad flag"))

    outcome = osv_tool.run_osv_source(tmp_path, provisioned)

    assert outcome.run.verdict == Verdict.FAILED
    assert "bad flag" in outcome.run.detail


def test_osv_source_scan_pins_the_data_source(provisioned, monkeypatch, tmp_path):
    captured: list[list[str]] = []

    def fake_run(argv, **kwargs):
        captured.append(list(argv))
        return result(0, stdout="{}")

    monkeypatch.setattr(osv_tool, "resolve_executable", lambda *a, **k: "osv-scanner")
    monkeypatch.setattr(osv_tool, "run_command", fake_run)
    osv_tool.run_osv_source(tmp_path, provisioned)

    assert "--offline-vulnerabilities" in captured[0]
    assert "--data-source" in captured[0]  # stops OSV querying deps.dev
    # Found by the evaluation: resolving requirements.txt transitively queries
    # PyPI, so results depended on whether that network call succeeded.
    assert "--no-resolve" in captured[0]


def test_osv_image_scan_omits_the_data_source_flag(provisioned, monkeypatch):
    captured: list[list[str]] = []

    def fake_run(argv, **kwargs):
        captured.append(list(argv))
        return result(0, stdout="{}")

    monkeypatch.setattr(osv_tool, "resolve_executable", lambda *a, **k: "osv-scanner")
    monkeypatch.setattr(osv_tool, "run_command", fake_run)
    osv_tool.run_osv_image("some/image", provisioned)

    # 'scan image' does not define --data-source; passing it is a usage error.
    assert "--data-source" not in captured[0]
    assert "--offline-vulnerabilities" in captured[0]


def test_osv_is_skipped_without_an_offline_database(context, monkeypatch, tmp_path):
    monkeypatch.setattr(osv_tool, "resolve_executable", lambda *a, **k: "osv-scanner")
    assert osv_tool.run_osv_source(tmp_path, context).run.verdict == Verdict.SKIPPED


def test_untagged_images_gain_an_explicit_latest_tag():
    # OSV-Scanner refuses a bare name with "is not a tagged image name",
    # even though Docker treats it as :latest.
    assert osv_tool.normalize_image_ref("bkimminich/juice-shop") == (
        "bkimminich/juice-shop:latest"
    )


def test_an_existing_tag_or_digest_is_left_alone():
    assert osv_tool.normalize_image_ref("nginx:1.25") == "nginx:1.25"
    assert osv_tool.normalize_image_ref("nginx@sha256:abc") == "nginx@sha256:abc"


def test_a_registry_port_is_not_mistaken_for_a_tag():
    assert osv_tool.normalize_image_ref("registry.local:5000/app") == (
        "registry.local:5000/app:latest"
    )


def test_osv_image_scan_uses_the_normalised_reference(provisioned, monkeypatch):
    captured: list[list[str]] = []

    def fake_run(argv, **kwargs):
        captured.append(list(argv))
        return result(0, stdout="{}")

    monkeypatch.setattr(osv_tool, "resolve_executable", lambda *a, **k: "osv-scanner")
    monkeypatch.setattr(osv_tool, "run_command", fake_run)
    osv_tool.run_osv_image("bkimminich/juice-shop", provisioned)

    assert captured[0][-1] == "bkimminich/juice-shop:latest"


# --------------------------------------------------------------------------
# lighthouse adapter
# --------------------------------------------------------------------------
def test_lighthouse_is_skipped_when_not_installed(context):
    outcome = lighthouse_tool.run_lighthouse("http://localhost:3000", context)

    assert outcome.run.verdict == Verdict.SKIPPED
    assert "seed" in outcome.run.detail


def test_lighthouse_accepts_a_report_written_despite_a_non_zero_exit(context, monkeypatch):
    # On Windows, Chrome's launcher often fails to delete its temp profile and
    # exits non-zero after writing a perfectly good report.
    cli = context.settings.lighthouse_cli
    cli.parent.mkdir(parents=True, exist_ok=True)
    cli.write_text("// lighthouse", encoding="utf-8")

    payload = {
        "categories": {"performance": {"title": "Performance", "score": 0.2, "auditRefs": []}},
        "audits": {},
    }

    def fake_run(argv, **kwargs):
        context.workspace.raw_path("lighthouse-00").write_text(
            json.dumps(payload), encoding="utf-8"
        )
        return result(1, stderr="EPERM: operation not permitted, rm")

    monkeypatch.setattr(lighthouse_tool, "resolve_executable", lambda *a, **k: "node")
    monkeypatch.setattr(lighthouse_tool, "run_command", fake_run)
    monkeypatch.setattr(lighthouse_tool, "chromium_path", lambda: "")

    outcome = lighthouse_tool.run_lighthouse("http://localhost:3000", context)

    assert outcome.run.verdict == Verdict.OK
    assert len(outcome.findings) == 1
    assert "exited non-zero" in outcome.run.detail


def test_lighthouse_fails_when_no_report_appears(context, monkeypatch):
    cli = context.settings.lighthouse_cli
    cli.parent.mkdir(parents=True, exist_ok=True)
    cli.write_text("// lighthouse", encoding="utf-8")

    monkeypatch.setattr(lighthouse_tool, "resolve_executable", lambda *a, **k: "node")
    monkeypatch.setattr(lighthouse_tool, "run_command", lambda *a, **k: result(1, stderr="nope"))
    monkeypatch.setattr(lighthouse_tool, "chromium_path", lambda: "")

    assert lighthouse_tool.run_lighthouse("http://x", context).run.verdict == Verdict.FAILED


# --------------------------------------------------------------------------
# zap adapter
# --------------------------------------------------------------------------
def test_zap_is_skipped_without_docker(context, monkeypatch):
    monkeypatch.setattr(zap_tool, "resolve_executable", lambda *a, **k: None)
    assert zap_tool.run_zap_baseline("http://localhost:3000", context).run.verdict == (
        Verdict.SKIPPED
    )


def test_zap_parses_the_report_it_mounted(context, monkeypatch):
    payload = {
        "site": [
            {
                "@name": "http://host.docker.internal:3000",
                "alerts": [
                    {"pluginid": "1", "alert": "X", "riskcode": "3", "instances": [], "count": "1"}
                ],
            }
        ]
    }

    def fake_run(argv, **kwargs):
        (context.workspace.raw_dir / zap_tool.REPORT_NAME).write_text(
            json.dumps(payload), encoding="utf-8"
        )
        return result()

    monkeypatch.setattr(zap_tool, "resolve_executable", lambda *a, **k: "docker")
    monkeypatch.setattr(zap_tool, "run_command", fake_run)

    outcome = zap_tool.run_zap_baseline("http://localhost:3000", context)

    assert outcome.run.verdict == Verdict.OK
    assert len(outcome.findings) == 1


def test_zap_uses_a_shared_volume_when_running_inside_a_container(tmp_path, monkeypatch):
    # Through the Docker socket a bind-mount path is resolved on the host, where
    # the agent container's workspace does not exist; a named volume works.
    exchange = tmp_path / "exchange"
    exchange.mkdir()
    settings = Settings(
        data_dir=tmp_path / "data",
        zap_exchange_volume="qa-agent-zap-exchange",
        zap_exchange_dir=exchange,
    )
    workspace = RunWorkspace.create(settings.workspace_dir, run_id="20260930-101112-abcdef")
    ctx = ToolContext(settings=settings, workspace=workspace)
    captured: list[list[str]] = []

    def fake_run(argv, **kwargs):
        captured.append(list(argv))
        (exchange / "20260930-101112-abcdef-zap.json").write_text(
            json.dumps({"site": []}), encoding="utf-8"
        )
        return result()

    monkeypatch.setattr(zap_tool, "resolve_executable", lambda *a, **k: "docker")
    monkeypatch.setattr(zap_tool, "run_command", fake_run)

    modes: list[int] = []
    monkeypatch.setattr(zap_tool.Path, "chmod", lambda self, mode: modes.append(mode))

    outcome = zap_tool.run_zap_baseline("http://host.docker.internal:3000", ctx)

    assert outcome.run.verdict == Verdict.OK
    assert "qa-agent-zap-exchange:/zap/wrk/:rw" in captured[0]
    # Found by the Docker smoke test: ZAP runs as an unprivileged user and
    # could not write into the root-owned volume.
    assert modes == [0o1777]
    # The report was moved from the shared volume into the run's raw folder.
    assert (workspace.raw_dir / zap_tool.REPORT_NAME).is_file()
    assert not (exchange / "20260930-101112-abcdef-zap.json").exists()


def test_a_timed_out_zap_container_is_removed(context, monkeypatch):
    # Found by the evaluation: killing the docker client on timeout left the
    # ZAP container scanning in the background for over an hour.
    captured: list[list[str]] = []

    def fake_run(argv, **kwargs):
        captured.append(list(argv))
        return result(timed_out=True) if argv[1] == "run" else result()

    monkeypatch.setattr(zap_tool, "resolve_executable", lambda *a, **k: "docker")
    monkeypatch.setattr(zap_tool, "run_command", fake_run)

    outcome = zap_tool.run_zap_baseline("http://localhost:3000", context)

    assert outcome.run.verdict == Verdict.TIMEOUT
    # Without -silent, zap-baseline downloads add-on updates on every scan.
    assert captured[0][captured[0].index("-z") + 1] == "-silent"
    name = captured[0][captured[0].index("--name") + 1]
    assert context.workspace.run_id in name
    assert captured[1][1:] == ["rm", "-f", name]


def test_zap_fails_when_the_container_writes_nothing(context, monkeypatch):
    monkeypatch.setattr(zap_tool, "resolve_executable", lambda *a, **k: "docker")
    monkeypatch.setattr(zap_tool, "run_command", lambda *a, **k: result(3, stderr="no route"))

    outcome = zap_tool.run_zap_baseline("http://localhost:3000", context)

    assert outcome.run.verdict == Verdict.FAILED
    assert "no route" in outcome.run.detail


# --------------------------------------------------------------------------
# url handling
# --------------------------------------------------------------------------
def test_hash_routes_are_treated_as_distinct_pages():
    # A single-page app keeps its whole route in the fragment.
    assert normalize_url("http://localhost:3000/#/login") == "http://localhost:3000/#/login"
    assert is_hash_route("http://localhost:3000/#/login")


def test_plain_anchors_are_discarded():
    assert normalize_url("http://localhost:3000/page#section") == "http://localhost:3000/page"
    assert not is_hash_route("http://localhost:3000/page#section")


def test_relative_links_resolve_against_the_page():
    assert normalize_url("/about", base="http://localhost:3000/shop") == (
        "http://localhost:3000/about"
    )


def test_non_http_schemes_are_rejected():
    assert normalize_url("mailto:a@b.com") == ""
    assert normalize_url("javascript:alert(1)") == ""


def test_trailing_slashes_and_case_are_normalised():
    assert normalize_url("http://LOCALHOST:3000/a/") == "http://localhost:3000/a"


def test_same_origin_compares_scheme_and_host():
    assert same_origin("http://localhost:3000/a", "http://localhost:3000/b")
    assert not same_origin("http://localhost:3000/a", "http://localhost:4000/a")
    assert not same_origin("http://localhost:3000/a", "https://localhost:3000/a")


def test_strip_fragment_returns_what_the_server_sees():
    assert strip_fragment("http://localhost:3000/#/login") == "http://localhost:3000/"


# --------------------------------------------------------------------------
# launcher
# --------------------------------------------------------------------------
def test_compose_file_is_preferred_over_a_dockerfile(tmp_path):
    from qa_agent.input.launcher import detect_launch_method

    (tmp_path / "Dockerfile").write_text("FROM node", encoding="utf-8")
    (tmp_path / "docker-compose.yml").write_text("services: {}", encoding="utf-8")

    method, path = detect_launch_method(tmp_path)

    assert method == "compose"
    assert path.name == "docker-compose.yml"


def test_dockerfile_is_used_when_there_is_no_compose_file(tmp_path):
    from qa_agent.input.launcher import detect_launch_method

    (tmp_path / "Dockerfile").write_text("FROM node", encoding="utf-8")

    assert detect_launch_method(tmp_path)[0] == "dockerfile"


def test_a_repository_with_neither_cannot_be_launched(tmp_path):
    from qa_agent.input.launcher import detect_launch_method, launch_app

    assert detect_launch_method(tmp_path) == ("", None)

    app = launch_app(tmp_path, docker_bin="docker", run_id="r", timeout_s=1)
    assert not app.ok
    assert "no docker-compose.yml or Dockerfile" in app.detail


def test_wait_for_http_gives_up_after_the_deadline(monkeypatch):
    import httpx

    from qa_agent.input import launcher

    def always_fail(*args, **kwargs):
        raise httpx.ConnectError("refused")

    monkeypatch.setattr(launcher.httpx, "get", always_fail)
    monkeypatch.setattr(launcher.time, "sleep", lambda _: None)

    assert launcher.wait_for_http("http://localhost:1", timeout_s=0.01) is False


def test_wait_for_http_accepts_any_status(monkeypatch):
    from qa_agent.input import launcher

    # A 500 still proves something is listening; the crawler records the rest.
    monkeypatch.setattr(launcher.httpx, "get", lambda *a, **k: object())

    assert launcher.wait_for_http("http://localhost:3000", timeout_s=1) is True


# --------------------------------------------------------------------------
# repository input
# --------------------------------------------------------------------------
def test_clone_failure_is_reported_clearly(tmp_path, monkeypatch):
    from qa_agent.input import repo

    monkeypatch.setattr(repo, "resolve_executable", lambda *a, **k: "git")
    monkeypatch.setattr(repo, "run_command", lambda *a, **k: result(128, stderr="not found"))

    with pytest.raises(repo.CloneFailed) as error:
        repo.clone_repo("https://example.com/x.git", tmp_path / "repo")

    assert "not found" in str(error.value)


def test_clone_timeout_is_reported_clearly(tmp_path, monkeypatch):
    from qa_agent.input import repo

    monkeypatch.setattr(repo, "resolve_executable", lambda *a, **k: "git")
    monkeypatch.setattr(repo, "run_command", lambda *a, **k: result(timed_out=True))

    with pytest.raises(repo.CloneFailed) as error:
        repo.clone_repo("https://example.com/x.git", tmp_path / "repo", timeout=5)

    assert "timed out" in str(error.value)


def test_clone_uses_long_paths_and_blocks_credential_prompts(tmp_path, monkeypatch):
    from qa_agent.input import repo

    # Cloning issues two git commands (clone, then rev-parse), so every call
    # is recorded and the first one is the one under test.
    calls: list[dict] = []

    def fake_run(argv, **kwargs):
        calls.append({"argv": list(argv), "env": kwargs.get("env") or {}})
        return result()

    monkeypatch.setattr(repo, "resolve_executable", lambda *a, **k: "git")
    monkeypatch.setattr(repo, "run_command", fake_run)
    repo.clone_repo("https://example.com/x.git", tmp_path / "repo")

    clone = calls[0]
    assert "core.longpaths=true" in clone["argv"]  # Windows MAX_PATH
    assert "--depth" in clone["argv"]
    assert clone["env"]["GIT_TERMINAL_PROMPT"] == "0"  # never hang on a prompt
    assert calls[1]["argv"][-1] == "HEAD"  # the commit lookup


def test_local_directory_is_used_in_place(tmp_path):
    from qa_agent.input.repo import use_local_path

    tree = use_local_path(tmp_path)

    assert tree.path == tmp_path.resolve()


def test_missing_local_directory_is_rejected(tmp_path):
    from qa_agent.input.repo import CloneFailed, use_local_path

    with pytest.raises(CloneFailed):
        use_local_path(tmp_path / "nope")


# --------------------------------------------------------------------------
# pipeline
# --------------------------------------------------------------------------
def test_pipeline_produces_a_report_even_when_every_stage_is_skipped(tmp_path):
    from qa_agent.pipeline import run_pipeline

    source = tmp_path / "project"
    source.mkdir()
    (source / "main.py").write_text("print('hi')", encoding="utf-8")

    settings = Settings(data_dir=tmp_path / "data")
    outcome = run_pipeline(
        settings=settings,
        url=str(source),
        launch=False,
        skip=frozenset({"semgrep", "trivy", "osv", "crawler", "axe", "lighthouse", "zap"}),
        use_llm=False,  # tests never depend on a live model
    )

    assert outcome.report_html.is_file()
    assert outcome.report_md.is_file()
    assert outcome.workspace.findings_path.is_file()
    assert outcome.findings == []
    # The report must say that nothing dynamic ran, not imply a clean result.
    assert any("only static analysis" in note for note in outcome.summary.notes)


def test_pipeline_refuses_a_public_target(tmp_path):
    from qa_agent.pipeline import run_pipeline

    settings = Settings(data_dir=tmp_path / "data", allow_public_targets=False)
    outcome = run_pipeline(
        settings=settings, app_url="http://8.8.8.8", launch=False, use_llm=False
    )

    crawler = next(t for t in outcome.summary.tool_runs if t.tool == "crawler")
    assert crawler.verdict == Verdict.SKIPPED
    assert "refusing to" in crawler.detail
