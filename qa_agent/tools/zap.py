"""OWASP ZAP adapter: a passive baseline security scan of the running app.

ZAP runs as a container, which creates one wrinkle worth understanding: inside
that container, ``localhost`` is the container itself, not the machine running
it. A target of ``http://localhost:3000`` would therefore scan nothing. Docker
Desktop publishes ``host.docker.internal`` for exactly this, so the adapter
rewrites loopback targets before handing them to ZAP.

Only the *baseline* scan is used. It spiders and observes traffic rather than
attacking, which is the right trade-off for a QA tool that may be pointed at
someone's development environment.
"""

from __future__ import annotations

import shutil
import time
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from qa_agent.logging_setup import get_logger
from qa_agent.models.run import Verdict
from qa_agent.parsers.zap import parse_zap
from qa_agent.tools.base import ScanOutcome, ToolContext, load_json
from qa_agent.tools.process import resolve_executable, run_command

log = get_logger(__name__)

TOOL = "zap"
REPORT_NAME = "zap.json"
# Passive-scan budget, in minutes, after the spider finishes.
PASSIVE_SCAN_MINUTES = "2"
# Container wall-clock limit: image start-up plus spider plus passive scan.
ZAP_TIMEOUT_S = 900
# Removing a stuck container should take seconds.
CLEANUP_TIMEOUT_S = 60
# World-writable with the sticky bit, like /tmp.
SHARED_DIR_MODE = 0o1777

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def rewrite_for_container(url: str, gateway_host: str) -> str:
    """Rewrite a loopback URL so a container can reach the host machine."""
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() not in _LOOPBACK_HOSTS:
        return url
    netloc = gateway_host + (f":{parsed.port}" if parsed.port else "")
    return urlunparse(parsed._replace(netloc=netloc))


def run_zap_baseline(url: str, ctx: ToolContext) -> ScanOutcome:
    """Run ``zap-baseline.py`` against *url* and return unified findings."""
    settings = ctx.settings
    docker = resolve_executable(settings.docker_bin, [settings.vendor_bin_dir])
    if docker is None:
        return ScanOutcome.skipped(TOOL, "docker is not installed (see check_env)")

    work_dir: Path = ctx.workspace.raw_dir
    work_dir.mkdir(parents=True, exist_ok=True)
    report = work_dir / REPORT_NAME
    target = rewrite_for_container(url, settings.docker_gateway_host)

    if settings.zap_exchange_volume:
        # Running inside a container: share a named volume with ZAP (see the
        # zap_exchange_volume setting for why a bind mount cannot work here).
        report_name = f"{ctx.workspace.run_id}-zap.json"
        mount = f"{settings.zap_exchange_volume}:/zap/wrk/:rw"
        produced = settings.zap_exchange_dir / report_name
        # ZAP runs as an unprivileged user and the volume is created root-owned;
        # the sticky bit keeps users from deleting each other's files.
        settings.zap_exchange_dir.chmod(SHARED_DIR_MODE)
    else:
        # On a workstation: map the run's raw directory straight into ZAP.
        report_name = REPORT_NAME
        mount = f"{work_dir}:/zap/wrk/:rw"
        produced = report

    # A fixed name lets a timed-out container be found and removed.
    container = f"qa-agent-zap-{ctx.workspace.run_id}"
    argv = [
        docker,
        "run",
        "--rm",
        "--name",
        container,
        "-v",
        mount,
        settings.zap_image,
        "zap-baseline.py",
        "-t",
        target,
        "-J",
        report_name,
        # Report warnings without turning them into a non-zero exit status.
        "-I",
        "-m",
        PASSIVE_SCAN_MINUTES,
        # Without -silent, zap-baseline downloads add-on updates from the
        # internet on every scan. Found by the evaluation: on a slow link that
        # made scan time vary from 2 to over 15 minutes.
        "-z",
        "-silent",
    ]

    log.info("running ZAP baseline against %s", target)
    started = time.perf_counter()
    result = run_command(argv, timeout=ZAP_TIMEOUT_S, log_path=ctx.command_log)
    elapsed = time.perf_counter() - started

    if result.timed_out:
        # Killing the docker client does not stop the container it started.
        run_command(
            [docker, "rm", "-f", container], timeout=CLEANUP_TIMEOUT_S, log_path=ctx.command_log
        )
        return ScanOutcome.of(
            TOOL,
            Verdict.TIMEOUT,
            duration_s=elapsed,
            detail=f"ZAP exceeded {ZAP_TIMEOUT_S}s and was stopped",
        )

    if produced != report and produced.exists():
        # Bring the report from the shared volume into the run's raw folder.
        shutil.copyfile(produced, report)
        produced.unlink(missing_ok=True)

    if not report.exists():
        return ScanOutcome.failed(
            TOOL,
            f"ZAP produced no report (exit {result.returncode}): "
            f"{(result.stderr or result.stdout).strip()[-300:]}",
            elapsed,
        )

    try:
        payload = load_json(report)
    except ValueError as exc:
        return ScanOutcome.failed(TOOL, f"ZAP report was not valid JSON: {exc}", elapsed)

    findings = parse_zap(payload, target_url=target)
    log.info("zap: %d finding(s) in %.1fs", len(findings), elapsed)
    return ScanOutcome.of(
        TOOL,
        Verdict.OK,
        findings=findings,
        duration_s=elapsed,
        detail=f"baseline scan of {target}",
        raw_output=str(report),
    )
