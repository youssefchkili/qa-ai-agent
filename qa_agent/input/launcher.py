"""Bring the application under test up from its own repository.

If the repository ships a ``docker-compose.yml`` or a ``Dockerfile``, the agent
can start it and then point the dynamic half of the pipeline at the result.

Launching is best-effort by design. Many projects need credentials, seed data
or a build step the agent cannot guess, and the spec is explicit that a failure
here must be *recorded as a verdict*, not hidden: a report showing no dynamic
findings because the app never started would be actively misleading.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from qa_agent.logging_setup import get_logger
from qa_agent.tools.process import resolve_executable, run_command

log = get_logger(__name__)

COMPOSE_FILES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")
_EXPOSE = re.compile(r"^\s*EXPOSE\s+(\d+)", re.IGNORECASE | re.MULTILINE)
# Used when a Dockerfile declares no EXPOSE at all.
FALLBACK_PORT = 3000
POLL_INTERVAL_S = 3.0


@dataclass
class LaunchedApp:
    """A running application the agent started, and how to shut it down."""

    url: str = ""
    method: str = ""
    detail: str = ""
    ok: bool = False
    image: str = ""
    container_id: str = ""
    compose_project: str = ""
    compose_file: Path | None = None
    teardown: list[list[str]] = field(default_factory=list)


def detect_launch_method(source: Path) -> tuple[str, Path | None]:
    """Return ``("compose"|"dockerfile"|"", path)`` for *source*."""
    for name in COMPOSE_FILES:
        candidate = source / name
        if candidate.is_file():
            return "compose", candidate
    dockerfile = source / "Dockerfile"
    if dockerfile.is_file():
        return "dockerfile", dockerfile
    return "", None


def wait_for_http(url: str, timeout_s: float, *, interval_s: float = POLL_INTERVAL_S) -> bool:
    """Poll *url* until it answers at all, or the deadline passes.

    Any HTTP status counts as "up": a 401 or a 500 still proves the server is
    listening, and the crawler will record what it actually returns.
    """
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            httpx.get(url, timeout=5.0, follow_redirects=True)
            return True
        except httpx.HTTPError:
            time.sleep(interval_s)
    return False


def _published_port_from_compose(docker: str, project: str, cwd: Path) -> int | None:
    """Ask compose which host port it published."""
    result = run_command(
        [docker, "compose", "-p", project, "ps", "--format", "json"], cwd=cwd, timeout=60
    )
    if not result.ok:
        return None

    # Compose emits either a JSON array or one JSON object per line.
    entries = []
    text = result.stdout.strip()
    try:
        parsed = json.loads(text)
        entries = parsed if isinstance(parsed, list) else [parsed]
    except ValueError:
        for line in text.splitlines():
            try:
                entries.append(json.loads(line))
            except ValueError:
                continue

    for entry in entries:
        for publisher in entry.get("Publishers") or []:
            port = publisher.get("PublishedPort")
            if port:
                return int(port)
    return None


def _launch_compose(
    source: Path, compose_file: Path, docker: str, run_id: str, timeout_s: float
) -> LaunchedApp:
    project = f"qa-{run_id.lower()[:20]}"
    app = LaunchedApp(method="docker compose", compose_project=project, compose_file=compose_file)
    app.teardown = [[docker, "compose", "-p", project, "down", "-v", "--remove-orphans"]]

    log.info("starting application with docker compose (project %s)", project)
    result = run_command(
        [docker, "compose", "-p", project, "up", "-d", "--build"],
        cwd=source,
        timeout=timeout_s,
    )
    if not result.ok:
        app.detail = f"'docker compose up' failed: {result.stderr.strip()[-300:]}"
        return app

    port = _published_port_from_compose(docker, project, source)
    if port is None:
        app.detail = "compose started but published no host port, so there is nothing to crawl"
        return app

    app.url = f"http://localhost:{port}"
    app.ok = wait_for_http(app.url, timeout_s)
    app.detail = (
        f"started via {compose_file.name} on port {port}"
        if app.ok
        else f"compose started but {app.url} never answered within {timeout_s:.0f}s"
    )
    return app


def _launch_dockerfile(
    source: Path, dockerfile: Path, docker: str, run_id: str, timeout_s: float
) -> LaunchedApp:
    image = f"qa-agent/target:{run_id.lower()[:20]}"
    app = LaunchedApp(method="dockerfile", image=image)

    log.info("building image %s", image)
    build = run_command([docker, "build", "-t", image, str(source)], cwd=source, timeout=timeout_s)
    if not build.ok:
        app.detail = f"'docker build' failed: {build.stderr.strip()[-300:]}"
        return app

    match = _EXPOSE.search(dockerfile.read_text(encoding="utf-8", errors="replace"))
    container_port = int(match.group(1)) if match else FALLBACK_PORT

    # Publishing to port 0 lets the operating system pick a free host port,
    # so a scan never collides with something already running.
    run = run_command(
        [docker, "run", "-d", "--rm", "-p", f"0:{container_port}", image], timeout=120
    )
    if not run.ok:
        app.detail = f"'docker run' failed: {run.stderr.strip()[-300:]}"
        return app

    app.container_id = run.stdout.strip()
    app.teardown = [[docker, "rm", "-f", app.container_id]]

    mapping = run_command([docker, "port", app.container_id, str(container_port)], timeout=60)
    host_port = mapping.stdout.strip().rsplit(":", 1)[-1] if mapping.ok else ""
    if not host_port.isdigit():
        app.detail = f"could not determine the published host port for {container_port}"
        return app

    app.url = f"http://localhost:{host_port}"
    app.ok = wait_for_http(app.url, timeout_s)
    app.detail = (
        f"built from Dockerfile, container port {container_port} -> host {host_port}"
        if app.ok
        else f"container started but {app.url} never answered within {timeout_s:.0f}s"
    )
    return app


def launch_app(source: Path, *, docker_bin: str, run_id: str, timeout_s: float) -> LaunchedApp:
    """Try to start the application in *source*; never raises."""
    docker = resolve_executable(docker_bin)
    if docker is None:
        return LaunchedApp(detail="docker is not installed, so the app could not be launched")

    method, path = detect_launch_method(source)
    if not method or path is None:
        return LaunchedApp(
            detail="no docker-compose.yml or Dockerfile found, so the app could not be launched"
        )

    try:
        if method == "compose":
            return _launch_compose(source, path, docker, run_id, timeout_s)
        return _launch_dockerfile(source, path, docker, run_id, timeout_s)
    except Exception as exc:  # noqa: BLE001 - a launch failure is a verdict, not a crash
        log.warning("launch failed: %s", exc)
        return LaunchedApp(method=method, detail=f"launch raised {type(exc).__name__}: {exc}")


def shutdown(app: LaunchedApp) -> None:
    """Stop whatever :func:`launch_app` started. Failures are logged, not raised."""
    for argv in app.teardown:
        try:
            run_command(argv, timeout=180)
        except Exception as exc:  # noqa: BLE001
            log.warning("could not tear down the application: %s", exc)
