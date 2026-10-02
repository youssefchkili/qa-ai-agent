"""One-time, online provisioning of everything the scanners need offline.

This module is the deliberate seam between the two network modes:

* ``seed`` runs **once, online**, and downloads rule packs, vulnerability
  databases and Lighthouse into the data directory.
* ``run`` then works entirely **offline**, reading only what seed produced.

An air-gapped deployment runs seed on a connected machine and copies the data
directory across.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from qa_agent.config import Settings
from qa_agent.logging_setup import get_logger
from qa_agent.tools.process import resolve_executable, run_command

log = get_logger(__name__)

# Rule packs pulled from the Semgrep registry. The registry serves a config
# document per pack; "default" carries the broad multi-language rule set.
SEMGREP_PACKS = ("default", "owasp-top-ten", "secrets")
SEMGREP_REGISTRY = "https://semgrep.dev/c/p/{pack}"

# Minimal manifests used to make OSV download the database for each ecosystem.
# OSV only fetches the ecosystems it actually sees, so seeding needs a sample.
ECOSYSTEM_FIXTURES: dict[str, tuple[str, str]] = {
    "npm": (
        "package-lock.json",
        json.dumps(
            {
                "name": "seed",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": True,
                "packages": {
                    "": {"name": "seed", "version": "1.0.0"},
                    "node_modules/lodash": {"version": "4.17.20"},
                },
            }
        ),
    ),
    "PyPI": ("requirements.txt", "flask==1.0.0\n"),
}


@dataclass
class SeedStep:
    """Result of provisioning one component."""

    name: str
    ok: bool
    detail: str


def seed_semgrep_rules(settings: Settings, *, force: bool = False) -> SeedStep:
    """Download the Semgrep rule packs used for offline scanning."""
    target = settings.semgrep_rules_dir
    target.mkdir(parents=True, exist_ok=True)

    downloaded, skipped, failed = [], [], []
    for pack in SEMGREP_PACKS:
        destination = target / f"{pack}.yml"
        if destination.is_file() and not force:
            skipped.append(pack)
            continue
        try:
            response = httpx.get(
                SEMGREP_REGISTRY.format(pack=pack), timeout=120.0, follow_redirects=True
            )
            response.raise_for_status()
            destination.write_text(response.text, encoding="utf-8")
            downloaded.append(pack)
        except Exception as exc:  # noqa: BLE001
            failed.append(f"{pack} ({exc})")

    detail = f"downloaded={downloaded or '-'} already-present={skipped or '-'}"
    if failed:
        return SeedStep("semgrep rules", False, detail + f" failed={failed}")
    return SeedStep("semgrep rules", True, detail)


def seed_trivy_db(settings: Settings) -> SeedStep:
    """Download Trivy's vulnerability database into the local cache."""
    binary = resolve_executable(settings.trivy_bin, [settings.vendor_bin_dir])
    if binary is None:
        return SeedStep("trivy database", False, "trivy is not installed")

    settings.trivy_cache_dir.mkdir(parents=True, exist_ok=True)
    result = run_command(
        [
            binary,
            "image",
            "--download-db-only",
            "--cache-dir",
            str(settings.trivy_cache_dir),
            "--disable-telemetry",
            "--skip-version-check",
            "--quiet",
        ],
        timeout=1800,
    )
    if not result.ok:
        return SeedStep("trivy database", False, result.stderr.strip()[-300:] or "download failed")

    size = sum(p.stat().st_size for p in settings.trivy_cache_dir.rglob("*") if p.is_file())
    return SeedStep(
        "trivy database", True, f"{size / 1_048_576:.0f} MB in {settings.trivy_cache_dir}"
    )


def seed_osv_db(settings: Settings, ecosystems: tuple[str, ...] = ("npm", "PyPI")) -> SeedStep:
    """Download OSV's offline databases for the given ecosystems.

    OSV downloads only the ecosystems it encounters, so a tiny synthetic
    manifest per ecosystem is written to a temporary directory to trigger it.
    """
    binary = resolve_executable(settings.osv_bin, [settings.vendor_bin_dir])
    if binary is None:
        return SeedStep("osv database", False, "osv-scanner is not installed")

    settings.osv_db_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"] = str(settings.osv_db_dir)

    done, failed = [], []
    with tempfile.TemporaryDirectory(prefix="qa-agent-seed-") as temp:
        for ecosystem in ecosystems:
            fixture = ECOSYSTEM_FIXTURES.get(ecosystem)
            if fixture is None:
                failed.append(f"{ecosystem} (no fixture)")
                continue
            filename, content = fixture
            sample_dir = Path(temp) / ecosystem.lower()
            sample_dir.mkdir(parents=True, exist_ok=True)
            (sample_dir / filename).write_text(content, encoding="utf-8")

            result = run_command(
                [
                    binary,
                    "scan",
                    "source",
                    "--offline-vulnerabilities",
                    "--download-offline-databases",
                    "--data-source",
                    "native",
                    "--format",
                    "json",
                    "-r",
                    str(sample_dir),
                ],
                env=env,
                timeout=1800,
            )
            # 0 = clean, 1 = vulnerabilities found; both mean the DB arrived.
            if result.returncode in (0, 1):
                done.append(ecosystem)
            else:
                failed.append(f"{ecosystem} (exit {result.returncode})")

    if failed:
        return SeedStep("osv database", False, f"downloaded={done or '-'} failed={failed}")
    return SeedStep("osv database", True, f"downloaded={done}")


def seed_lighthouse(settings: Settings) -> SeedStep:
    """Install Lighthouse locally so no package is fetched at scan time."""
    if settings.lighthouse_cli.is_file():
        return SeedStep("lighthouse", True, f"already present in {settings.lighthouse_dir}")

    npm = resolve_executable("npm")
    if npm is None:
        return SeedStep("lighthouse", False, "npm is not installed")

    settings.lighthouse_dir.mkdir(parents=True, exist_ok=True)
    result = run_command(
        [
            npm,
            "install",
            "--prefix",
            str(settings.lighthouse_dir),
            "lighthouse",
            "--no-audit",
            "--no-fund",
            "--loglevel=error",
        ],
        timeout=1800,
    )
    if not settings.lighthouse_cli.is_file():
        return SeedStep("lighthouse", False, result.stderr.strip()[-300:] or "npm install failed")
    return SeedStep("lighthouse", True, f"installed in {settings.lighthouse_dir}")


def seed_zap_image(settings: Settings) -> SeedStep:
    """Pull the ZAP image so the scan itself needs no registry access."""
    docker = resolve_executable(settings.docker_bin, [settings.vendor_bin_dir])
    if docker is None:
        return SeedStep("zap image", False, "docker is not installed")

    present = run_command([docker, "image", "inspect", settings.zap_image], timeout=60)
    if present.ok:
        return SeedStep("zap image", True, f"{settings.zap_image} already present")

    result = run_command([docker, "pull", settings.zap_image], timeout=3600)
    if not result.ok:
        return SeedStep("zap image", False, result.stderr.strip()[-300:] or "pull failed")
    return SeedStep("zap image", True, f"pulled {settings.zap_image}")


COMPONENTS = ("semgrep", "trivy", "osv", "lighthouse", "zap")


def seed_all(
    settings: Settings, *, force: bool = False, components: tuple[str, ...] = ()
) -> list[SeedStep]:
    """Provision everything (or just *components*), continuing past failures.

    Selecting components matters for the container build: the image bakes in
    the rules and databases, but cannot pull the ZAP image from inside a build.
    """
    wanted = set(components) or set(COMPONENTS)
    unknown = wanted - set(COMPONENTS)
    if unknown:
        raise ValueError(f"unknown component(s): {', '.join(sorted(unknown))}")

    settings.data_dir.mkdir(parents=True, exist_ok=True)
    steps = {
        "semgrep": lambda: seed_semgrep_rules(settings, force=force),
        "trivy": lambda: seed_trivy_db(settings),
        "osv": lambda: seed_osv_db(settings),
        "lighthouse": lambda: seed_lighthouse(settings),
        "zap": lambda: seed_zap_image(settings),
    }
    return [steps[name]() for name in COMPONENTS if name in wanted]
