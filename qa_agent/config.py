"""Central configuration.

Every value can be overridden with an environment variable prefixed ``QA_AGENT_``
or through a ``.env`` file at the project root, e.g.::

    QA_AGENT_LLM_MODEL=qwen2.5-coder:7b
    QA_AGENT_MAX_PAGES=40

The only network endpoints referenced here are localhost services (Ollama, ZAP,
the target application). Nothing in a scan run reaches the public internet.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Repository root: <root>/qa_agent/config.py -> <root>
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Minimum interpreter the project supports.
MIN_PYTHON = (3, 11)


class Settings(BaseSettings):
    """Runtime settings for the agent."""

    model_config = SettingsConfigDict(
        env_prefix="QA_AGENT_",
        # Anchored to the project root, so the file is found no matter which
        # directory the command is launched from.
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- filesystem layout -------------------------------------------------
    # Runs and offline databases deliberately live OUTSIDE the project folder.
    # Two reasons, both discovered the hard way on this machine:
    #   1. The project sits inside OneDrive. A cloned confidential repository
    #      placed here would be uploaded to Microsoft's cloud, which destroys
    #      the entire premise of an on-premise tool.
    #   2. Windows' legacy 260-character path limit. Deep project paths plus
    #      deep repository paths overflow it; a short root avoids that.
    data_dir: Path = Path.home() / ".qa-agent"
    # Scanner binaries fetched by scripts/install_tools.ps1 stay with the code.
    vendor_dir: Path = PROJECT_ROOT / "vendor"

    # --- local LLM (Ollama exposed through its OpenAI-compatible API) -------
    # Kept OpenAI-shaped so the backend can later be swapped for vLLM unchanged.
    llm_base_url: str = "http://localhost:11434/v1"
    llm_api_key: str = "ollama"  # Ollama ignores the value; the client requires one.
    llm_model: str = "qwen2.5-coder:3b"
    llm_temperature: float = 0.0
    # temperature=0 alone is not a determinism guarantee; a fixed seed is what
    # made identical prompts return byte-identical answers on this machine.
    llm_seed: int = 7
    # The context window the model ACTUALLY runs with. Measured, not assumed:
    # Ollama 0.34 accepts options.num_ctx through its OpenAI-compatible API
    # without error but ignores it, and `ollama ps` still reports 4096. A
    # prompt larger than this is truncated from the front with no error, so
    # the client refuses to send one (see llm/client.py).
    llm_context_tokens: int = 4096
    llm_max_output_tokens: int = 1024
    # How many times a reply that is not valid JSON is sent back for repair.
    llm_json_retries: int = 1
    llm_timeout_s: int = 180

    # --- phase 2 jobs --------------------------------------------------------
    # Master switch: with it off, the run is exactly the phase 1 pipeline.
    use_llm: bool = True
    # A 3B model on a 4k context reviews a handful of findings per call.
    triage_batch_size: int = 4
    # Most severe first; anything beyond this is reported as "not triaged".
    triage_max_findings: int = 60
    # Test generation: pages to plan from, and a hard cap on flows run.
    testgen_pages: int = 3
    testgen_max_flows: int = 6
    testgen_step_timeout_ms: int = 8000
    testgen_run_timeout_s: int = 120
    # Re-confirm flaky and generated findings before they reach the report.
    verify_findings: bool = True
    ollama_host: str = "http://localhost:11434"

    # --- external executables (override when not on PATH) ------------------
    semgrep_bin: str = "semgrep"
    trivy_bin: str = "trivy"
    osv_bin: str = "osv-scanner"
    docker_bin: str = "docker"
    node_bin: str = "node"
    npx_bin: str = "npx"
    git_bin: str = "git"

    # --- crawl and scan limits ---------------------------------------------
    max_pages: int = 20
    page_timeout_s: int = 30
    tool_timeout_s: int = 900
    app_launch_timeout_s: int = 300

    # --- offline behaviour --------------------------------------------------
    # When true (the default and the whole point of the project) every scanner
    # is invoked with the flags that stop it reaching the internet, and uses
    # the databases and rule packs provisioned by ``qa_agent seed``.
    offline: bool = True
    # Empty means "use the vendored rule packs in semgrep_rules_dir".
    # Setting it to "auto" restores Semgrep's online registry behaviour.
    semgrep_config: str = ""

    # --- dynamic analysis ----------------------------------------------------
    zap_image: str = "zaproxy/zap-stable"
    # Containerised deployment only. The agent starts ZAP through the Docker
    # socket, so a bind-mount path would be resolved on the *host*, where the
    # agent's workspace does not exist. Instead both containers mount one named
    # volume: ZAP writes its report there and the agent reads it back.
    zap_exchange_volume: str = ""
    zap_exchange_dir: Path = Path("/zap-exchange")
    # Inside a container, "localhost" is the container itself. Docker Desktop
    # publishes this name for reaching a service on the host machine.
    docker_gateway_host: str = "host.docker.internal"
    # Lighthouse costs roughly 20-30 s per page, so it runs on the first few
    # pages rather than all of them. Raise it for a full audit.
    lighthouse_max_pages: int = 3
    # "devtools" measures the real, throttled load. Lighthouse's default,
    # "simulate", estimates it from a model: on the evaluation app it reported
    # a 0.8 s first paint for a page whose first paint really takes 4.7 s,
    # because the simulation did not account for a slow server response.
    lighthouse_throttling: str = "devtools"
    performance_budget: int = 50
    best_practices_budget: int = 70
    seo_budget: int = 70

    # --- safety -------------------------------------------------------------
    # Active scanning (crawler, ZAP, generated tests) is refused against a
    # target that is not loopback or RFC1918 unless this is explicitly enabled.
    allow_public_targets: bool = False

    # --- derived paths -------------------------------------------------------
    @property
    def vendor_bin_dir(self) -> Path:
        """Directory holding scanner binaries fetched by ``scripts/install_tools.ps1``."""
        return self.vendor_dir / "bin"

    @property
    def workspace_dir(self) -> Path:
        """Root under which every run gets its own directory."""
        return self.data_dir / "workspace"

    @property
    def semgrep_rules_dir(self) -> Path:
        """Offline Semgrep rule packs downloaded once by ``seed``."""
        return self.data_dir / "rules" / "semgrep"

    @property
    def trivy_cache_dir(self) -> Path:
        """Trivy's cache, holding the offline vulnerability database."""
        return self.data_dir / "db" / "trivy"

    @property
    def osv_db_dir(self) -> Path:
        """OSV-Scanner's offline database directory."""
        return self.data_dir / "db" / "osv"

    @property
    def lighthouse_dir(self) -> Path:
        """Local npm prefix holding Lighthouse, so npx never downloads it."""
        return self.data_dir / "tools" / "lighthouse"

    @property
    def lighthouse_bin(self) -> Path:
        """Path of the Lighthouse launcher script for this platform."""
        name = "lighthouse.cmd" if os.name == "nt" else "lighthouse"
        return self.lighthouse_dir / "node_modules" / ".bin" / name

    @property
    def lighthouse_cli(self) -> Path:
        """Lighthouse's entry script, run directly with node.

        Preferred over the generated shim above: one identical invocation
        works on Windows and inside the phase 3 Linux container.
        """
        return self.lighthouse_dir / "node_modules" / "lighthouse" / "cli" / "index.js"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()
