# Local On-Premise AI QA Testing Agent

A QA testing agent that runs **entirely on the local machine**. No source code,
scan result or prompt ever leaves the environment.

Give it a URL — a Git repository or a deployed web application — and it produces
a structured QA report (Markdown + HTML) covering code issues, vulnerable
dependencies, security findings, accessibility violations, performance problems
and broken functionality.

## Core design principle

**Deterministic tools are the oracle; the LLM never invents findings.**

Every finding traces back to real tool output — Semgrep, Trivy, OSV-Scanner,
OWASP ZAP, axe-core, Lighthouse, a Playwright assertion, or a captured
console/network error. The local model is used only to triage, rank and explain
what the tools found, and to propose tests. All model calls use `temperature=0`.

## Architecture

```
URL ──> classifier ──> repo?  ──> clone ──────> Semgrep / Trivy / OSV-Scanner
                   └─> app?   ──> launcher ──> crawler ──> axe / Lighthouse / ZAP
                                                    │
                        every tool ──> raw JSON on disk
                                                    v
                                 parsers ──> unified Finding schema
                                                    │
                                 dedupe + cross-tool merge
                                                    v
                                 Jinja2 ──> report.md + report.html
```

Each tool is wired in as `adapter -> raw JSON on disk -> pure parser -> Findings`.
Parsers are pure functions over recorded JSON, so they are unit-tested without
Docker, a browser or a network.

| Layer | Technology |
|---|---|
| Language / CLI | Python 3.11+, Typer |
| Repo handling | Git |
| App runtime | Docker + Docker Compose |
| Static analysis | Semgrep |
| Dependency / secret scanning | Trivy, OSV-Scanner |
| Browser automation | Playwright (Chromium) |
| Accessibility | axe-core via axe-playwright-python |
| Performance | Lighthouse (headless, drives Playwright's Chromium) |
| DAST | OWASP ZAP baseline scan (Docker) |
| Local LLM | Ollama, OpenAI-compatible API at `localhost:11434/v1` |
| Reporting | Jinja2 -> Markdown + HTML |

### Two network modes

"No external network calls at runtime" conflicts with three tools by default:
`semgrep --config auto` fetches rules from semgrep.dev, Trivy downloads a
vulnerability database *and reports telemetry*, and OSV-Scanner queries
`deps.dev`. The project separates:

* **Provisioning — `qa_agent seed`, online, once.** Rule packs, vulnerability
  databases, Lighthouse and the ZAP image land in `~/.qa-agent/`.
* **Scanning — `qa_agent run`, offline, always.** Every tool is invoked with
  the flags that keep it local (`--metrics=off`, `--skip-db-update`,
  `--disable-telemetry`, `--offline-vulnerabilities`, `--data-source native`,
  `--no-resolve`, and ZAP's `-silent`, without which it downloads add-on
  updates on every scan).

For an air-gapped deployment, run `seed` on a connected machine and copy
`~/.qa-agent/` across.

## Prerequisites

| Requirement | Why | Check |
|---|---|---|
| Python 3.11+ | the agent itself | `python --version` |
| Git | cloning the repository under test | `git --version` |
| Docker Desktop (**running**) | ZAP, image scans, launching the app | `docker info` |
| Node.js LTS | Lighthouse | `node --version` |
| Ollama (**running**) | the local model (phase 2) | `ollama list` |
| ~20 GB free disk | databases, images, browsers, models | |

## Install

```powershell
# 1. Virtual environment and Python dependencies
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[scanners,dev]"

# 2. Scanner binaries that ship no Python package (Trivy, OSV-Scanner)
powershell -ExecutionPolicy Bypass -File scripts/install_tools.ps1

# 3. Chromium for Playwright
.\.venv\Scripts\python.exe -m playwright install chromium

# 4. The local model
ollama pull qwen2.5-coder:3b

# 5. Verify the environment
.\.venv\Scripts\python.exe -m qa_agent check_env

# 6. Provision the offline data (the one online step, ~2 GB)
.\.venv\Scripts\python.exe -m qa_agent seed
```

## Usage

```powershell
# A running application
python -m qa_agent run --app-url http://localhost:3000

# A repository: clone, analyse, and launch it if it ships a Dockerfile/compose
python -m qa_agent run --url https://github.com/owner/project.git

# Everything: source, running instance, and the built image
python -m qa_agent run --url https://github.com/juice-shop/juice-shop.git `
                       --app-url http://localhost:3000 `
                       --image bkimminich/juice-shop
```

Useful flags: `--max-pages N`, `--no-launch`, `--no-llm` (deterministic
pipeline only), `--skip <stage>` (repeatable: `semgrep`, `trivy`, `osv`,
`crawler`, `axe`, `lighthouse`, `zap`, `image`, `testgen`, `verify`, `triage`),
`--run-id`, `-v`.

## What the local model does (phase 2)

The model never creates or deletes a finding. It does four bounded jobs, each
with its own guard against hallucination:

| Job | What the model does | Guard |
|---|---|---|
| **Triage** | Explains each finding, suggests a fix, flags likely false positives, may re-score severity | Unknown finding ids are discarded; severity moves at most one level; a false-positive flag is a label, never a deletion |
| **Test generation** | Plans user flows as a restricted JSON step list | Only 7 actions and only selectors the crawler saw; the *agent* compiles the plan into Playwright code; one repair attempt, then "not testable" |
| **Verification** | (none: this is the agent) | Generated-test failures and browser errors must reproduce in a fresh browser; Semgrep findings are re-scanned |
| **Executive summary** | Writes the opening paragraph | Every number it writes must appear in the tool output, or a deterministic summary is used instead |

Every call uses `temperature=0` and a fixed seed; on this setup identical
prompts returned byte-identical answers. Every prompt and reply is recorded in
the run's `logs/llm.jsonl`.

Two measured facts shaped the client:

* Ollama's OpenAI-compatible API silently **ignores** `num_ctx`; the model
  runs with 4096 tokens regardless. Oversized prompts would be truncated from
  the front, dropping the rules first, so the client refuses to send them and
  the caller splits its batch (`QA_AGENT_LLM_CONTEXT_TOKENS`).
* A generated test can fail because the **model's expectation** is wrong (it
  once expected "Invalid email address" where the app correctly says "Invalid
  email or password"). Re-running cannot catch that, so such failures are
  reported at low severity and labelled as needing human confirmation.

### Why `--image` exists

Dependency scanners need a **lockfile** to resolve exact versions. Many
projects (OWASP Juice Shop among them) git-ignore theirs, so a source-only scan
finds no dependency vulnerabilities and OSV-Scanner correctly reports "no
package sources found". The built container image contains what was actually
installed, so scanning it recovers that coverage.

## Configuration

Every setting is an environment variable prefixed `QA_AGENT_`, or a line in a
`.env` file at the project root. See `qa_agent/config.py` for the full list.

```dotenv
QA_AGENT_LLM_MODEL=qwen2.5-coder:7b
QA_AGENT_MAX_PAGES=40
QA_AGENT_LIGHTHOUSE_MAX_PAGES=5
QA_AGENT_PERFORMANCE_BUDGET=50
QA_AGENT_ALLOW_PUBLIC_TARGETS=false
QA_AGENT_DATA_DIR=D:\qa-agent-data
```

### Choosing a model

The default `qwen2.5-coder:3b` fits in 6 GB of VRAM. Roughly: `:3b` ~2 GB,
`:7b` ~5 GB, `:32b` ~20 GB. A model that does not fit is offloaded to the CPU
and becomes very slow rather than failing outright.

## Where the data lives

Runs and offline databases live in `~/.qa-agent/`, **outside the project
folder**, for two reasons found the hard way on Windows:

* The project folder may be inside OneDrive, which would sync cloned
  confidential code to a cloud provider and defeat the entire premise.
* Windows' 260-character path limit: a deep project path plus a deep repository
  path overflows it.

```
~/.qa-agent/
    rules/semgrep/       offline Semgrep rule packs
    db/trivy/            offline vulnerability database
    db/osv/              offline OSV databases, per ecosystem
    tools/lighthouse/    local Lighthouse install
    workspace/<run_id>/
        repo/            cloned repository under test
        raw/             raw tool output, one JSON file per tool
        pages/           per-page screenshots
        logs/            run.log, commands.jsonl, llm.jsonl
        findings.json    unified findings
        report.md
        report.html
```

`commands.jsonl` records every subprocess the run invoked, so any finding can be
traced from the report back to the exact command that produced it.

## Safety guardrails

* Active scanning is refused unless the target is loopback or RFC1918, unless
  `QA_AGENT_ALLOW_PUBLIC_TARGETS=true` is set deliberately. Unresolvable hosts
  fail closed.
* Secret **values** are never copied into the report — only the kind and
  location — so the QA report cannot become the leak.
* The HTML report escapes all text taken from the scanned application, so a
  hostile page title cannot inject script into the report.
* Every subprocess runs without a shell, with an explicit timeout.
* Clones run with `GIT_TERMINAL_PROMPT=0`, so a private repository fails fast
  instead of hanging on an invisible prompt.

## Test target

OWASP Juice Shop is the development target — demo only, never evaluation proof,
since it is heavily represented in model training data.

```powershell
docker run --rm -d -p 3000:3000 --name juice-shop bkimminich/juice-shop
```

Phase 3 evaluates against a private application with deliberately injected bugs
and a secret answer sheet.

## Evaluation (phase 3)

Juice Shop is demo-only: it is widely represented in model training data. The
agent is measured instead against a private Flask app with **24 planted
defects** across every category it reports on (see `eval/README.md`).

```powershell
.\.venv\Scripts\python.exe -m qa_agent evaluate --runs 3
```

The harness starts the app on `127.0.0.1:5055`, runs the full agent three
times, and reports:

* **Recall**: planted defects found / planted defects.
* **Precision (strict)**: findings that match a planted defect / all findings.
  Real problems that were *not* planted count against it.
* **Precision (reviewed)**: also counts findings a human confirmed as genuine
  but unplanted (listed in the answer sheet, added after manual review).
* **Consistency**: mean pairwise Jaccard similarity of the finding ids across
  runs, measurable only because finding ids are deterministic.

The answer sheet is private and git-ignored. Any matcher change made after
seeing results is recorded in its `changes` list.

## On-premise / air-gapped deployment

One command builds and starts the whole stack (agent + local model server):

```powershell
docker compose up --build          # build, start Ollama, run the agent's self-check
docker compose exec ollama ollama pull qwen2.5-coder:3b     # once, while online
docker compose run --rm agent run --app-url http://host.docker.internal:3000
```

* The **image build is the only online step**. Scanner binaries are pinned and
  verified against their published SHA-256 checksums; Semgrep rules, the Trivy
  and OSV databases, Lighthouse and Chromium are baked in, so the image is
  large (~5 GB) and needs no network at scan time.
* ZAP runs as a short-lived sibling container started through the Docker
  socket. The report travels back through a shared named volume
  (`qa-agent-zap-exchange`), because with socket access a bind-mount path
  would be resolved on the host rather than inside the agent's container.
* Mounting the Docker socket gives the agent control of the Docker daemon:
  acceptable on a dedicated scanning host, not on a shared one.
* For a host with no internet at all, run
  `scripts/export_bundle.ps1` on a connected machine: it saves the three
  images and the model volume into one folder and prints the commands to
  load them on the offline host.

## Development

```powershell
.\.venv\Scripts\python.exe -m pytest                       # tests
.\.venv\Scripts\python.exe -m pytest --cov=qa_agent        # with coverage
.\.venv\Scripts\python.exe -m ruff check .                 # lint
```

## Project status

| Phase | Scope | Status |
|---|---|---|
| 0 | Environment, scaffold, `check_env` | done |
| 1 | Deterministic pipeline, zero AI | done |
| 2 | LLM triage, test generation, verification | done |
| 3 | Evaluation harness and on-prem packaging | done |
