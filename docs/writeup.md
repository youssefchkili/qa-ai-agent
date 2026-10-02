# A Local, On-Premise AI QA Agent

*Internship project write-up.*

## 1. Problem and motivation

Organisations with confidential codebases cannot send source code, scan
results or application traffic to cloud services. Cloud coding assistants and
hosted scanners are therefore unavailable to exactly the teams whose code most
needs review. The goal of this project is a QA agent that runs **entirely on
the local machine** and, given a Git repository and/or a running web
application, produces a structured QA report covering code security, vulnerable
dependencies, committed secrets, container misconfiguration, accessibility,
performance and broken functionality.

A second requirement follows from the first: because the report is meant to be
acted on, **it must not contain invented problems**. Large language models are
known to state false things confidently; a single fabricated "critical
vulnerability" destroys trust in a report.

## 2. State of the art

*(Citations to be added.)*

* **Static analysis (SAST)**: pattern and dataflow scanners such as Semgrep and
  CodeQL find code-level weaknesses deterministically.
* **Software composition analysis (SCA)**: Trivy, OSV-Scanner and similar
  tools match installed package versions against advisory databases.
* **Dynamic analysis (DAST)**: OWASP ZAP observes and probes a running
  application; axe-core and Lighthouse measure accessibility and performance
  in a real browser.
* **LLM-assisted review**: cloud assistants can explain code and suggest fixes,
  but require sending code off-premise, and their findings are not grounded
  in any deterministic evidence.

The gap this project addresses is the combination: deterministic tools as the
source of truth, a *local* model used only where it adds value, and an
architecture in which the model cannot introduce findings of its own.

## 3. Architecture

**Principle: deterministic tools are the oracle; the LLM never invents
findings.** Every reported problem traces back to raw tool output stored next
to the report.

```
URL ─> classify ─> repository? ─> clone ─> Semgrep, Trivy, OSV-Scanner
                └> application? ─> guardrail ─> crawler (Playwright)
                                               ├─ axe-core, Lighthouse, ZAP
                                               └─ LLM-planned tests (phase 2)
   every tool ─> raw JSON on disk ─> pure parser ─> unified Finding schema
   ─> deduplicate ─> verify (must reproduce) ─> LLM triage ─> summary ─> report
```

Key design decisions:

| Decision | Reason |
|---|---|
| One unified `Finding` schema, one parser per tool | Tools speak different dialects; everything downstream is tool-agnostic |
| Deterministic finding ids (`sha256(tool, category, rule, location)`) instead of UUIDs | Enables de-duplication, run-to-run consistency and answer-sheet matching |
| Raw output saved before parsing | Every finding is auditable back to its evidence |
| Two network modes: `seed` (online, once) and `run` (offline) | Three scanners contact the internet by default; vendoring their data makes air-gapped use possible |
| Honest verdicts per tool (ok / failed / skipped / not applicable) | "No findings" and "the scanner never ran" must never look the same |
| Local model via an OpenAI-compatible API (Ollama) | No data leaves the machine; the backend can be swapped for vLLM unchanged |

## 4. Implementation

The system is a Python package (`qa_agent`) orchestrated by a single linear
function (`pipeline.py`), with a Typer CLI (`check_env`, `seed`, `run`,
`evaluate`).

**Phase 1: deterministic pipeline.** Adapters invoke each scanner with a
timeout and without a shell, write raw JSON, and hand it to pure parsers.
Findings are de-duplicated three ways: exact fingerprint, cross-tool advisory
aliases (a CVE reported by Trivy and its GHSA alias reported by OSV become one
finding marked *independently confirmed*), and page-level rules collapsed
across pages. A guardrail refuses active scanning of any non-local target.

**Phase 2: local LLM layer.** A single client enforces temperature 0 plus a
fixed seed (identical prompts gave byte-identical answers), strict JSON with
one repair attempt, a hard context budget, and an audit log of every exchange.
The model performs four bounded jobs, each with its own guard:

* *Triage* explains findings and suggests fixes; unknown ids are discarded,
  severity may move by at most one level, and a false-positive flag never
  deletes a finding.
* *Test generation*: the model writes a restricted JSON plan (nine actions,
  only selectors the crawler observed); the agent validates it and compiles
  it into Playwright code itself, so no model-written code is ever executed.
* *Verification*: flaky and generated findings must reproduce in a fresh
  browser before they count.
* *Executive summary*: every number in it must appear in the tool output,
  otherwise a deterministic summary is used.

**Phase 3: evaluation and packaging.** A private evaluation app, a metrics
harness, and a Docker Compose stack described in section 5 and the README.

### Findings from building it

Several design elements exist only because running the system exposed a
problem:

* Ollama's OpenAI-compatible endpoint silently ignores the context-size
  option; the model always runs with 4096 tokens, so oversized prompts would
  have lost their instructions without error. The client now refuses to send
  them.
* The model filled forms without submitting them, then asserted on the result;
  a structural rule now rejects such plans.
* The model's expected error texts were frequently wrong ("Invalid password"
  where the application correctly shows "Invalid email or password").
  Re-running cannot detect this, so generated-test failures are low severity,
  labelled for human confirmation, and show the text the page actually
  displayed.
* Lighthouse's default simulated throttling reported a 0.8 s first paint for a
  page whose first paint really takes 4.7 s; the agent now measures the real
  load and also applies Google's published Core Web Vitals thresholds.
* The first three-run evaluation reported 78% run-to-run consistency. The
  cause was not the model: OSV-Scanner resolves a `requirements.txt` into its
  transitive dependencies by querying PyPI, even with its offline database.
  When that call failed, 14 findings disappeared. Transitive resolution is
  now disabled, which restores the no-network guarantee at the cost of
  transitive packages for projects without a lockfile.
* ZAP's scan time varied from 2 to over 15 minutes. Its baseline script
  downloads add-on updates from the internet on every scan unless ZAP is
  started with `-silent`; on a slow link it sometimes hit the time limit and
  lost all its findings. It now runs with `-silent`. When it did time out,
  stopping the Docker client left the ZAP container scanning for another
  hour; containers are now named per run and removed on timeout.
* Packaging was verified by a real scan inside the Compose stack, not only
  by a successful build. That scan found that ZAP, which runs as an
  unprivileged user, could not write its report into the root-owned shared
  volume; the agent now makes that folder writable before starting ZAP. The
  model was loaded into the stack by copying it from another Ollama install,
  the same route an air-gapped host would use.
* The OSV and ZAP problems were network calls the tools make by default. The lesson for
  an on-premise tool: "offline" has to be verified per tool, not assumed from
  a flag that sounds right.
* The project folder was inside OneDrive: scan data is stored outside it, so
  confidential code is never synced to a cloud provider.

## 5. Evaluation

### Method

OWASP Juice Shop was used only as a development target: it is widely present
in model training data and cannot serve as evidence. The agent is evaluated
against a new Flask application with **24 planted defects** (8 in code
security, 1 hard-coded AWS credential, 2 vulnerable dependencies, 2 container
misconfigurations, 2 HTTP header or cookie weaknesses, 4 accessibility
violations, 4 functional failures, 1 performance problem). The answer sheet is
private and records how a correct detection is recognised.

Metrics:

* **Recall**: planted defects detected / planted defects.
* **Strict precision**: findings matching a planted defect / all verified
  findings. Real but unplanted problems count against it.
* **Reviewed precision**: additionally counts findings confirmed by manual
  review as genuine but unplanted.
* **Consistency**: mean pairwise Jaccard similarity of finding ids over three
  runs.

### Results

Final three-run evaluation (`eval/results/20261001-101611.json`), full
pipeline including the local model:

| Metric | Value |
|---|---|
| Recall | **95.8%** (23 of 24 planted defects, every run) |
| Strict precision | **79.7%** (51 of 64 findings match a planted defect) |
| Reviewed precision | **95.3%** (61 of 64 are genuine problems) |
| Consistency (3 runs) | **100%** (identical finding ids in all three runs) |
| Time per run | about 7 minutes |

Recall by category: accessibility, dependency, functional and performance
100%; security 92%. The one miss is the low-entropy Flask `SECRET_KEY`.

Of the 64 findings, 10 are genuine but unplanted (for example Flask's missing
hardening headers and an inaccessible default 404 page). Only 3 are false
positives: two LLM-generated tests whose expected text was wrong (both
already reported at low severity as "needs human confirmation") and one
informational ZAP alert.

How the numbers developed shows why the metric needs three runs:

| Evaluation | Strict precision | Consistency | Cause of the change |
|---|---|---|---|
| First 3-run evaluation | 72.7% | 78.3% | OSV resolved dependencies via PyPI; ZAP timed out once |
| After OSV fix | 81.0% | 87.1% | ZAP still timed out once (add-on download) |
| After ZAP fix (final) | 79.7% | 100% | No network calls left at scan time |

Strict precision fell slightly in the final row because ZAP findings are now
present in every run; it was higher in runs where ZAP failed and its
genuine-but-unplanted alerts were missing. Two coverage trade-offs came with
these fixes. Transitive dependencies of a bare `requirements.txt` are no
longer resolved (13 urllib3/idna advisories disappeared; a lockfile restores
them). ZAP's beta passive rules are no longer downloaded (16 alerts became 10,
none of them a planted defect).

A preliminary single run, before the Lighthouse change, detected 22 of 24
planted defects (recall 91.7%) with strict precision 62.0%. A manual review of
all 30 unmatched findings classified 28 as genuine but unplanted problems
(transitive CVEs in urllib3 and idna, Flask's missing hardening headers, a
Dockerfile without a health check, an inaccessible default 404 page) and 2 as
false positives, both LLM-generated tests with wrong expected text. The
LLM-generated tests also found one planted defect that no scanner reports: the
contact form cannot be submitted (HTTP 405).

## 6. Limitations and future work

* **Model capability.** A 3B model (chosen for a 6 GB GPU) explains findings
  well but does not discriminate: it flagged no false positives, and most of
  its generated test failures were wrong expectations. A 7B or larger model
  is the first lever to pull.
* **Post-hoc changes.** The Lighthouse configuration, one matcher, the
  reviewed-issues list, and the OSV and ZAP network fixes were all made after
  seeing evaluation results; they are recorded in the answer sheet or above
  and reported openly. The app was not changed to suit the agent.
* **Single evaluation app.** Twenty-four defects in one small app is a small
  sample; a broader benchmark would strengthen the conclusions.
* **Missed defect classes.** A low-entropy hard-coded Flask `SECRET_KEY` was
  not detected by any scanner.
* **Docker socket.** The packaged agent controls the Docker daemon to start
  ZAP; this suits a dedicated scanning host, not a shared one.
* **Future work:** stronger local models, authenticated crawling, active (not
  only passive) DAST under explicit authorisation, and learning from triage
  decisions confirmed by humans.
