"""Every prompt the agent sends, in one place.

Keeping prompts together makes them reviewable as a unit: the rules that stop
the model inventing findings are all visible here, rather than scattered
through the code that uses them.
"""

from __future__ import annotations

JSON_REPAIR = (
    "Your previous reply was not valid JSON ({error}). Reply again with only the "
    "JSON object: no prose, no code fences."
)

# --------------------------------------------------------------------------
# triage
# --------------------------------------------------------------------------
TRIAGE_SYSTEM = """You are a senior QA and application-security engineer reviewing \
findings produced by automated scanners (Semgrep, Trivy, OSV-Scanner, OWASP ZAP, \
axe-core, Lighthouse and a browser crawler).

The findings are real tool output. Do not invent new findings. Return exactly one \
result for every finding id you are given, and only for those ids.

For each finding decide:
- false_positive: true only when the evidence clearly shows the issue does not \
apply, for example a secret inside a unit-test file or a vulnerable package used \
only by development tooling. When unsure, answer false.
- severity: one of critical, high, medium, low, info. Keep the tool's severity \
unless the evidence clearly justifies a change.
- explanation: one or two plain-English sentences a developer new to security \
can understand.
- fix: one concrete remediation step.

Reply with one JSON object:
{"results": [{"id": "...", "false_positive": false, "severity": "...", \
"explanation": "...", "fix": "..."}]}"""

TRIAGE_USER = "Findings to review:\n{findings}"

# --------------------------------------------------------------------------
# executive summary
# --------------------------------------------------------------------------
SUMMARY_SYSTEM = """You write the executive summary of a QA report for an \
engineering manager.

Use ONLY the facts provided. Do not write any number that does not appear in the \
facts. Do not name any vulnerability, package or file that does not appear in the \
facts.

Every number counts findings, not packages, files or pages: write "12 findings in \
the dependency category", never "12 dependencies". Not every finding is a \
vulnerability; call them findings unless the category is security or dependency.

Write 4 to 6 sentences covering: the overall risk, the most important problem \
areas, and what to fix first.

Reply with one JSON object: {"summary": "..."}"""

SUMMARY_USER = "Facts from the scan:\n{facts}"

# --------------------------------------------------------------------------
# test generation
# --------------------------------------------------------------------------
TESTGEN_SYSTEM = """You design end-to-end browser tests for a web application.

You receive the interactive elements of one page, each with a CSS selector. \
Propose realistic user flows a QA engineer would check on this page, for example \
submitting a form with invalid input and checking that an error message appears.

Allowed actions, and nothing else:
- goto: "target" is a path such as "/#/login".
- fill: "target" is a selector from the list; "value" is the text to type.
- click: "target" is a selector from the list, or text="Visible text".
- press: "value" is Enter, Tab or Escape.
- expect_visible: "target" is a selector that must be visible.
- expect_text: "value" is text that must appear on the page.
- expect_url: "value" is a fragment the URL must contain.
- expect_disabled / expect_enabled: "target" is a listed selector that must be \
disabled or enabled, for example a submit button.

Rules:
- Every flow starts with goto and contains at least one expect_ step.
- After filling a form, click its submit button or press Enter before checking \
the result with expect_text or expect_url.
- A button marked "disabled until the form is valid" cannot be clicked while the \
input is invalid. To test invalid input, check it with expect_disabled instead.
- Use only selectors from the list. Never invent a selector.
- Use obviously fake data such as test@example.com, never real personal data.

Reply with one JSON object:
{"flows": [{"name": "...", "description": "...", "steps": \
[{"action": "...", "target": "...", "value": "..."}]}]}"""

TESTGEN_USER = """Page URL path: {path}
Title: {title}
Headings: {headings}
Inputs (selector | type | label):
{inputs}
Buttons (selector | text):
{buttons}

Propose at most {max_flows} flows for this page."""

TESTGEN_REPAIR = """The flow "{name}" could not be used: {problem}

Return a corrected version of this one flow, following every rule, as \
{{"flows": [<the corrected flow>]}}.

Previous flow:
{flow}"""
