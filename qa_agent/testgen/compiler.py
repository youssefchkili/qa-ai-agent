"""Compile a validated flow into a standalone Playwright test script.

The agent writes this code, not the model. Every value that came from the
model (selectors, typed text, expected text) enters the script through
``repr()``, which always yields a valid Python string literal, so no reply can
break out of a string and inject code.

Each generated script is self-contained: a developer can re-run it by hand with
``python flow_01_....py`` to reproduce a failure.
"""

from __future__ import annotations

import re

from qa_agent.testgen.dsl import Flow, resolve_url

MARKER = "QA_RESULT "

_PRELUDE = '''
import json
import re
import sys
from pathlib import Path

from playwright.sync_api import Error as PlaywrightError
from playwright.sync_api import expect, sync_playwright

MARKER = "QA_RESULT "
SCREENSHOT = Path(__file__).with_suffix(".png")
ANSI = re.compile(r"\\x1b\\[[0-9;]*m")
# Welcome dialogs and cookie banners block clicks; clear them after navigating.
OVERLAY = re.compile(r"dismiss|close welcome|accept( all)?$|got it|i agree", re.IGNORECASE)


MESSAGE_SELECTOR = "[role=alert], .error, .mat-error, [class*='error'], h1"


def visible_messages(page):
    """Short messages visible when a step failed, for the human confirming it.

    A failed expectation is often the model guessing the wrong wording; showing
    what the page actually said makes that obvious at a glance.
    """
    found = []
    try:
        for element in page.locator(MESSAGE_SELECTOR).all()[:20]:
            if not element.is_visible():
                continue
            text = " ".join(element.inner_text(timeout=500).split())
            if text and len(text) <= 160 and text not in found:
                found.append(text)
    except PlaywrightError:
        pass
    return found[:5]


def settle(page):
    """Let a single-page app render its route, then clear blocking overlays."""
    page.wait_for_timeout(1200)
    for button in page.locator("button").all():
        try:
            if not button.is_visible():
                continue
            label = (button.get_attribute("aria-label") or button.inner_text() or "").strip()
            if OVERLAY.search(label):
                button.click(timeout=1500)
        except PlaywrightError:
            continue
'''

_MAIN = '''

def main():
    state = {"step": 0, "action": ""}

    def mark(step, action):
        state.update(step=step, action=action)

    status, message, observed = "pass", "", []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            flow(page, mark)
        except AssertionError as exc:
            # An expect_ step did not hold: the application behaved differently.
            status, message = "fail", str(exc)
        except Exception as exc:  # noqa: BLE001
            # An action could not be performed: the test itself is unusable.
            status, message = "error", f"{type(exc).__name__}: {exc}"
        if status != "pass":
            observed = visible_messages(page)
            try:
                page.screenshot(path=str(SCREENSHOT))
            except Exception:  # noqa: BLE001
                pass
        browser.close()

    message = " ".join(ANSI.sub("", message).split())[:600]
    print(MARKER + json.dumps({
        "flow": FLOW_NAME,
        "status": status,
        "step": state["step"] if status != "pass" else None,
        "action": state["action"] if status != "pass" else None,
        "message": message,
        "screenshot": SCREENSHOT.name if status != "pass" else "",
        "observed": observed,
    }))
    sys.exit({"pass": 0, "fail": 1}.get(status, 2))


if __name__ == "__main__":
    main()
'''

_SLUG = re.compile(r"[^a-z0-9]+")


def slugify(text: str, limit: int = 40) -> str:
    """Filesystem-safe name fragment."""
    return _SLUG.sub("-", text.lower()).strip("-")[:limit] or "flow"


def _step_lines(number: int, action: str, target: str, value: str, base_url: str) -> list[str]:
    """Python lines implementing one validated step."""
    mark = f"    mark({number}, {action!r})"
    if action == "goto":
        url = resolve_url(target, base_url)
        return [mark, f"    page.goto({url!r}, timeout=TIMEOUT_MS)", "    settle(page)"]
    if action == "fill":
        return [mark, f"    page.locator({target!r}).first.fill({value!r}, timeout=TIMEOUT_MS)"]
    if action == "click":
        return [
            mark,
            f"    page.locator({target!r}).first.click(timeout=TIMEOUT_MS)",
            "    page.wait_for_timeout(800)",
        ]
    if action == "press":
        return [mark, f"    page.keyboard.press({value!r})", "    page.wait_for_timeout(800)"]
    if action == "expect_visible":
        return [
            mark,
            f"    expect(page.locator({target!r}).first).to_be_visible(timeout=TIMEOUT_MS)",
        ]
    if action == "expect_text":
        return [
            mark,
            f"    expect(page.get_by_text({value!r}).first).to_be_visible(timeout=TIMEOUT_MS)",
        ]
    if action == "expect_disabled":
        return [
            mark,
            f"    expect(page.locator({target!r}).first).to_be_disabled(timeout=TIMEOUT_MS)",
        ]
    if action == "expect_enabled":
        return [
            mark,
            f"    expect(page.locator({target!r}).first).to_be_enabled(timeout=TIMEOUT_MS)",
        ]
    if action == "expect_url":
        return [
            mark,
            f"    expect(page).to_have_url(re.compile(re.escape({value!r})), timeout=TIMEOUT_MS)",
        ]
    raise ValueError(f"cannot compile unknown action {action!r}")


def compile_flow(flow: Flow, *, base_url: str, step_timeout_ms: int) -> str:
    """Return the full source of a Playwright script for *flow*.

    The flow must already have passed :func:`~qa_agent.testgen.dsl.validate_flow`.
    """
    header = [
        '"""Generated by qa-agent from a flow planned by the local model.',
        "",
        "The model proposed the steps; the agent validated them and wrote this code.",
        'Re-run by hand with:  python "<this file>"',
        '"""',
    ]
    constants = [
        f"FLOW_NAME = {flow.name!r}",
        f"TIMEOUT_MS = {int(step_timeout_ms)}",
    ]
    body = ["", "", "def flow(page, mark):"]
    for number, step in enumerate(flow.steps, start=1):
        body += _step_lines(number, step.action, step.target, step.value, base_url)

    return "\n".join(header) + _PRELUDE + "\n".join(constants) + "\n".join(body) + _MAIN
