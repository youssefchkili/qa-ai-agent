"""Playwright crawler: visits the application and records what it observes.

This is the source of the dynamic half of the report. For every page it
records the title, the HTTP status, JavaScript console errors, failed network
requests, a screenshot, the axe-core accessibility results, and a compact
description of the interactive elements.

Console errors and failed requests are findings in their own right: they are
real defects that a user's browser encountered, witnessed and screenshotted.
"""

from __future__ import annotations

import re
from collections import deque
from pathlib import Path

from qa_agent.logging_setup import get_logger
from qa_agent.web.page_model import (
    PAGE_STRUCTURE_SCRIPT,
    NetworkFailure,
    PageObservation,
    normalize_url,
    same_origin,
)

log = get_logger(__name__)

# Browser noise that says nothing about the application's own quality.
_IGNORED_CONSOLE = re.compile(
    r"favicon\.ico|DevTools|Download the React DevTools|"
    r"Lighthouse|chrome-extension://|sourcemap|source map",
    re.IGNORECASE,
)
# Requests to these resource types failing is usually cosmetic.
_MINOR_RESOURCES = {"image", "font", "media"}


def _slug(url: str, index: int) -> str:
    """Filesystem-safe screenshot name derived from the URL."""
    tail = re.sub(r"^https?://", "", url)
    tail = re.sub(r"[^A-Za-z0-9._-]+", "-", tail).strip("-")
    return f"{index:02d}-{tail[:60] or 'page'}"


def crawl(
    start_url: str,
    *,
    pages_dir: Path,
    max_pages: int = 20,
    page_timeout_s: int = 30,
    settle_ms: int = 1500,
    run_axe: bool = True,
) -> list[PageObservation]:
    """Breadth-first crawl of *start_url*, staying on the same origin."""
    # Imported here so that merely importing this module does not require a
    # browser to be installed; check_env reports that separately.
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    axe = None
    if run_axe:
        from axe_playwright_python.sync_playwright import Axe

        axe = Axe()

    pages_dir.mkdir(parents=True, exist_ok=True)
    observations: list[PageObservation] = []

    start = normalize_url(start_url)
    if not start:
        raise ValueError(f"cannot crawl {start_url!r}: not an http(s) URL")

    queue: deque[str] = deque([start])
    seen: set[str] = {start}

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        # A test target frequently has a self-signed certificate; refusing to
        # load it would end the crawl before it starts.
        context = browser.new_context(ignore_https_errors=True)
        try:
            while queue and len(observations) < max_pages:
                url = queue.popleft()
                observation = _visit(
                    context,
                    url,
                    index=len(observations),
                    pages_dir=pages_dir,
                    timeout_ms=page_timeout_s * 1000,
                    settle_ms=settle_ms,
                    axe=axe,
                    playwright_error=PlaywrightError,
                )
                observations.append(observation)

                for link in observation.links:
                    candidate = normalize_url(link, base=url)
                    if not candidate or candidate in seen:
                        continue
                    if not same_origin(candidate, start):
                        continue
                    seen.add(candidate)
                    queue.append(candidate)
        finally:
            context.close()
            browser.close()

    log.info("crawled %d page(s) from %s", len(observations), start)
    return observations


def observe_pages(
    urls: list[str],
    *,
    pages_dir: Path,
    page_timeout_s: int = 30,
    settle_ms: int = 1500,
) -> list[PageObservation]:
    """Visit exactly these URLs in a brand-new browser, following no links.

    Used by verification: a console error or failed request seen during the
    crawl only counts if it happens again in a fresh session, which filters
    out one-off network hiccups and state left over from earlier pages.
    """
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import sync_playwright

    pages_dir.mkdir(parents=True, exist_ok=True)
    observations: list[PageObservation] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        try:
            for index, url in enumerate(urls):
                observations.append(
                    _visit(
                        context,
                        url,
                        index=index,
                        pages_dir=pages_dir,
                        timeout_ms=page_timeout_s * 1000,
                        settle_ms=settle_ms,
                        axe=None,
                        playwright_error=PlaywrightError,
                    )
                )
        finally:
            context.close()
            browser.close()
    return observations


def _visit(
    context,
    url: str,
    *,
    index: int,
    pages_dir: Path,
    timeout_ms: int,
    settle_ms: int,
    axe,
    playwright_error: type[Exception],
) -> PageObservation:
    """Load one page and record everything observable about it."""
    observation = PageObservation(url=url)
    page = context.new_page()

    console_errors: list[str] = []
    failures: list[NetworkFailure] = []

    def on_console(message) -> None:
        if message.type == "error" and not _IGNORED_CONSOLE.search(message.text):
            console_errors.append(message.text.strip()[:500])

    def on_page_error(error) -> None:
        # An uncaught exception: stronger evidence than a console.error call.
        console_errors.append(f"Uncaught exception: {str(error).strip()[:500]}")

    def on_request_failed(request) -> None:
        failures.append(
            NetworkFailure(
                url=request.url,
                reason=(request.failure or "request failed"),
                resource_type=request.resource_type,
            )
        )

    def on_response(response) -> None:
        if response.status >= 400:
            failures.append(
                NetworkFailure(
                    url=response.url,
                    status=response.status,
                    reason=response.status_text or "",
                    resource_type=response.request.resource_type,
                )
            )

    page.on("console", on_console)
    page.on("pageerror", on_page_error)
    page.on("requestfailed", on_request_failed)
    page.on("response", on_response)

    try:
        response = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        observation.status = response.status if response else None
        # Give a single-page application time to render its route before the
        # screenshot, the accessibility pass and the link harvest.
        page.wait_for_timeout(settle_ms)

        observation.title = (page.title() or "").strip()

        try:
            structure = page.evaluate(PAGE_STRUCTURE_SCRIPT)
        except playwright_error as exc:
            structure = {}
            log.debug("structure extraction failed on %s: %s", url, exc)
        observation.structure = structure or {}
        observation.links = [
            item.get("href", "") for item in (structure or {}).get("links", []) if item.get("href")
        ]

        screenshot_path = pages_dir / f"{_slug(url, index)}.png"
        try:
            page.screenshot(path=str(screenshot_path))
            observation.screenshot = screenshot_path.name
        except playwright_error as exc:
            log.debug("screenshot failed on %s: %s", url, exc)

        if axe is not None:
            try:
                observation.axe = axe.run(page).response
            except Exception as exc:  # noqa: BLE001 - never let a11y kill the crawl
                log.warning("axe failed on %s: %s", url, exc)

    except playwright_error as exc:
        # A page that will not load is itself a finding, so record and move on.
        observation.load_error = str(exc).splitlines()[0][:300]
        log.warning("could not load %s: %s", url, observation.load_error)
    finally:
        observation.console_errors = console_errors
        observation.network_failures = _dedupe_failures(failures)
        page.close()

    return observation


def _dedupe_failures(failures: list[NetworkFailure]) -> list[NetworkFailure]:
    """Collapse repeated failures of the same URL, keeping the first of each."""
    seen: set[tuple[str, int | None]] = set()
    unique: list[NetworkFailure] = []
    for failure in failures:
        key = (failure.url, failure.status)
        if key in seen:
            continue
        seen.add(key)
        unique.append(failure)
    return unique


def is_minor_resource(resource_type: str) -> bool:
    """Whether a failed request for this resource type is cosmetic."""
    return resource_type in _MINOR_RESOURCES
