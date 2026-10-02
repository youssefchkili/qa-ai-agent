"""Turn crawler observations into findings.

A JavaScript exception or a failed request is not a "potential" problem that
needs interpreting: the browser actually hit it while loading the page, and
there is a screenshot of the moment. These are among the most trustworthy
findings the agent produces.
"""

from __future__ import annotations

from qa_agent.models.finding import Category, Finding, Severity, Tool
from qa_agent.parsers.common import truncate
from qa_agent.web.crawler import is_minor_resource
from qa_agent.web.page_model import PageObservation

# Only the first few errors per page; one broken loop can log hundreds.
MAX_CONSOLE_ERRORS = 5
MAX_NETWORK_FAILURES = 8


def _console_findings(page: PageObservation) -> list[Finding]:
    findings: list[Finding] = []
    for message in page.console_errors[:MAX_CONSOLE_ERRORS]:
        uncaught = message.startswith("Uncaught exception:")
        findings.append(
            Finding(
                tool=Tool.CRAWLER,
                category=Category.FUNCTIONAL,
                # An uncaught exception usually means a broken feature;
                # a console.error may be deliberate logging.
                severity=Severity.HIGH if uncaught else Severity.MEDIUM,
                title=(
                    "Uncaught JavaScript exception on page"
                    if uncaught
                    else "JavaScript console error on page"
                ),
                location=page.url,
                description=truncate(
                    "The browser reported an error while loading this page. "
                    "Scripted behaviour on the page may be partly or fully broken."
                ),
                evidence=truncate(message, 600)
                + (f"\nscreenshot: {page.screenshot}" if page.screenshot else ""),
                # The message text is the rule identity here: two different
                # errors on one page must stay two findings.
                rule_id=f"console:{truncate(message, 120)}",
                metadata={"page": page.url, "message": truncate(message, 300)},
            )
        )
    return findings


def _network_findings(page: PageObservation) -> list[Finding]:
    findings: list[Finding] = []
    for failure in page.network_failures[:MAX_NETWORK_FAILURES]:
        status = failure.status
        if status is not None and status >= 500:
            severity = Severity.HIGH
            headline = f"Server error {status} for a request made by this page"
        elif status is not None:
            severity = Severity.LOW if is_minor_resource(failure.resource_type) else Severity.MEDIUM
            headline = f"Failed request ({status}) made by this page"
        else:
            severity = Severity.MEDIUM
            headline = "Network request could not be completed"

        findings.append(
            Finding(
                tool=Tool.CRAWLER,
                category=Category.FUNCTIONAL,
                severity=severity,
                title=headline,
                location=page.url,
                description=truncate(
                    f"While loading {page.url} the browser requested {failure.url} "
                    f"and it did not succeed ({failure.reason or status})."
                ),
                evidence=f"{failure.resource_type or 'request'} {failure.url} -> "
                f"{status or failure.reason}",
                rule_id=f"network:{status or 'failed'}:{failure.url}",
                metadata={
                    "page": page.url,
                    "request_url": failure.url,
                    "status": status,
                    "resource_type": failure.resource_type,
                },
            )
        )
    return findings


def _load_failure_finding(page: PageObservation) -> list[Finding]:
    if not page.load_error:
        return []
    return [
        Finding(
            tool=Tool.CRAWLER,
            category=Category.FUNCTIONAL,
            severity=Severity.HIGH,
            title="Page failed to load",
            location=page.url,
            description=truncate(
                f"The crawler could not load {page.url}. A page that does not load "
                f"cannot be used at all."
            ),
            evidence=truncate(page.load_error, 400),
            rule_id="page-load-failed",
            metadata={"page": page.url},
        )
    ]


def _http_status_finding(page: PageObservation) -> list[Finding]:
    """A page answering 4xx/5xx is broken navigation, not just a bad request."""
    if page.status is None or page.status < 400:
        return []
    return [
        Finding(
            tool=Tool.CRAWLER,
            category=Category.FUNCTIONAL,
            severity=Severity.HIGH if page.status >= 500 else Severity.MEDIUM,
            title=f"Page returned HTTP {page.status}",
            location=page.url,
            description=truncate(
                f"Navigating to {page.url} returned status {page.status}, "
                f"so this page is reachable by a link but does not work."
            ),
            evidence=f"GET {page.url} -> {page.status}",
            rule_id=f"http-status:{page.status}",
            metadata={"page": page.url, "status": page.status},
        )
    ]


def parse_page(page: PageObservation) -> list[Finding]:
    """All findings derived from one crawled page, excluding accessibility."""
    return [
        *_load_failure_finding(page),
        *_http_status_finding(page),
        *_console_findings(page),
        *_network_findings(page),
    ]


def parse_pages(pages: list[PageObservation]) -> list[Finding]:
    """All browser-derived findings for the whole crawl."""
    findings: list[Finding] = []
    for page in pages:
        findings.extend(parse_page(page))
    return findings
