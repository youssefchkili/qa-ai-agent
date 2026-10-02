"""What the crawler records about one page, and how URLs are normalised.

The observation is deliberately plain data: the crawler produces it, parsers
turn parts of it into findings, and phase 2 hands the ``structure`` field to
the LLM so it can propose user flows to test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urldefrag, urljoin, urlparse, urlunparse


@dataclass
class NetworkFailure:
    """A request the browser could not complete, or that came back 4xx/5xx."""

    url: str
    status: int | None = None
    reason: str = ""
    resource_type: str = ""


@dataclass
class PageObservation:
    """Everything one page visit produced."""

    url: str
    title: str = ""
    status: int | None = None
    load_error: str = ""
    console_errors: list[str] = field(default_factory=list)
    network_failures: list[NetworkFailure] = field(default_factory=list)
    screenshot: str = ""
    axe: dict[str, Any] | None = None
    structure: dict[str, Any] = field(default_factory=dict)
    links: list[str] = field(default_factory=list)


def is_hash_route(url: str) -> bool:
    """True when the fragment is a client-side route rather than an anchor.

    Single-page applications such as OWASP Juice Shop put the whole route in
    the fragment (``/#/login``). Stripping fragments blindly would collapse
    every page of such an app into one URL and the crawl would see a single
    page, so ``#/``-style fragments are kept while plain anchors are dropped.
    """
    fragment = urlparse(url).fragment
    return fragment.startswith("/")


def normalize_url(url: str, base: str | None = None) -> str:
    """Resolve *url* against *base* and reduce it to a canonical form."""
    absolute = urljoin(base, url) if base else url
    parsed = urlparse(absolute)

    if parsed.scheme not in ("http", "https"):
        return ""

    path = parsed.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # Keep client-side routes, discard in-page anchors.
    fragment = parsed.fragment if parsed.fragment.startswith("/") else ""
    host = parsed.netloc.lower()

    return urlunparse((parsed.scheme.lower(), host, path, "", parsed.query, fragment))


def same_origin(url: str, other: str) -> bool:
    """True when both URLs share scheme, host and port.

    The crawl stays inside the application under test; following links to
    external sites would both waste time and breach the "local targets only"
    guardrail.
    """
    first, second = urlparse(url), urlparse(other)
    return (first.scheme, first.netloc.lower()) == (second.scheme, second.netloc.lower())


def strip_fragment(url: str) -> str:
    """URL without its fragment, which is what the server actually sees."""
    return urldefrag(url)[0]


# Executed inside the page. Returns a compact description of what a user can
# interact with: forms and their fields, buttons, and links. Phase 2 feeds this
# to the local model so it can propose realistic user flows.
PAGE_STRUCTURE_SCRIPT = """
() => {
  // Icon fonts render a ligature name ("exit_to_app") on its own line before
  // the real label, so only the last non-empty line is kept.
  const clean = (s) => (s || '').split('\\n').map(x => x.trim()).filter(Boolean).pop() || '';
  const text = (el) => clean(el.innerText || el.textContent).slice(0, 80);
  const quote = (v) => v.replace(/\\\\/g, '\\\\\\\\').replace(/"/g, '\\\\"');
  const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  // A stable selector the generated tests can use, most specific first.
  const selectorFor = (el) => {
    if (el.id) return '#' + CSS.escape(el.id);
    const name = el.getAttribute('name');
    if (name) return el.tagName.toLowerCase() + '[name="' + quote(name) + '"]';
    const aria = el.getAttribute('aria-label');
    if (aria) return '[aria-label="' + quote(aria) + '"]';
    const t = text(el);
    if (t) return 'text="' + quote(t) + '"';
    return '';
  };
  const inputs = Array.from(document.querySelectorAll('input, select, textarea'))
    .filter(i => visible(i) && (i.getAttribute('type') || '') !== 'hidden')
    .slice(0, 25).map(i => ({
      selector: selectorFor(i),
      type: i.getAttribute('type') || i.tagName.toLowerCase(),
      required: i.hasAttribute('required'),
      // Disabled or read-only fields cannot be typed into; a test that tries
      // simply times out, so they are flagged for the planner.
      disabled: i.disabled || i.readOnly,
      label: i.getAttribute('aria-label') || i.getAttribute('placeholder') || ''
    })).filter(i => i.selector);
  const forms = Array.from(document.querySelectorAll('form')).slice(0, 10).map(f => ({
    action: f.getAttribute('action') || '',
    method: (f.getAttribute('method') || 'get').toLowerCase(),
    fields: Array.from(f.querySelectorAll('input, select, textarea')).slice(0, 20).map(i => ({
      name: i.getAttribute('name') || i.getAttribute('id') || '',
      selector: selectorFor(i),
      type: i.getAttribute('type') || i.tagName.toLowerCase(),
      required: i.hasAttribute('required'),
      label: i.getAttribute('aria-label') || i.getAttribute('placeholder') || ''
    }))
  }));
  const buttons = Array.from(
    document.querySelectorAll('button, [role=button], input[type=submit]')
  ).filter(visible).slice(0, 25).map(b => ({
    text: text(b) || b.getAttribute('aria-label') || '',
    id: b.getAttribute('id') || '',
    selector: selectorFor(b),
    disabled: b.hasAttribute('disabled')
  })).filter(b => b.text || b.id);
  const links = Array.from(document.querySelectorAll('a[href]')).slice(0, 200).map(a => ({
    href: a.getAttribute('href') || '',
    text: text(a)
  }));
  return {
    title: document.title || '',
    headings: Array.from(document.querySelectorAll('h1, h2')).slice(0, 10).map(text),
    inputs, forms, buttons, links
  };
}
"""
