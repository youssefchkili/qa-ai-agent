"""Guardrail: never actively scan a target that is not ours to scan.

Crawling a site, running ZAP against it and executing generated tests are all
*active* operations: they send traffic, submit forms and can change data. Doing
that to a production system, or to someone else's server, ranges from
embarrassing to illegal.

The rule is therefore allow-list shaped and fails closed: unless the target
resolves to loopback or a private (RFC1918) address, the run stops. Setting
``QA_AGENT_ALLOW_PUBLIC_TARGETS=true`` is a deliberate, logged override.

Static analysis of a cloned repository is *passive* and is never blocked by
this module.
"""

from __future__ import annotations

import ipaddress
import socket
from enum import Enum
from urllib.parse import urlparse

from qa_agent.logging_setup import get_logger

log = get_logger(__name__)


class HostClass(str, Enum):
    """Where a host lives, as far as this guardrail is concerned."""

    LOOPBACK = "loopback"
    PRIVATE = "private"
    PUBLIC = "public"
    UNKNOWN = "unknown"


class TargetNotAllowed(RuntimeError):
    """Raised when an active scan is attempted against a non-local target."""


# Names that are local by definition and must not trigger a DNS lookup.
_LOOPBACK_NAMES = {"localhost", "ip6-localhost", "localhost.localdomain"}
# RFC 6761 reserves the whole .localhost tree for loopback.
_LOOPBACK_SUFFIXES = (".localhost",)
# Docker Desktop publishes this name so a container can reach the host machine.
_PRIVATE_NAMES = {"host.docker.internal", "gateway.docker.internal"}
_PRIVATE_SUFFIXES = (".local", ".internal", ".localdomain", ".test")


def host_of(url: str) -> str:
    """Extract the hostname from a URL, tolerating a bare ``host:port``."""
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return (parsed.hostname or "").strip().lower()


def _classify_ip(address: str) -> HostClass:
    """Classify a literal IP address."""
    ip = ipaddress.ip_address(address)
    if ip.is_loopback:
        return HostClass.LOOPBACK
    # is_private covers RFC1918 (10/8, 172.16/12, 192.168/16) plus link-local
    # and unique-local IPv6, which is exactly the "our own network" set.
    if ip.is_private or ip.is_link_local:
        return HostClass.PRIVATE
    return HostClass.PUBLIC


def classify_host(host: str) -> HostClass:
    """Decide whether *host* is loopback, private, public or unresolvable.

    A name that cannot be resolved returns ``UNKNOWN``, which the caller treats
    as "not allowed": failing closed is the safe direction for a guardrail.
    """
    host = host.strip().lower().strip("[]")
    if not host:
        return HostClass.UNKNOWN

    try:
        return _classify_ip(host)
    except ValueError:
        pass  # not a literal IP, fall through to name handling

    if host in _LOOPBACK_NAMES or host.endswith(_LOOPBACK_SUFFIXES):
        return HostClass.LOOPBACK
    if host in _PRIVATE_NAMES or host.endswith(_PRIVATE_SUFFIXES):
        return HostClass.PRIVATE

    # Resolve the name and judge the address it points at. This asks the local
    # resolver only; it is not a request to the target itself.
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError, OSError):
        return HostClass.UNKNOWN

    classes = {_classify_ip(info[4][0]) for info in infos}
    if HostClass.PUBLIC in classes:
        return HostClass.PUBLIC
    if HostClass.PRIVATE in classes:
        return HostClass.PRIVATE
    if HostClass.LOOPBACK in classes:
        return HostClass.LOOPBACK
    return HostClass.UNKNOWN


def assert_target_allowed(
    url: str, *, allow_public: bool, action: str = "actively scan"
) -> HostClass:
    """Raise :class:`TargetNotAllowed` unless *url* may be actively scanned.

    Returns the host classification so the caller can log or record it.
    """
    host = host_of(url)
    classification = classify_host(host)

    if classification in (HostClass.LOOPBACK, HostClass.PRIVATE):
        return classification

    if allow_public:
        # Explicitly permitted, but loud: this is the dangerous path.
        log.warning(
            "target %s is %s and is being scanned because "
            "QA_AGENT_ALLOW_PUBLIC_TARGETS is enabled - make sure you are authorised",
            host,
            classification.value,
        )
        return classification

    raise TargetNotAllowed(
        f"refusing to {action} '{url}': host '{host}' is {classification.value}, "
        f"not loopback or private. Point the agent at a local instance, or set "
        f"QA_AGENT_ALLOW_PUBLIC_TARGETS=true if you are authorised to test it."
    )
