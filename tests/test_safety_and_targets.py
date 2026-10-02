"""Tests for the active-scanning guardrail and target classification."""

from __future__ import annotations

import pytest

from qa_agent.input.target import TargetKind, classify_target, repo_name
from qa_agent.safety import (
    HostClass,
    TargetNotAllowed,
    assert_target_allowed,
    classify_host,
    host_of,
)
from qa_agent.tools.zap import rewrite_for_container


# --------------------------------------------------------------------------
# host classification
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "host",
    ["127.0.0.1", "localhost", "::1", "LOCALHOST", "app.localhost"],
)
def test_loopback_hosts_are_recognised(host):
    assert classify_host(host) == HostClass.LOOPBACK


@pytest.mark.parametrize(
    "host",
    ["10.0.0.5", "192.168.1.20", "172.16.3.4", "host.docker.internal", "staging.internal"],
)
def test_private_hosts_are_recognised(host):
    assert classify_host(host) == HostClass.PRIVATE


@pytest.mark.parametrize("host", ["8.8.8.8", "93.184.216.34"])
def test_public_addresses_are_recognised(host):
    assert classify_host(host) == HostClass.PUBLIC


def test_unresolvable_name_is_unknown():
    assert classify_host("this-host-does-not-exist.invalid") == HostClass.UNKNOWN


def test_empty_host_is_unknown():
    assert classify_host("") == HostClass.UNKNOWN


def test_host_of_handles_a_bare_host_and_port():
    assert host_of("localhost:3000") == "localhost"
    assert host_of("http://127.0.0.1:8080/path") == "127.0.0.1"


# --------------------------------------------------------------------------
# the guardrail
# --------------------------------------------------------------------------
def test_local_target_is_allowed():
    assert assert_target_allowed("http://localhost:3000", allow_public=False) == HostClass.LOOPBACK


def test_private_target_is_allowed():
    assert assert_target_allowed("http://192.168.1.10", allow_public=False) == HostClass.PRIVATE


def test_public_target_is_refused_by_default():
    with pytest.raises(TargetNotAllowed) as error:
        assert_target_allowed("http://8.8.8.8", allow_public=False)
    assert "not loopback or private" in str(error.value)


def test_unresolvable_target_fails_closed():
    with pytest.raises(TargetNotAllowed):
        assert_target_allowed("http://nope.invalid", allow_public=False)


def test_public_target_is_allowed_only_with_the_explicit_override():
    assert assert_target_allowed("http://8.8.8.8", allow_public=True) == HostClass.PUBLIC


# --------------------------------------------------------------------------
# target classification
# --------------------------------------------------------------------------
@pytest.mark.parametrize(
    "value",
    [
        "https://github.com/juice-shop/juice-shop.git",
        "https://github.com/juice-shop/juice-shop",
        "git@github.com:owner/repo.git",
        "https://gitlab.com/group/project",
        "ssh://git@example.com/repo",
    ],
)
def test_repository_urls_are_detected(value):
    assert classify_target(value) == TargetKind.GIT_REPO


@pytest.mark.parametrize(
    "value",
    [
        "http://localhost:3000",
        "https://example.com/shop",
        # A deeper GitHub path is a page, not something to clone.
        "https://github.com/owner/repo/issues/12",
    ],
)
def test_application_urls_are_detected(value):
    assert classify_target(value) == TargetKind.WEB_APP


def test_an_existing_directory_is_a_local_path(tmp_path):
    assert classify_target(str(tmp_path)) == TargetKind.LOCAL_PATH


def test_empty_target_is_rejected():
    with pytest.raises(ValueError):
        classify_target("   ")


def test_repo_name_is_filesystem_safe():
    assert repo_name("https://github.com/juice-shop/juice-shop.git") == "juice-shop"
    assert repo_name("git@github.com:owner/my repo.git") == "my-repo"


# --------------------------------------------------------------------------
# container networking
# --------------------------------------------------------------------------
def test_loopback_is_rewritten_for_the_zap_container():
    assert (
        rewrite_for_container("http://localhost:3000/shop", "host.docker.internal")
        == "http://host.docker.internal:3000/shop"
    )


def test_non_loopback_targets_are_left_alone():
    url = "http://192.168.1.5:8080/"
    assert rewrite_for_container(url, "host.docker.internal") == url
