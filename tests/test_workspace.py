"""Tests for the per-run workspace layout."""

from __future__ import annotations

import re

from qa_agent.workspace import RunWorkspace, new_run_id

RUN_ID_PATTERN = re.compile(r"^\d{8}-\d{6}-[0-9a-f]{6}$")


def test_new_run_id_is_sortable_and_unique():
    # Arrange / Act
    first = new_run_id()
    second = new_run_id()

    # Assert
    assert RUN_ID_PATTERN.match(first), first
    assert first != second


def test_create_makes_every_subdirectory(tmp_path):
    # Act
    workspace = RunWorkspace.create(tmp_path)

    # Assert
    for directory in (
        workspace.repo_dir,
        workspace.raw_dir,
        workspace.pages_dir,
        workspace.tests_dir,
        workspace.logs_dir,
    ):
        assert directory.is_dir()


def test_create_honours_an_explicit_run_id(tmp_path):
    workspace = RunWorkspace.create(tmp_path, run_id="20260917-100411-a3f9c1")

    assert workspace.run_id == "20260917-100411-a3f9c1"
    assert workspace.root.name == "20260917-100411-a3f9c1"


def test_raw_path_is_named_after_the_tool(tmp_path):
    workspace = RunWorkspace.create(tmp_path)

    assert workspace.raw_path("semgrep") == workspace.raw_dir / "semgrep.json"


def test_save_json_round_trips_unicode(tmp_path):
    import json

    workspace = RunWorkspace.create(tmp_path)
    payload = {"title": "cross-site scripting (XSS) — réflechi", "count": 3}

    written = workspace.save_json(workspace.raw_path("semgrep"), payload)

    assert json.loads(written.read_text(encoding="utf-8")) == payload


def test_well_known_files_live_in_the_run_root(tmp_path):
    workspace = RunWorkspace.create(tmp_path)

    assert workspace.findings_path.parent == workspace.root
    assert workspace.report_md_path.parent == workspace.root
    assert workspace.report_html_path.parent == workspace.root
    assert workspace.command_log.parent == workspace.logs_dir
