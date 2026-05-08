# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for W-class workspace integrity detectors (W1, W2)."""

from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.workspace import build_workspace_detectors, _REQUIRED_CONSOLE_FILES


def _ctx(tmp_path: Path) -> AuditContext:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    git = tmp_path / ".git"
    git.mkdir(exist_ok=True)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path / "tests",
        config={"repo_key": "TestRepo", "src_root": "src", "tests_root": "tests"},
        plugin_modules=[],
    )


def _w1(tmp_path):
    return build_workspace_detectors()[0]


def _w2(tmp_path):
    return build_workspace_detectors()[1]


# ── W1: .console/ required files ─────────────────────────────────────────────

class TestW1ConsoleStructure:
    def test_no_console_dir_passes(self, tmp_path):
        result = _w1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_complete_console_passes(self, tmp_path):
        console = tmp_path / ".console"
        console.mkdir()
        for f in _REQUIRED_CONSOLE_FILES:
            (console / f).write_text("")
        result = _w1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_missing_log_md_flagged(self, tmp_path):
        console = tmp_path / ".console"
        console.mkdir()
        for f in _REQUIRED_CONSOLE_FILES:
            (console / f).write_text("")
        (console / "log.md").unlink()
        result = _w1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 1
        assert ".console/log.md is missing" in result.samples[0]

    def test_missing_multiple_files_flagged(self, tmp_path):
        console = tmp_path / ".console"
        console.mkdir()
        (console / "task.md").write_text("")
        result = _w1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 3  # guidelines, backlog, log missing

    def test_all_files_missing_flagged(self, tmp_path):
        (tmp_path / ".console").mkdir()
        result = _w1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == len(_REQUIRED_CONSOLE_FILES)

    def test_extra_files_ignored(self, tmp_path):
        console = tmp_path / ".console"
        console.mkdir()
        for f in _REQUIRED_CONSOLE_FILES:
            (console / f).write_text("")
        (console / ".context").write_text("generated")
        (console / "extra.md").write_text("")
        result = _w1(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_detector_id(self, tmp_path):
        assert _w1(tmp_path).id == "W1"


# ── W2: .hooks/ wiring ────────────────────────────────────────────────────────

class TestW2HooksWiring:
    def _write_git_config(self, tmp_path: Path, content: str) -> None:
        (tmp_path / ".git").mkdir(exist_ok=True)
        (tmp_path / ".git" / "config").write_text(content)

    def test_no_pre_commit_hook_passes(self, tmp_path):
        result = _w2(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_hook_wired_passes(self, tmp_path):
        (tmp_path / ".hooks").mkdir()
        (tmp_path / ".hooks" / "pre-commit").write_text("#!/bin/bash\n")
        self._write_git_config(tmp_path, "[core]\n\thooksPath = .hooks\n")
        result = _w2(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_hook_not_wired_flagged(self, tmp_path):
        (tmp_path / ".hooks").mkdir()
        (tmp_path / ".hooks" / "pre-commit").write_text("#!/bin/bash\n")
        self._write_git_config(tmp_path, "[core]\n\tfileMode = true\n")
        result = _w2(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 1
        assert "core.hooksPath is not set" in result.samples[0]
        assert "git config core.hooksPath .hooks" in result.samples[0]

    def test_hook_no_git_config_passes(self, tmp_path):
        (tmp_path / ".hooks").mkdir()
        (tmp_path / ".hooks" / "pre-commit").write_text("#!/bin/bash\n")
        # .git dir exists (created by _ctx) but no config file
        result = _w2(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_case_insensitive_hookspath(self, tmp_path):
        (tmp_path / ".hooks").mkdir()
        (tmp_path / ".hooks" / "pre-commit").write_text("#!/bin/bash\n")
        self._write_git_config(tmp_path, "[core]\n\thookspath = .hooks\n")
        result = _w2(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_detector_id(self, tmp_path):
        assert _w2(tmp_path).id == "W2"
