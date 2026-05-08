# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for W-class workspace integrity detectors (W1–W5)."""

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


def _w3(tmp_path):
    return build_workspace_detectors()[2]


def _w4(tmp_path):
    return build_workspace_detectors()[3]


def _w5(tmp_path):
    return build_workspace_detectors()[4]


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


# ── W3: .hooks/pre-commit content ────────────────────────────────────────────

class TestW3HookContent:
    def _write_hook(self, tmp_path: Path, content: str) -> None:
        hooks = tmp_path / ".hooks"
        hooks.mkdir(exist_ok=True)
        (hooks / "pre-commit").write_text(content)

    def test_no_hook_passes(self, tmp_path):
        result = _w3(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_hook_with_log_guard_passes(self, tmp_path):
        self._write_hook(tmp_path, "#!/bin/bash\ngrep .console/log.md\nexit 0\n")
        result = _w3(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_hook_without_log_guard_flagged(self, tmp_path):
        self._write_hook(tmp_path, "#!/bin/bash\necho hello\n")
        result = _w3(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 1
        assert "log.md enforcement" in result.samples[0]

    def test_hook_console_log_variant_passes(self, tmp_path):
        self._write_hook(tmp_path, "#!/bin/bash\nlog=$(git diff --cached --name-only | grep 'console/log.md')\n")
        result = _w3(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_detector_id(self, tmp_path):
        assert _w3(tmp_path).id == "W3"


# ── W4: .gitmodules branch pinning ───────────────────────────────────────────

_GITMODULES_WITH_BRANCH = """\
[submodule "external/zonos"]
\tpath = external/zonos
\turl = https://github.com/example/zonos.git
\tbranch = dev
"""

_GITMODULES_MISSING_BRANCH = """\
[submodule "external/zonos"]
\tpath = external/zonos
\turl = https://github.com/example/zonos.git
"""

_GITMODULES_MULTI_ONE_MISSING = """\
[submodule "external/a"]
\tpath = external/a
\turl = https://github.com/example/a.git
\tbranch = main

[submodule "external/b"]
\tpath = external/b
\turl = https://github.com/example/b.git
"""


class TestW4GitmodulesBranch:
    def test_no_gitmodules_passes(self, tmp_path):
        result = _w4(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_submodule_with_branch_passes(self, tmp_path):
        (tmp_path / ".gitmodules").write_text(_GITMODULES_WITH_BRANCH)
        result = _w4(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_submodule_missing_branch_flagged(self, tmp_path):
        (tmp_path / ".gitmodules").write_text(_GITMODULES_MISSING_BRANCH)
        result = _w4(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 1
        assert "zonos" in result.samples[0]

    def test_multi_submodule_one_missing_flagged(self, tmp_path):
        (tmp_path / ".gitmodules").write_text(_GITMODULES_MULTI_ONE_MISSING)
        result = _w4(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 1
        assert "external/b" in result.samples[0]

    def test_detector_id(self, tmp_path):
        assert _w4(tmp_path).id == "W4"


# ── W5: .env.example present ─────────────────────────────────────────────────

class TestW5EnvExample:
    def test_no_gitignore_passes(self, tmp_path):
        result = _w5(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_gitignore_no_env_passes(self, tmp_path):
        (tmp_path / ".gitignore").write_text("*.pyc\n__pycache__/\n")
        result = _w5(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_env_ignored_with_example_passes(self, tmp_path):
        (tmp_path / ".gitignore").write_text(".env\n.env.local\n")
        (tmp_path / ".env.example").write_text("# env vars\n")
        result = _w5(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_env_ignored_no_example_flagged(self, tmp_path):
        (tmp_path / ".gitignore").write_text(".env\n.env.local\n")
        result = _w5(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 1
        assert ".env.example is missing" in result.samples[0]

    def test_env_local_only_does_not_trigger(self, tmp_path):
        (tmp_path / ".gitignore").write_text(".env.local\n.env.*.local\n")
        result = _w5(tmp_path).detect(_ctx(tmp_path))
        assert result.count == 0

    def test_detector_id(self, tmp_path):
        assert _w5(tmp_path).id == "W5"
