# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for the live ToolAdapter base contract + find_tool.

(Previously these symbols were only test-referenced via the orphan
``core.runner`` pipeline; that scaffold was removed, so the live base class is
covered here directly.)"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from custodian.adapters.base import ToolAdapter, audited_repo, find_tool
from custodian.core.finding import Finding

# Console scripts are extensionless on POSIX and ``.exe`` on Windows; the fake
# venvs below have to be spelled the way the host actually spells them.
_EXE_SUFFIX = ".exe" if os.name == "nt" else ""
_SCRIPT_DIR = "Scripts" if os.name == "nt" else "bin"


def _fake_venv_tool(repo: Path, name: str, *, script_dir: str = _SCRIPT_DIR) -> Path:
    """Create ``repo/.venv/<script_dir>/<name>`` and return it."""
    tool = repo / ".venv" / script_dir / f"{name}{_EXE_SUFFIX}"
    tool.parent.mkdir(parents=True, exist_ok=True)
    tool.write_text("#!/bin/sh\n", encoding="utf-8")
    tool.chmod(0o755)
    return tool


def test_find_tool_returns_none_for_missing_binary():
    assert find_tool("definitely-not-a-real-tool-xyz-123") is None


def test_find_tool_locates_an_existing_binary():
    # python3 is always present in the test environment (PATH or venv).
    assert find_tool("python3") is not None


def test_find_tool_prefers_the_audited_repos_venv(tmp_path):
    """A repo's own pinned toolchain wins over Custodian's venv and PATH.

    The regression: a globally-installed custodian-multi audited a repo pinned to
    ruff 0.15.13 with a system-wide ruff 0.16.1 and reported 1222 phantom findings.
    """
    repo = tmp_path / "SomeRepo"
    repo.mkdir()
    pinned = _fake_venv_tool(repo, "ruff")

    with audited_repo(repo):
        assert find_tool("ruff") == str(pinned)


def test_find_tool_falls_back_when_the_audited_repo_has_no_venv(tmp_path):
    """No repo venv ⇒ the old behaviour (Custodian's venv, then PATH) still applies."""
    repo = tmp_path / "NoVenvRepo"
    repo.mkdir()

    with audited_repo(repo):
        assert find_tool("python3") is not None
        assert find_tool("definitely-not-a-real-tool-xyz-123") is None


def test_find_tool_accepts_either_venv_script_dir(tmp_path):
    """``bin`` and ``Scripts`` are both honoured regardless of host.

    A venv built under WSL and audited from Windows (or the reverse, over /mnt/c)
    carries the *other* platform's layout, so neither name can be assumed.
    """
    for script_dir in ("bin", "Scripts"):
        repo = tmp_path / f"Repo{script_dir}"
        repo.mkdir()
        pinned = _fake_venv_tool(repo, "vulture", script_dir=script_dir)
        with audited_repo(repo):
            assert find_tool("vulture") == str(pinned)


def test_audited_repo_scope_is_restored_on_exit(tmp_path):
    """The ContextVar must not leak past the loop — later repos would inherit it."""
    repo = tmp_path / "ScopedRepo"
    repo.mkdir()
    _fake_venv_tool(repo, "ruff")

    before = find_tool("ruff")
    with audited_repo(repo):
        assert find_tool("ruff") is not None
    assert find_tool("ruff") == before


def test_audited_repo_accepts_none(tmp_path):
    """``audited_repo(None)`` clears the scope rather than exploding."""
    repo = tmp_path / "ClearedRepo"
    repo.mkdir()
    _fake_venv_tool(repo, "ruff")

    with audited_repo(repo), audited_repo(None):
        # Scope cleared, so this falls through to Custodian's venv / PATH rather
        # than resolving repo's fake ruff — and must not raise on the None.
        assert find_tool("ruff") != str(repo / ".venv" / _SCRIPT_DIR / f"ruff{_EXE_SUFFIX}")


def test_tooladapter_is_abstract():
    with pytest.raises(TypeError):
        ToolAdapter()  # type: ignore[abstract]


def test_concrete_adapter_satisfies_the_contract():
    class _StubAdapter(ToolAdapter):
        name = "stub"

        def is_available(self) -> bool:
            return True

        def run(self, repo_path: Path, config: dict) -> list[Finding]:
            return []

    adapter = _StubAdapter()
    assert adapter.name == "stub"
    assert adapter.is_available() is True
    assert adapter.run(Path("."), {}) == []
