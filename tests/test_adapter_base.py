# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for the live ToolAdapter base contract + find_tool.

(Previously these symbols were only test-referenced via the orphan
``core.runner`` pipeline; that scaffold was removed, so the live base class is
covered here directly.)"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from custodian.adapters.base import ToolAdapter, find_tool
from custodian.core.finding import Finding


def test_find_tool_returns_none_for_missing_binary():
    assert find_tool("definitely-not-a-real-tool-xyz-123") is None


def test_find_tool_locates_an_existing_binary():
    # python3 is always present in the test environment (PATH or venv).
    assert find_tool("python3") is not None


def test_find_tool_prefers_venv_binary_that_carries_a_platform_extension(tmp_path, monkeypatch):
    """Regression: venv-first must survive platform executable extensions.

    A venv ships ``ruff.exe`` on Windows, never an extensionless ``ruff``, so
    probing the plain name with ``Path.exists()`` never matched there and EVERY
    lookup fell through to PATH — making venv-first a silent no-op on Windows.
    A venv pinned to ruff 0.15.13 resolved a newer global ruff instead, whose
    wider default rule set emitted thousands of phantom findings. Build the
    binary with the real extension for this platform and assert the venv copy
    wins even though the caller asks for the bare name.
    """
    venv_bin = tmp_path / "venv" / ("Scripts" if os.name == "nt" else "bin")
    venv_bin.mkdir(parents=True)
    suffix = ".exe" if os.name == "nt" else ""
    tool = venv_bin / f"custodian-probe-tool{suffix}"
    tool.write_text("", encoding="utf-8")
    tool.chmod(0o755)

    monkeypatch.setattr(sys, "executable", str(venv_bin / "python"))

    found = find_tool("custodian-probe-tool")
    assert found is not None, "venv binary was not found via the bare name"
    assert Path(found).parent == venv_bin


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
