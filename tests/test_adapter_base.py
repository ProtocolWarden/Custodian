# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for the live ToolAdapter base contract + find_tool.

(Previously these symbols were only test-referenced via the orphan
``core.runner`` pipeline; that scaffold was removed, so the live base class is
covered here directly.)"""
from __future__ import annotations

from pathlib import Path

import pytest

from custodian.adapters.base import ToolAdapter, find_tool
from custodian.core.finding import Finding


def test_find_tool_returns_none_for_missing_binary():
    assert find_tool("definitely-not-a-real-tool-xyz-123") is None


def test_find_tool_locates_an_existing_binary():
    # python3 is always present in the test environment (PATH or venv).
    assert find_tool("python3") is not None


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
