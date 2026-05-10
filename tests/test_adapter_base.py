# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

from pathlib import Path

import pytest
from custodian.adapters.base import ToolAdapter
from custodian.core.finding import Finding, HIGH
from custodian.core.runner import run_adapters, filter_findings


class _AlwaysAvailableAdapter(ToolAdapter):
    name = "always"

    def is_available(self) -> bool:
        return True

    def run(self, repo_path: Path, config: dict) -> list[Finding]:
        return [Finding(tool=self.name, rule="TEST", severity=HIGH, path="a.py", line=1, message="test")]


class _NeverAvailableAdapter(ToolAdapter):
    name = "never"

    def is_available(self) -> bool:
        return False

    def run(self, repo_path: Path, config: dict) -> list[Finding]:
        raise AssertionError("run should not be called when unavailable")


class _ErrorAdapter(ToolAdapter):
    name = "explodes"

    def is_available(self) -> bool:
        return True

    def run(self, repo_path: Path, config: dict) -> list[Finding]:
        raise RuntimeError("something went wrong")


class TestToolAdapterContract:
    def test_available_adapter_runs(self, tmp_path):
        findings = run_adapters(tmp_path, [_AlwaysAvailableAdapter()], {})
        assert len(findings) == 1
        assert findings[0].rule == "TEST"

    def test_unavailable_adapter_emits_finding_not_runs(self, tmp_path):
        findings = run_adapters(tmp_path, [_NeverAvailableAdapter()], {})
        assert len(findings) == 1
        assert findings[0].rule == "TOOL_UNAVAILABLE"
        assert findings[0].tool == "never"

    def test_error_adapter_emits_tool_error(self, tmp_path):
        findings = run_adapters(tmp_path, [_ErrorAdapter()], {})
        assert len(findings) == 1
        assert findings[0].rule == "TOOL_ERROR"
        assert "something went wrong" in findings[0].message

    def test_multiple_adapters_combined(self, tmp_path):
        findings = run_adapters(tmp_path, [_AlwaysAvailableAdapter(), _NeverAvailableAdapter()], {})
        rules = {f.rule for f in findings}
        assert "TEST" in rules
        assert "TOOL_UNAVAILABLE" in rules

    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            ToolAdapter()  # type: ignore[abstract]


class TestFilterFindings:
    def _make(self, severity: str, rule: str = "R", path: str = "a.py") -> Finding:
        return Finding(tool="t", rule=rule, severity=severity, path=path, line=1, message="")

    def test_no_filter(self):
        findings = [self._make("high"), self._make("low")]
        assert filter_findings(findings) == findings

    def test_min_severity_high(self):
        findings = [self._make("high"), self._make("medium"), self._make("low")]
        result = filter_findings(findings, min_severity="high")
        assert len(result) == 1
        assert result[0].severity == "high"

    def test_ignore_rules(self):
        findings = [self._make("high", rule="E722"), self._make("high", rule="S1")]
        result = filter_findings(findings, ignore_rules={"E722"})
        assert len(result) == 1
        assert result[0].rule == "S1"

    def test_ignore_paths(self):
        findings = [self._make("high", path="tests/foo.py"), self._make("high", path="src/bar.py")]
        result = filter_findings(findings, ignore_paths={"tests/"})
        assert len(result) == 1
        assert result[0].path == "src/bar.py"


class TestFindTool:
    def test_returns_path_when_in_venv(self):
        from custodian.adapters.base import find_tool
        # ruff is always installed in dev; find_tool should locate it
        result = find_tool("ruff")
        assert result is not None
        assert "ruff" in result

    def test_returns_none_for_nonexistent_tool(self):
        from custodian.adapters.base import find_tool
        assert find_tool("__tool_that_does_not_exist_xyz__") is None


class TestGetEnabledAdapters:
    def test_empty_config_returns_no_adapters(self):
        from custodian.adapters.registry import get_enabled_adapters
        assert get_enabled_adapters({}) == []

    def test_all_false_returns_no_adapters(self):
        from custodian.adapters.registry import get_enabled_adapters
        cfg = {"tools": {"ruff": False, "mypy": False, "vulture": False}}
        assert get_enabled_adapters(cfg) == []

    def test_ruff_enabled_returns_ruff_adapter(self):
        from custodian.adapters.registry import get_enabled_adapters
        from custodian.adapters.ruff import RuffAdapter
        adapters = get_enabled_adapters({"tools": {"ruff": True}})
        assert len(adapters) == 1
        assert isinstance(adapters[0], RuffAdapter)

    def test_vulture_enabled_returns_vulture_adapter(self):
        from custodian.adapters.registry import get_enabled_adapters
        from custodian.adapters.vulture import VultureAdapter
        adapters = get_enabled_adapters({"tools": {"vulture": True}})
        assert len(adapters) == 1
        assert isinstance(adapters[0], VultureAdapter)

    def test_multiple_tools_returns_multiple_adapters(self):
        from custodian.adapters.registry import get_enabled_adapters
        adapters = get_enabled_adapters({"tools": {"ruff": True, "vulture": True}})
        assert len(adapters) == 2

    def test_vulture_custom_min_confidence(self):
        from custodian.adapters.registry import get_enabled_adapters
        from custodian.adapters.vulture import VultureAdapter
        adapters = get_enabled_adapters({"tools": {"vulture": True, "vulture_min_confidence": 80}})
        assert isinstance(adapters[0], VultureAdapter)
        assert adapters[0]._min_confidence == 80
