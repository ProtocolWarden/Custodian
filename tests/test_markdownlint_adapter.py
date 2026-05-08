# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Markdownlint adapter tests."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from custodian.adapters.markdownlint import (
    MarkdownlintAdapter, _severity_for,
)
from custodian.core.finding import HIGH, LOW, MEDIUM


class TestSeverityMapping:
    def test_md025_high(self):
        assert _severity_for("MD025") == HIGH

    def test_md040_high(self):
        assert _severity_for("MD040") == HIGH

    def test_md001_medium(self):
        assert _severity_for("MD001") == MEDIUM

    def test_unknown_rule_low(self):
        assert _severity_for("MD999") == LOW


class TestAdapterAvailability:
    def test_returns_unavailable_when_binary_missing(self, tmp_path: Path):
        adapter = MarkdownlintAdapter()
        with patch(
            "custodian.adapters.markdownlint._binary",
            return_value=None,
        ):
            findings = adapter.run(tmp_path, {})
        assert len(findings) == 1
        assert findings[0].rule == "TOOL_UNAVAILABLE"


class TestParseCli2Output:
    def test_parses_cli2_finding_array(self, tmp_path: Path):
        adapter = MarkdownlintAdapter()
        cli2_output = json.dumps([
            {
                "fileName": "README.md",
                "lineNumber": 12,
                "ruleNames": ["MD025", "single-h1"],
                "ruleDescription": "Multiple top-level headings",
            },
            {
                "fileName": "docs/guide.md",
                "lineNumber": 3,
                "ruleNames": ["MD040"],
                "ruleDescription": "Fenced code blocks should have a language",
            },
        ])

        class _Proc:
            stdout = cli2_output
            stderr = ""

        with patch(
            "custodian.adapters.markdownlint._binary",
            return_value="/usr/bin/markdownlint-cli2",
        ), patch(
            "subprocess.run", return_value=_Proc(),
        ):
            findings = adapter.run(tmp_path, {})

        assert len(findings) == 2
        assert findings[0].rule == "MD025"
        assert findings[0].severity == HIGH
        assert findings[0].path == "README.md"
        assert findings[0].line == 12
        assert findings[1].rule == "MD040"
        assert findings[1].severity == HIGH


class TestParseLegacyOutput:
    def test_parses_legacy_finding_dict(self, tmp_path: Path):
        adapter = MarkdownlintAdapter()
        legacy_output = json.dumps({
            "README.md": [
                {
                    "lineNumber": 1,
                    "ruleNames": ["MD025"],
                    "ruleDescription": "Multiple H1s",
                },
            ],
            "docs/x.md": [
                {
                    "lineNumber": 7,
                    "ruleNames": ["MD003"],
                    "ruleDescription": "Heading style",
                },
            ],
        })

        class _Proc:
            stdout = legacy_output
            stderr = ""

        with patch(
            "custodian.adapters.markdownlint._binary",
            return_value="/usr/bin/markdownlint",
        ), patch(
            "subprocess.run", return_value=_Proc(),
        ):
            findings = adapter.run(tmp_path, {})

        assert len(findings) == 2
        rules = {f.rule for f in findings}
        assert rules == {"MD025", "MD003"}


class TestEmptyOutputIsClean:
    def test_zero_findings_when_stdout_empty(self, tmp_path: Path):
        adapter = MarkdownlintAdapter()

        class _Proc:
            stdout = ""
            stderr = ""

        with patch(
            "custodian.adapters.markdownlint._binary",
            return_value="/usr/bin/markdownlint-cli2",
        ), patch(
            "subprocess.run", return_value=_Proc(),
        ):
            findings = adapter.run(tmp_path, {})

        assert findings == []

    def test_invalid_json_yields_zero_findings(self, tmp_path: Path):
        adapter = MarkdownlintAdapter()

        class _Proc:
            stdout = "not json garbage"
            stderr = ""

        with patch(
            "custodian.adapters.markdownlint._binary",
            return_value="/usr/bin/markdownlint-cli2",
        ), patch(
            "subprocess.run", return_value=_Proc(),
        ):
            findings = adapter.run(tmp_path, {})

        assert findings == []


class TestRegistryWiring:
    def test_truthy_value_registers_adapter(self):
        from custodian.adapters.registry import get_enabled_adapters
        adapters = get_enabled_adapters({"tools": {"markdownlint": True}})
        names = [a.name for a in adapters]
        assert "markdownlint" in names

    def test_dict_config_registers_adapter_with_overrides(self):
        from custodian.adapters.registry import get_enabled_adapters
        adapters = get_enabled_adapters({"tools": {
            "markdownlint": {
                "globs": ["README.md"],
                "config": ".markdownlint.yaml",
                "timeout": 30,
            },
        }})
        md = next(a for a in adapters if a.name == "markdownlint")
        assert md._globs == ["README.md"]
        assert md._config == ".markdownlint.yaml"
        assert md._timeout == 30

    def test_absent_config_does_not_register(self):
        from custodian.adapters.registry import get_enabled_adapters
        adapters = get_enabled_adapters({"tools": {}})
        assert all(a.name != "markdownlint" for a in adapters)
