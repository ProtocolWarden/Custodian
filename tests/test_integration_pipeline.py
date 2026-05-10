# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Integration tests — adapter → filter → report pipeline."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from custodian.adapters.ruff import RuffAdapter
from custodian.core.finding import Finding, HIGH, MEDIUM, LOW
from custodian.core.runner import run_adapters, filter_findings
from custodian.policy.filter import apply_policy
from custodian.reports.json_report import build_json_report
from custodian.reports.sarif_report import build_sarif_report


class TestAdapterToFilterPipeline:
    def test_ruff_findings_filtered_by_severity(self, tmp_path):
        (tmp_path / "src").mkdir()
        ruff_output = json.dumps([
            {"code": "E722", "message": "bare except", "filename": str(tmp_path / "src/a.py"),
             "location": {"row": 5, "column": 0}, "end_location": {"row": 5, "column": 10},
             "fix": None, "url": "", "noqa_row": None},
            {"code": "ANN001", "message": "missing annotation", "filename": str(tmp_path / "src/b.py"),
             "location": {"row": 1, "column": 0}, "end_location": {"row": 1, "column": 5},
             "fix": None, "url": "", "noqa_row": None},
        ])
        proc = MagicMock()
        proc.stdout = ruff_output
        proc.returncode = 1
        with patch("subprocess.run", return_value=proc):
            findings = RuffAdapter().run(tmp_path, {})

        filtered = apply_policy(findings, min_severity="medium")
        rules = {f.rule for f in filtered}
        assert "E722" in rules
        assert "ANN001" not in rules

    def test_ignore_paths_removes_test_findings(self, tmp_path):
        (tmp_path / "src").mkdir()
        ruff_output = json.dumps([
            {"code": "E722", "message": "bare except", "filename": str(tmp_path / "src/foo.py"),
             "location": {"row": 1, "column": 0}, "end_location": {"row": 1, "column": 5},
             "fix": None, "url": "", "noqa_row": None},
            {"code": "E722", "message": "bare except", "filename": str(tmp_path / "tests/test_foo.py"),
             "location": {"row": 1, "column": 0}, "end_location": {"row": 1, "column": 5},
             "fix": None, "url": "", "noqa_row": None},
        ])
        proc = MagicMock()
        proc.stdout = ruff_output
        proc.returncode = 1
        with patch("subprocess.run", return_value=proc):
            findings = RuffAdapter().run(tmp_path, {})

        filtered = apply_policy(findings, ignore_paths=["tests/**"])
        paths = [f.path for f in filtered]
        assert all("tests" not in (p or "") for p in paths)

    def test_full_pipeline_to_json_report(self, tmp_path):
        findings = [
            Finding(tool="ruff", rule="E722", severity=HIGH, path="src/a.py", line=5, message="bad"),
            Finding(tool="ty", rule="invalid-assignment", severity=HIGH, path="src/b.py", line=10, message="type error"),
            Finding(tool="ruff", rule="ANN001", severity=LOW, path="src/c.py", line=1, message="annotation"),
        ]
        filtered = apply_policy(findings, min_severity="high")
        assert len(filtered) == 2

        report_json = build_json_report(filtered, repo_key="test-repo")
        doc = json.loads(report_json)
        assert doc["repo"] == "test-repo"
        assert doc["summary"]["total"] == 2
        assert doc["summary"]["high"] == 2
        assert doc["summary"]["low"] == 0

    def test_full_pipeline_to_sarif(self):
        findings = [
            Finding(tool="semgrep", rule="sqli", severity=HIGH, path="src/db.py", line=42, message="SQL injection"),
            Finding(tool="ruff", rule="F401", severity=MEDIUM, path="src/x.py", line=1, message="unused"),
        ]
        sarif = json.loads(build_sarif_report(findings))
        assert sarif["version"] == "2.1.0"
        tool_names = {r["tool"]["driver"]["name"] for r in sarif["runs"]}
        assert "semgrep" in tool_names
        assert "ruff" in tool_names


class TestRunAdapters:
    def test_unavailable_adapter_returns_tool_unavailable(self, tmp_path):
        (tmp_path / ".custodian.yaml").write_text("repo_key: test\n")

        class AlwaysUnavailable(RuffAdapter):
            def is_available(self): return False

        findings = run_adapters(tmp_path, [AlwaysUnavailable()], {})
        assert any(f.rule == "TOOL_UNAVAILABLE" for f in findings)

    def test_available_adapter_called(self, tmp_path):
        (tmp_path / "src").mkdir()
        proc = MagicMock()
        proc.stdout = json.dumps([])
        proc.returncode = 0
        with patch("subprocess.run", return_value=proc):
            findings = run_adapters(tmp_path, [RuffAdapter()], {})
        assert findings == []


class TestFilterFindings:
    def test_filter_findings_delegates_to_apply_policy(self):
        findings = [
            Finding(tool="t", rule="A", severity=HIGH, path="src/x.py", line=1, message="m"),
            Finding(tool="t", rule="B", severity=LOW, path="src/y.py", line=1, message="m"),
        ]
        result = filter_findings(findings, min_severity="high", ignore_rules=[], ignore_paths=[])
        assert len(result) == 1
        assert result[0].rule == "A"
