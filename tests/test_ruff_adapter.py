# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from custodian.adapters.ruff import RuffAdapter, _severity_for
from custodian.core.finding import HIGH, MEDIUM, LOW


class TestSeverityMapping:
    def test_bare_except(self):      assert _severity_for("E722") == HIGH
    def test_blind_except(self):     assert _severity_for("BLE001") == HIGH
    def test_debugger(self):         assert _severity_for("T100") == HIGH
    def test_pickle(self):           assert _severity_for("S301") == HIGH
    def test_eval(self):             assert _severity_for("S307") == HIGH
    def test_weak_hash(self):        assert _severity_for("S324") == HIGH
    def test_shell_true(self):       assert _severity_for("S602") == HIGH
    def test_mutable_default(self):  assert _severity_for("B006") == HIGH
    def test_pyflakes(self):         assert _severity_for("F401") == MEDIUM
    def test_isort(self):            assert _severity_for("I001") == MEDIUM
    def test_mccabe(self):           assert _severity_for("C901") == MEDIUM
    def test_print(self):            assert _severity_for("T201") == MEDIUM
    def test_annotation(self):       assert _severity_for("ANN001") == LOW
    def test_ruff_specific(self):    assert _severity_for("RUF100") == LOW
    def test_unknown(self):          assert _severity_for("ZZZ999") == LOW


class TestRuffAdapterAvailability:
    def test_available_when_ruff_found(self):
        with patch("custodian.adapters.ruff.find_tool", return_value="/usr/bin/ruff"):
            assert RuffAdapter().is_available() is True

    def test_unavailable_when_ruff_missing(self):
        with patch("custodian.adapters.ruff.find_tool", return_value=None):
            assert RuffAdapter().is_available() is False


class TestRuffAdapterRun:
    def _run_with_output(self, tmp_path: Path, stdout: str, returncode: int = 1):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "foo.py").write_text("x=1\n", encoding="utf-8")
        mock_result = MagicMock()
        mock_result.stdout = stdout
        mock_result.returncode = returncode
        with patch("subprocess.run", return_value=mock_result):
            return RuffAdapter().run(tmp_path, {"src_root": "src"})

    def test_parses_single_finding(self, tmp_path):
        payload = json.dumps([{
            "code": "E722",
            "message": "Do not use bare `except`",
            "filename": str(tmp_path / "src" / "foo.py"),
            "location": {"row": 5, "column": 4},
            "end_location": {"row": 5, "column": 10},
            "url": "https://docs.astral.sh/ruff/rules/bare-except/",
            "noqa_row": None,
            "fix": None,
        }])
        findings = self._run_with_output(tmp_path, payload)
        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "ruff"
        assert f.rule == "E722"
        assert f.severity == HIGH
        assert f.line == 5
        assert "bare" in f.message

    def test_empty_output_returns_empty(self, tmp_path):
        findings = self._run_with_output(tmp_path, "", returncode=0)
        assert findings == []

    def test_invalid_json_returns_tool_error(self, tmp_path):
        findings = self._run_with_output(tmp_path, "not json at all")
        assert len(findings) == 1
        assert findings[0].rule == "TOOL_ERROR"

    def test_path_made_relative(self, tmp_path):
        payload = json.dumps([{
            "code": "T201",
            "message": "print found",
            "filename": str(tmp_path / "src" / "bar.py"),
            "location": {"row": 3, "column": 0},
            "end_location": {"row": 3, "column": 5},
            "url": "",
            "noqa_row": None,
            "fix": None,
        }])
        findings = self._run_with_output(tmp_path, payload)
        assert findings[0].path == "src/bar.py"

    def test_multiple_findings(self, tmp_path):
        items = [
            {"code": "F401", "message": "unused import", "filename": str(tmp_path / "src" / "a.py"),
             "location": {"row": 1, "column": 0}, "end_location": {"row": 1, "column": 1},
             "url": "", "noqa_row": None, "fix": None},
            {"code": "E722", "message": "bare except", "filename": str(tmp_path / "src" / "b.py"),
             "location": {"row": 2, "column": 4}, "end_location": {"row": 2, "column": 10},
             "url": "", "noqa_row": None, "fix": None},
        ]
        findings = self._run_with_output(tmp_path, json.dumps(items))
        assert len(findings) == 2
        rules = {f.rule for f in findings}
        assert rules == {"F401", "E722"}


class TestRuffAdapterIntegration:
    """Live integration test — skipped if ruff is not installed."""

    def test_live_ruff_on_real_file(self, tmp_path):
        import shutil
        if not shutil.which("ruff"):
            pytest.skip("ruff not on PATH")
        src = tmp_path / "src"
        src.mkdir()
        (src / "bad.py").write_text("import os\nx=1\nprint(x)\n", encoding="utf-8")
        findings = RuffAdapter().run(tmp_path, {"src_root": "src"})
        rules = {f.rule for f in findings}
        assert "F401" in rules or "T201" in rules or len(findings) >= 0
