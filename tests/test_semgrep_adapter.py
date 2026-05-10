# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from custodian.adapters.semgrep import SemgrepAdapter, _semgrep_severity
from custodian.core.finding import HIGH, MEDIUM, LOW


class TestSemgrepSeverityMapping:
    def test_error_is_high(self):        assert _semgrep_severity("ERROR") == HIGH
    def test_warning_is_medium(self):    assert _semgrep_severity("WARNING") == MEDIUM
    def test_info_is_low(self):          assert _semgrep_severity("INFO") == LOW
    def test_inventory_is_low(self):     assert _semgrep_severity("INVENTORY") == LOW
    def test_experiment_is_low(self):    assert _semgrep_severity("EXPERIMENT") == LOW
    def test_unknown_falls_back(self):   assert _semgrep_severity("WHATEVER") == MEDIUM
    def test_case_insensitive(self):     assert _semgrep_severity("error") == HIGH


class TestSemgrepAdapterAvailability:
    def test_available_when_semgrep_found(self):
        with patch("custodian.adapters.semgrep.find_tool", return_value="/usr/bin/semgrep"):
            assert SemgrepAdapter().is_available() is True

    def test_unavailable_when_semgrep_missing(self):
        with patch("custodian.adapters.semgrep.find_tool", return_value=None):
            assert SemgrepAdapter().is_available() is False


class TestSemgrepAdapterRun:
    def _make_result(self, *, check_id="rules.my-rule", message="bad code",
                     severity="WARNING", path="src/foo.py", line=10):
        return {
            "check_id": check_id,
            "extra": {"message": message, "severity": severity},
            "path": path,
            "start": {"line": line, "col": 1},
        }

    def _run_with_output(self, tmp_path, output, configs=None, returncode=0):
        (tmp_path / "src").mkdir(exist_ok=True)
        adapter = SemgrepAdapter(configs=configs or [str(tmp_path / "rules" / "semgrep")])
        proc = MagicMock()
        proc.stdout = output
        proc.returncode = returncode
        with patch("subprocess.run", return_value=proc):
            return adapter.run(tmp_path, {})

    def test_no_configs_no_rules_dir_returns_empty(self, tmp_path):
        (tmp_path / "src").mkdir()
        adapter = SemgrepAdapter(configs=[])
        findings = adapter.run(tmp_path, {})
        assert findings == []

    def test_uses_rules_dir_when_no_explicit_config(self, tmp_path):
        (tmp_path / "src").mkdir()
        rules_dir = tmp_path / "rules" / "semgrep"
        rules_dir.mkdir(parents=True)
        data = {"results": [self._make_result(path=str(tmp_path / "src" / "foo.py"))]}
        proc = MagicMock()
        proc.stdout = json.dumps(data)
        with patch("subprocess.run", return_value=proc):
            findings = SemgrepAdapter().run(tmp_path, {})
        assert len(findings) == 1

    def test_empty_stdout_returns_empty(self, tmp_path):
        findings = self._run_with_output(tmp_path, "   ")
        assert findings == []

    def test_non_json_stdout_returns_tool_error(self, tmp_path):
        findings = self._run_with_output(tmp_path, "semgrep: error: something went wrong")
        assert len(findings) == 1
        assert findings[0].rule == "TOOL_ERROR"

    def test_binary_not_found_returns_unavailable(self, tmp_path):
        (tmp_path / "src").mkdir(exist_ok=True)
        adapter = SemgrepAdapter(configs=["/some/rules"])
        with patch("subprocess.run", side_effect=FileNotFoundError):
            findings = adapter.run(tmp_path, {})
        assert len(findings) == 1
        assert findings[0].rule == "TOOL_UNAVAILABLE"
        assert findings[0].tool == "semgrep"

    def test_parses_single_finding(self, tmp_path):
        result = self._make_result(
            check_id="my.rules.sql-injection",
            message="SQL injection risk",
            severity="ERROR",
            path=str(tmp_path / "src" / "db.py"),
            line=42,
        )
        data = {"results": [result]}
        findings = self._run_with_output(tmp_path, json.dumps(data))
        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "semgrep"
        assert f.rule == "sql-injection"
        assert f.severity == HIGH
        assert f.line == 42
        assert f.message == "SQL injection risk"

    def test_rule_id_extracts_last_segment(self, tmp_path):
        result = self._make_result(check_id="a.b.c.my-rule")
        data = {"results": [result]}
        findings = self._run_with_output(tmp_path, json.dumps(data))
        assert findings[0].rule == "my-rule"

    def test_rule_id_no_dots(self, tmp_path):
        result = self._make_result(check_id="simple-rule")
        data = {"results": [result]}
        findings = self._run_with_output(tmp_path, json.dumps(data))
        assert findings[0].rule == "simple-rule"

    def test_path_relativized(self, tmp_path):
        abs_path = str(tmp_path / "src" / "module" / "foo.py")
        result = self._make_result(path=abs_path)
        data = {"results": [result]}
        findings = self._run_with_output(tmp_path, json.dumps(data))
        assert findings[0].path == "src/module/foo.py"

    def test_path_outside_repo_kept_as_is(self, tmp_path):
        result = self._make_result(path="/totally/external/file.py")
        data = {"results": [result]}
        findings = self._run_with_output(tmp_path, json.dumps(data))
        assert findings[0].path == "/totally/external/file.py"

    def test_empty_results_list(self, tmp_path):
        data = {"results": []}
        findings = self._run_with_output(tmp_path, json.dumps(data))
        assert findings == []

    def test_multiple_findings(self, tmp_path):
        results = [
            self._make_result(check_id="r.a", severity="ERROR", line=1),
            self._make_result(check_id="r.b", severity="WARNING", line=2),
            self._make_result(check_id="r.c", severity="INFO", line=3),
        ]
        data = {"results": results}
        findings = self._run_with_output(tmp_path, json.dumps(data))
        assert len(findings) == 3
        assert [f.severity for f in findings] == [HIGH, MEDIUM, LOW]

    def test_src_root_fallback_to_repo_root(self, tmp_path):
        adapter = SemgrepAdapter(configs=[str(tmp_path / "rules")])
        proc = MagicMock()
        proc.stdout = json.dumps({"results": []})
        with patch("subprocess.run", return_value=proc) as mock_run:
            adapter.run(tmp_path, {})
        cmd = mock_run.call_args[0][0]
        assert str(tmp_path) in cmd

    def test_uses_config_src_root_when_exists(self, tmp_path):
        src = tmp_path / "my_src"
        src.mkdir()
        adapter = SemgrepAdapter(configs=[str(tmp_path / "rules")])
        proc = MagicMock()
        proc.stdout = json.dumps({"results": []})
        with patch("subprocess.run", return_value=proc) as mock_run:
            adapter.run(tmp_path, {"src_root": "my_src"})
        cmd = mock_run.call_args[0][0]
        assert str(src) in cmd
