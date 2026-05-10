# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

from unittest.mock import MagicMock, patch

from custodian.adapters.ty import TyAdapter, _ty_severity
from custodian.core.finding import HIGH, MEDIUM, LOW


class TestTySeverityMapping:
    def test_error_is_high(self):    assert _ty_severity("error") == HIGH
    def test_warning_is_medium(self): assert _ty_severity("warning") == MEDIUM
    def test_info_is_low(self):      assert _ty_severity("info") == LOW
    def test_case_insensitive(self): assert _ty_severity("ERROR") == HIGH
    def test_unknown_is_medium(self): assert _ty_severity("unknown") == MEDIUM


class TestTyAdapterAvailability:
    def test_available_when_ty_found(self):
        with patch("custodian.adapters.ty.find_tool", return_value="/usr/bin/ty"):
            assert TyAdapter().is_available() is True

    def test_unavailable_when_ty_missing(self):
        with patch("custodian.adapters.ty.find_tool", return_value=None):
            assert TyAdapter().is_available() is False


class TestTyAdapterRun:
    def _run_with_stderr(self, tmp_path, stderr_lines, returncode=1):
        (tmp_path / "src").mkdir(exist_ok=True)
        adapter = TyAdapter()
        proc = MagicMock()
        proc.stderr = "\n".join(stderr_lines)
        proc.stdout = ""
        proc.returncode = returncode
        with patch("subprocess.run", return_value=proc):
            return adapter.run(tmp_path, {})

    def test_binary_not_found(self, tmp_path):
        (tmp_path / "src").mkdir()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            findings = TyAdapter().run(tmp_path, {})
        assert len(findings) == 1
        assert findings[0].rule == "TOOL_UNAVAILABLE"

    def test_no_diagnostics(self, tmp_path):
        findings = self._run_with_stderr(tmp_path, ["Found 0 diagnostics"], returncode=0)
        assert findings == []

    def test_parses_error_line(self, tmp_path):
        path = str(tmp_path / "src" / "foo.py")
        stderr = [f"{path}:10:5: error[invalid-assignment] Object of type `Literal[1]` is not assignable to `str`"]
        findings = self._run_with_stderr(tmp_path, stderr)
        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "ty"
        assert f.rule == "invalid-assignment"
        assert f.severity == HIGH
        assert f.line == 10
        assert "not assignable" in f.message

    def test_path_relativized(self, tmp_path):
        path = str(tmp_path / "src" / "sub" / "bar.py")
        stderr = [f"{path}:5:1: error[missing-return] Missing return statement"]
        findings = self._run_with_stderr(tmp_path, stderr)
        assert findings[0].path == "src/sub/bar.py"

    def test_warning_severity(self, tmp_path):
        path = str(tmp_path / "src" / "x.py")
        stderr = [f"{path}:1:1: warning[possibly-unbound] Variable may be unbound"]
        findings = self._run_with_stderr(tmp_path, stderr)
        assert findings[0].severity == MEDIUM

    def test_non_matching_lines_skipped(self, tmp_path):
        findings = self._run_with_stderr(tmp_path, [
            "Found 2 diagnostics",
            "",
            "Some other output",
        ])
        assert findings == []

    def test_multiple_diagnostics(self, tmp_path):
        p = str(tmp_path / "src" / "a.py")
        stderr = [
            f"{p}:1:1: error[invalid-assignment] Bad assignment",
            f"{p}:2:1: warning[possibly-unbound] Unbound var",
            f"{p}:3:1: info[some-info] Info message",
        ]
        findings = self._run_with_stderr(tmp_path, stderr)
        assert len(findings) == 3
        assert [f.severity for f in findings] == [HIGH, MEDIUM, LOW]

    def test_uses_custom_src_root(self, tmp_path):
        custom = tmp_path / "mycode"
        custom.mkdir()
        proc = MagicMock()
        proc.stderr = ""
        proc.stdout = ""
        with patch("subprocess.run", return_value=proc) as mock_run:
            TyAdapter().run(tmp_path, {"src_root": "mycode"})
        cmd = mock_run.call_args[0][0]
        assert str(custom) in cmd
