# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

from unittest.mock import MagicMock, patch

from custodian.adapters.mypy import MypyAdapter, _mypy_severity
from custodian.core.finding import HIGH, MEDIUM, LOW


class TestMypySeverityMapping:
    def test_error_is_high(self):    assert _mypy_severity("error") == HIGH
    def test_warning_is_medium(self): assert _mypy_severity("warning") == MEDIUM
    def test_note_is_low(self):      assert _mypy_severity("note") == LOW
    def test_unknown_is_medium(self): assert _mypy_severity("other") == MEDIUM


class TestMypyAdapterAvailability:
    def test_available(self):
        with patch("custodian.adapters.mypy.find_tool", return_value="/usr/bin/mypy"):
            assert MypyAdapter().is_available() is True

    def test_unavailable(self):
        with patch("custodian.adapters.mypy.find_tool", return_value=None):
            assert MypyAdapter().is_available() is False


class TestMypyAdapterRun:
    def _run(self, tmp_path, stdout_lines, returncode=1):
        (tmp_path / "src").mkdir(exist_ok=True)
        proc = MagicMock()
        proc.stdout = "\n".join(stdout_lines)
        proc.stderr = ""
        proc.returncode = returncode
        with patch("subprocess.run", return_value=proc):
            return MypyAdapter().run(tmp_path, {})

    def test_not_found_returns_unavailable(self, tmp_path):
        (tmp_path / "src").mkdir()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            findings = MypyAdapter().run(tmp_path, {})
        assert findings[0].rule == "TOOL_UNAVAILABLE"

    def test_parses_error_with_code(self, tmp_path):
        path = str(tmp_path / "src" / "foo.py")
        findings = self._run(tmp_path, [f"{path}:10:5: error: Incompatible types  [assignment]"])
        assert len(findings) == 1
        f = findings[0]
        assert f.rule == "assignment"
        assert f.severity == HIGH
        assert f.line == 10

    def test_parses_error_without_code(self, tmp_path):
        path = str(tmp_path / "src" / "foo.py")
        findings = self._run(tmp_path, [f"{path}:5:1: error: Cannot determine type"])
        assert len(findings) == 1
        assert findings[0].rule == "mypy"

    def test_notes_are_skipped(self, tmp_path):
        path = str(tmp_path / "src" / "foo.py")
        findings = self._run(tmp_path, [
            f"{path}:5:1: error: Bad type  [arg-type]",
            f"{path}:5:1: note: See here for details",
        ])
        assert len(findings) == 1

    def test_empty_output(self, tmp_path):
        findings = self._run(tmp_path, [], returncode=0)
        assert findings == []

    def test_path_relativized(self, tmp_path):
        path = str(tmp_path / "src" / "x.py")
        findings = self._run(tmp_path, [f"{path}:1:1: error: Bad  [misc]"])
        assert findings[0].path == "src/x.py"

    def test_non_matching_lines_skipped(self, tmp_path):
        findings = self._run(tmp_path, ["Success: no issues found"])
        assert findings == []
