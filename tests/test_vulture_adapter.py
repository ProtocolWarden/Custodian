# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

from unittest.mock import MagicMock, patch

from custodian.adapters.vulture import VultureAdapter, _rule_from_message
from custodian.core.finding import LOW


class TestRuleFromMessage:
    def test_unused_function(self): assert _rule_from_message("unused function 'foo'") == "UNUSED_FUNCTION"
    def test_unused_variable(self): assert _rule_from_message("unused variable 'x'") == "UNUSED_VARIABLE"
    def test_unused_import(self):   assert _rule_from_message("unused import 'os'") == "UNUSED_IMPORT"
    def test_unused_class(self):    assert _rule_from_message("unused class 'Foo'") == "UNUSED_CLASS"
    def test_unknown_message(self): assert _rule_from_message("something else") == "UNUSED_CODE"


class TestVultureAdapterAvailability:
    def test_available(self):
        with patch("custodian.adapters.vulture.find_tool", return_value="/usr/bin/vulture"):
            assert VultureAdapter().is_available() is True

    def test_unavailable(self):
        with patch("custodian.adapters.vulture.find_tool", return_value=None):
            assert VultureAdapter().is_available() is False


class TestVultureAdapterRun:
    def _run(self, tmp_path, stdout_lines, config=None):
        (tmp_path / "src").mkdir(exist_ok=True)
        proc = MagicMock()
        proc.stdout = "\n".join(stdout_lines)
        proc.stderr = ""
        # Mirror vulture's real exit codes: 3 when it found dead code, 0 when
        # clean. 1 and 2 mean it errored, and the adapter now reports those as
        # TOOL_ERROR rather than as an empty (falsely clean) result.
        proc.returncode = 3 if stdout_lines else 0
        with patch("subprocess.run", return_value=proc):
            return VultureAdapter().run(tmp_path, config or {})

    def test_not_found_returns_unavailable(self, tmp_path):
        (tmp_path / "src").mkdir()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            findings = VultureAdapter().run(tmp_path, {})
        assert findings[0].rule == "TOOL_UNAVAILABLE"

    def test_parses_unused_function(self, tmp_path):
        path = str(tmp_path / "src" / "foo.py")
        findings = self._run(tmp_path, [
            f"{path}:15: unused function 'bar' (100% confidence)"
        ])
        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "vulture"
        assert f.rule == "UNUSED_FUNCTION"
        assert f.severity == LOW
        assert f.line == 15
        assert "unused function" in f.message
        assert "100%" in f.message

    def test_path_relativized(self, tmp_path):
        path = str(tmp_path / "src" / "sub" / "x.py")
        findings = self._run(tmp_path, [
            f"{path}:5: unused variable 'x' (80% confidence)"
        ])
        assert findings[0].path == "src/sub/x.py"

    def test_below_confidence_threshold_filtered(self, tmp_path):
        path = str(tmp_path / "src" / "foo.py")
        # Default threshold is 60; 50% should be filtered
        findings = self._run(tmp_path, [
            f"{path}:1: unused attribute 'x' (50% confidence)"
        ])
        assert findings == []

    def test_above_confidence_threshold_kept(self, tmp_path):
        path = str(tmp_path / "src" / "foo.py")
        findings = self._run(tmp_path, [
            f"{path}:1: unused attribute 'x' (80% confidence)"
        ])
        assert len(findings) == 1

    def test_custom_min_confidence_from_config(self, tmp_path):
        path = str(tmp_path / "src" / "foo.py")
        findings = self._run(tmp_path, [
            f"{path}:1: unused function 'x' (70% confidence)"
        ], config={"vulture_min_confidence": 80})
        assert findings == []

    def test_empty_output(self, tmp_path):
        findings = self._run(tmp_path, [])
        assert findings == []

    def test_non_matching_lines_skipped(self, tmp_path):
        findings = self._run(tmp_path, ["some random output line"])
        assert findings == []

    def test_multiple_findings(self, tmp_path):
        path = str(tmp_path / "src" / "foo.py")
        findings = self._run(tmp_path, [
            f"{path}:1: unused function 'a' (100% confidence)",
            f"{path}:2: unused variable 'b' (80% confidence)",
            f"{path}:3: unused import 'os' (100% confidence)",
        ])
        assert len(findings) == 3

    def test_whitelist_included_when_exists(self, tmp_path):
        (tmp_path / "src").mkdir(exist_ok=True)
        whitelist = tmp_path / ".vulture_whitelist.py"
        whitelist.write_text("# whitelist\n", encoding="utf-8")
        proc = MagicMock()
        proc.stdout = ""
        proc.stderr = ""
        with patch("subprocess.run", return_value=proc) as mock_run:
            VultureAdapter().run(tmp_path, {})
        cmd = mock_run.call_args[0][0]
        assert str(whitelist) in cmd

    def test_whitelist_not_included_when_absent(self, tmp_path):
        (tmp_path / "src").mkdir(exist_ok=True)
        proc = MagicMock()
        proc.stdout = ""
        proc.stderr = ""
        with patch("subprocess.run", return_value=proc) as mock_run:
            VultureAdapter().run(tmp_path, {})
        cmd = mock_run.call_args[0][0]
        assert ".vulture_whitelist.py" not in " ".join(cmd)
