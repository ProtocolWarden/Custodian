# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import pytest
from custodian.core.finding import Finding, CRITICAL, HIGH, MEDIUM, LOW


class TestFindingConstruction:
    def test_minimal(self):
        f = Finding(tool="ruff", rule="E722", severity=HIGH, path="src/foo.py", line=10, message="bare except")
        assert f.tool == "ruff"
        assert f.rule == "E722"
        assert f.severity == HIGH
        assert f.path == "src/foo.py"
        assert f.line == 10
        assert f.message == "bare except"

    def test_no_path_no_line(self):
        f = Finding(tool="custodian", rule="S1", severity=HIGH, path=None, line=None, message="layer violation")
        assert f.path is None
        assert f.line is None

    def test_frozen(self):
        f = Finding(tool="ruff", rule="E722", severity=HIGH, path=None, line=None, message="x")
        with pytest.raises((AttributeError, TypeError)):
            f.tool = "other"  # type: ignore[misc]

    def test_hashable(self):
        f = Finding(tool="ruff", rule="E722", severity=HIGH, path="a.py", line=1, message="x")
        assert hash(f) is not None
        s = {f, f}
        assert len(s) == 1


class TestFindingSeverityComparison:
    def test_at_least_same(self):
        f = Finding(tool="t", rule="r", severity=HIGH, path=None, line=None, message="")
        assert f.at_least(HIGH)

    def test_at_least_lower_threshold(self):
        f = Finding(tool="t", rule="r", severity=HIGH, path=None, line=None, message="")
        assert f.at_least(MEDIUM)
        assert f.at_least(LOW)

    def test_not_at_least_higher(self):
        f = Finding(tool="t", rule="r", severity=MEDIUM, path=None, line=None, message="")
        assert not f.at_least(HIGH)
        assert not f.at_least(CRITICAL)

    def test_critical_beats_all(self):
        f = Finding(tool="t", rule="r", severity=CRITICAL, path=None, line=None, message="")
        assert f.at_least(CRITICAL)
        assert f.at_least(HIGH)
        assert f.at_least(LOW)


class TestFindingSerialization:
    def test_round_trip(self):
        f = Finding(tool="semgrep", rule="S1", severity=HIGH, path="src/a.py", line=5, message="msg")
        d = f.to_dict()
        assert d == {"tool": "semgrep", "rule": "S1", "severity": "high", "path": "src/a.py", "line": 5, "message": "msg"}
        f2 = Finding.from_dict(d)
        assert f == f2

    def test_from_dict_defaults(self):
        f = Finding.from_dict({"tool": "ruff", "rule": "E722", "message": "bare"})
        assert f.severity == LOW
        assert f.path is None
        assert f.line is None


class TestToolUnavailable:
    def test_shape(self):
        f = Finding.tool_unavailable("semgrep")
        assert f.tool == "semgrep"
        assert f.rule == "TOOL_UNAVAILABLE"
        assert f.severity == LOW
        assert "semgrep" in f.message
