# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

from custodian.core.finding import Finding, HIGH, MEDIUM, LOW, CRITICAL
from custodian.policy.filter import apply_policy, policy_from_config


def _f(severity=LOW, rule="R1", path="src/foo.py"):
    return Finding(tool="test", rule=rule, severity=severity,
                   path=path, line=1, message="msg")


class TestApplyPolicy:
    def test_no_filters_returns_all(self):
        findings = [_f(HIGH), _f(MEDIUM), _f(LOW)]
        assert apply_policy(findings) == findings

    def test_min_severity_high_keeps_only_high(self):
        findings = [_f(HIGH), _f(MEDIUM), _f(LOW)]
        result = apply_policy(findings, min_severity="high")
        assert result == [_f(HIGH)]

    def test_min_severity_medium_keeps_high_and_medium(self):
        findings = [_f(HIGH), _f(MEDIUM), _f(LOW)]
        result = apply_policy(findings, min_severity="medium")
        assert set(result) == {_f(HIGH), _f(MEDIUM)}

    def test_min_severity_low_keeps_all(self):
        findings = [_f(HIGH), _f(MEDIUM), _f(LOW)]
        result = apply_policy(findings, min_severity="low")
        assert len(result) == 3

    def test_critical_is_above_high(self):
        findings = [_f(CRITICAL), _f(HIGH), _f(MEDIUM)]
        result = apply_policy(findings, min_severity="high")
        assert set(result) == {_f(CRITICAL), _f(HIGH)}

    def test_ignore_rules(self):
        findings = [_f(rule="F401"), _f(rule="E722"), _f(rule="ANN001")]
        result = apply_policy(findings, ignore_rules=["F401", "ANN001"])
        assert len(result) == 1
        assert result[0].rule == "E722"

    def test_ignore_paths_exact(self):
        findings = [_f(path="src/foo.py"), _f(path="tests/test_foo.py")]
        result = apply_policy(findings, ignore_paths=["tests/test_foo.py"])
        assert len(result) == 1
        assert result[0].path == "src/foo.py"

    def test_ignore_paths_glob_star(self):
        findings = [
            _f(path="src/foo.py"),
            _f(path="tests/test_a.py"),
            _f(path="tests/sub/test_b.py"),
        ]
        result = apply_policy(findings, ignore_paths=["tests/*"])
        paths = [f.path for f in result]
        assert "src/foo.py" in paths
        assert "tests/test_a.py" not in paths

    def test_ignore_paths_glob_double_star(self):
        findings = [
            _f(path="src/foo.py"),
            _f(path="tests/test_a.py"),
            _f(path="tests/sub/test_b.py"),
        ]
        result = apply_policy(findings, ignore_paths=["tests/**"])
        assert len(result) == 1
        assert result[0].path == "src/foo.py"

    def test_none_path_not_filtered_by_path_pattern(self):
        f = Finding(tool="t", rule="R", severity=LOW, path=None, line=None, message="m")
        result = apply_policy([f], ignore_paths=["**"])
        assert result == [f]

    def test_combined_filters(self):
        findings = [
            _f(HIGH, rule="E722", path="src/foo.py"),
            _f(LOW, rule="F401", path="src/bar.py"),
            _f(MEDIUM, rule="ANN001", path="tests/t.py"),
        ]
        result = apply_policy(findings, min_severity="medium",
                               ignore_rules=["ANN001"], ignore_paths=["tests/**"])
        assert result == [_f(HIGH, rule="E722", path="src/foo.py")]

    def test_does_not_mutate_input(self):
        findings = [_f(HIGH), _f(LOW)]
        original = list(findings)
        apply_policy(findings, min_severity="high")
        assert findings == original


class TestPolicyFromConfig:
    def test_new_schema(self):
        config = {"policy": {"min_severity": "high", "ignore_rules": ["F401"]}}
        p = policy_from_config(config)
        assert p["min_severity"] == "high"
        assert p["ignore_rules"] == ["F401"]

    def test_old_schema_audit_key(self):
        config = {"audit": {"min_severity": "medium", "ignore_paths": ["tests/**"]}}
        p = policy_from_config(config)
        assert p["min_severity"] == "medium"
        assert p["ignore_paths"] == ["tests/**"]

    def test_empty_config(self):
        p = policy_from_config({})
        assert p["ignore_rules"] == []
        assert p["ignore_paths"] == []
