# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for the coverage.json adapter."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from custodian.adapters.coverage import CoverageAdapter
from custodian.adapters.registry import get_enabled_adapters


def _write_coverage_json(tmp_path: Path, payload: dict) -> Path:
    p = tmp_path / "coverage.json"
    p.write_text(json.dumps(payload), encoding="utf-8")
    return p


def _payload(files: dict) -> dict:
    return {"meta": {"version": "7.6.1"}, "files": files}


class TestCoverageAdapterDiscovery:
    def test_off_by_default_in_registry(self):
        # No `coverage:` key in tools → adapter not registered.
        adapters = get_enabled_adapters({"tools": {}})
        assert all(a.name != "coverage" for a in adapters)

    def test_opt_in_via_dict_config(self):
        adapters = get_enabled_adapters({"tools": {"coverage": {"enabled": True}}})
        assert any(a.name == "coverage" for a in adapters)

    def test_opt_in_via_truthy_value(self):
        adapters = get_enabled_adapters({"tools": {"coverage": True}})
        assert any(a.name == "coverage" for a in adapters)


class TestCoverageAdapterCV1:
    def test_cv1_module_unexecuted(self, tmp_path: Path):
        _write_coverage_json(tmp_path, _payload({
            "src/foo/bar.py": {
                "summary": {
                    "num_statements": 12,
                    "covered_lines": 0,
                    "percent_covered": 0.0,
                },
            },
        }))
        adapter = CoverageAdapter(json_path="coverage.json")
        findings = adapter.run(tmp_path, {})
        assert any(f.rule == "CV1_MODULE_UNEXECUTED" for f in findings)
        msg = next(f for f in findings if f.rule == "CV1_MODULE_UNEXECUTED").message
        assert "0/12" in msg

    def test_cv1_skipped_for_partially_covered(self, tmp_path: Path):
        _write_coverage_json(tmp_path, _payload({
            "src/foo/bar.py": {
                "summary": {"num_statements": 10, "covered_lines": 5, "percent_covered": 50.0},
            },
        }))
        adapter = CoverageAdapter(json_path="coverage.json")
        findings = adapter.run(tmp_path, {})
        assert not any(f.rule == "CV1_MODULE_UNEXECUTED" for f in findings)


class TestCoverageAdapterCV2:
    def test_cv2_function_unexecuted(self, tmp_path: Path):
        _write_coverage_json(tmp_path, _payload({
            "src/foo/bar.py": {
                "summary": {"num_statements": 10, "covered_lines": 5, "percent_covered": 50.0},
                "functions": {
                    "do_thing": {
                        "summary": {"num_statements": 4, "covered_lines": 0},
                        "missing_lines": [42, 43, 44, 45],
                    },
                    "other_thing": {
                        "summary": {"num_statements": 6, "covered_lines": 6},
                    },
                },
            },
        }))
        adapter = CoverageAdapter(json_path="coverage.json")
        findings = adapter.run(tmp_path, {})
        cv2 = [f for f in findings if f.rule == "CV2_FUNCTION_UNEXECUTED"]
        assert len(cv2) == 1
        assert "do_thing" in cv2[0].message
        assert cv2[0].line == 42


class TestCoverageAdapterCV3:
    def test_cv3_below_min_coverage(self, tmp_path: Path):
        _write_coverage_json(tmp_path, _payload({
            "src/foo/bar.py": {
                "summary": {"num_statements": 10, "covered_lines": 4, "percent_covered": 40.0},
            },
        }))
        adapter = CoverageAdapter(json_path="coverage.json", min_coverage=60)
        findings = adapter.run(tmp_path, {})
        cv3 = [f for f in findings if f.rule == "CV3_MODULE_BELOW_MIN_COVERAGE"]
        assert len(cv3) == 1

    def test_cv3_silent_when_min_coverage_unset(self, tmp_path: Path):
        _write_coverage_json(tmp_path, _payload({
            "src/foo/bar.py": {
                "summary": {"num_statements": 10, "covered_lines": 4, "percent_covered": 40.0},
            },
        }))
        adapter = CoverageAdapter(json_path="coverage.json")
        findings = adapter.run(tmp_path, {})
        assert not any(f.rule == "CV3_MODULE_BELOW_MIN_COVERAGE" for f in findings)


class TestCoverageAdapterErrorPaths:
    def test_missing_json_emits_finding(self, tmp_path: Path):
        adapter = CoverageAdapter(json_path="coverage.json")
        findings = adapter.run(tmp_path, {})
        assert len(findings) == 1
        assert findings[0].rule == "COVERAGE_JSON_MISSING"

    def test_invalid_json_emits_finding(self, tmp_path: Path):
        (tmp_path / "coverage.json").write_text("{not json", encoding="utf-8")
        adapter = CoverageAdapter(json_path="coverage.json")
        findings = adapter.run(tmp_path, {})
        assert len(findings) == 1
        assert findings[0].rule == "COVERAGE_JSON_INVALID"


class TestCoverageAdapterExclusions:
    def test_exclude_paths_suppresses(self, tmp_path: Path):
        _write_coverage_json(tmp_path, _payload({
            "src/foo/bar.py": {
                "summary": {"num_statements": 10, "covered_lines": 0, "percent_covered": 0.0},
            },
            "src/skipped/x.py": {
                "summary": {"num_statements": 5, "covered_lines": 0, "percent_covered": 0.0},
            },
        }))
        adapter = CoverageAdapter(
            json_path="coverage.json",
            exclude_paths=["src/skipped/*"],
        )
        findings = adapter.run(tmp_path, {})
        cv1_paths = [f.path for f in findings if f.rule == "CV1_MODULE_UNEXECUTED"]
        assert "src/foo/bar.py" in cv1_paths
        assert not any("skipped" in p for p in cv1_paths)

    def test_runner_enable_coverage_override(self, tmp_path: Path):
        """run_repo_audit(..., enable_coverage=True) opts in the adapter
        even when the repo's .custodian.yaml has no coverage block."""
        from custodian.cli.runner import run_repo_audit

        # Minimal repo: empty .custodian.yaml + a src/ with one module + coverage.json
        (tmp_path / ".custodian.yaml").write_text("repo_key: x\nsrc_root: src\ntests_root: tests\n")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "foo.py").write_text("def hello(): pass\n")
        (tmp_path / "tests").mkdir()
        cov_path = tmp_path / "coverage.json"
        cov_path.write_text(json.dumps(_payload({
            "src/foo.py": {
                "summary": {"num_statements": 5, "covered_lines": 0, "percent_covered": 0.0},
            },
        })))
        result = run_repo_audit(
            tmp_path,
            enable_coverage=True,
            coverage_json_path=str(cov_path),
        )
        # Coverage findings appear under the "COVERAGE" pattern key with non-zero count.
        assert "COVERAGE" in result.patterns
        assert result.patterns["COVERAGE"]["count"] >= 1

    def test_empty_file_skipped(self, tmp_path: Path):
        _write_coverage_json(tmp_path, _payload({
            "src/foo/__init__.py": {
                "summary": {"num_statements": 0, "covered_lines": 0, "percent_covered": 100.0},
            },
        }))
        adapter = CoverageAdapter(json_path="coverage.json")
        findings = adapter.run(tmp_path, {})
        assert findings == []
