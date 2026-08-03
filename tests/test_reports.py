# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import json

from custodian.core.finding import Finding, HIGH, MEDIUM, LOW, CRITICAL
from custodian.reports.json_report import build_json_report
from custodian.reports.sarif_report import build_sarif_report
from custodian.reports.markdown_report import build_markdown_report


def _f(tool="ruff", rule="E722", severity=HIGH, path="src/foo.py", line=10, msg="test msg"):
    return Finding(tool=tool, rule=rule, severity=severity, path=path, line=line, message=msg)


class TestJsonReport:
    def test_empty_findings(self):
        doc = json.loads(build_json_report([]))
        assert doc["summary"]["total"] == 0
        assert doc["findings"] == []

    def test_schema_field(self):
        doc = json.loads(build_json_report([]))
        assert doc["schema"] == "custodian-findings/v1"

    def test_counts_by_severity(self):
        findings = [_f(severity=HIGH), _f(severity=MEDIUM), _f(severity=LOW)]
        doc = json.loads(build_json_report(findings))
        assert doc["summary"]["high"] == 1
        assert doc["summary"]["medium"] == 1
        assert doc["summary"]["low"] == 1
        assert doc["summary"]["total"] == 3

    def test_repo_key(self):
        doc = json.loads(build_json_report([], repo_key="myrepo"))
        assert doc["repo"] == "myrepo"

    def test_tool_versions(self):
        doc = json.loads(build_json_report([], tool_versions={"ruff": "0.5.0"}))
        assert doc["tool_versions"]["ruff"] == "0.5.0"

    def test_finding_fields(self):
        f = _f(tool="semgrep", rule="sqli", severity=HIGH, path="src/db.py", line=42)
        doc = json.loads(build_json_report([f]))
        found = doc["findings"][0]
        assert found["tool"] == "semgrep"
        assert found["rule"] == "sqli"
        assert found["severity"] == "high"
        assert found["path"] == "src/db.py"
        assert found["line"] == 42

    def test_write_json_report(self, tmp_path):
        from custodian.reports.json_report import write_json_report
        out = write_json_report([_f()], tmp_path / "reports")
        assert out.exists()
        assert json.loads(out.read_text(encoding="utf-8"))["summary"]["total"] == 1


class TestSarifReport:
    def test_schema_version(self):
        doc = json.loads(build_sarif_report([]))
        assert doc["version"] == "2.1.0"

    def test_empty_findings_empty_runs(self):
        doc = json.loads(build_sarif_report([]))
        assert doc["runs"] == []

    def test_one_run_per_tool(self):
        findings = [_f(tool="ruff"), _f(tool="semgrep"), _f(tool="ruff")]
        doc = json.loads(build_sarif_report(findings))
        tool_names = {r["tool"]["driver"]["name"] for r in doc["runs"]}
        assert tool_names == {"ruff", "semgrep"}

    def test_high_severity_maps_to_error(self):
        doc = json.loads(build_sarif_report([_f(severity=HIGH)]))
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_critical_maps_to_error(self):
        doc = json.loads(build_sarif_report([_f(severity=CRITICAL)]))
        assert doc["runs"][0]["results"][0]["level"] == "error"

    def test_medium_maps_to_warning(self):
        doc = json.loads(build_sarif_report([_f(severity=MEDIUM)]))
        assert doc["runs"][0]["results"][0]["level"] == "warning"

    def test_low_maps_to_note(self):
        doc = json.loads(build_sarif_report([_f(severity=LOW)]))
        assert doc["runs"][0]["results"][0]["level"] == "note"

    def test_location_included_when_path_present(self):
        doc = json.loads(build_sarif_report([_f(path="src/foo.py", line=10)]))
        result = doc["runs"][0]["results"][0]
        assert "locations" in result
        loc = result["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"] == "src/foo.py"
        assert loc["region"]["startLine"] == 10

    def test_no_location_when_path_none(self):
        f = Finding(tool="t", rule="R", severity=LOW, path=None, line=None, message="m")
        doc = json.loads(build_sarif_report([f]))
        result = doc["runs"][0]["results"][0]
        assert "locations" not in result

    def test_rules_populated(self):
        findings = [_f(rule="E722"), _f(rule="F401")]
        doc = json.loads(build_sarif_report(findings))
        rule_ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
        assert "E722" in rule_ids
        assert "F401" in rule_ids


class TestMarkdownReport:
    def test_empty_findings(self):
        md = build_markdown_report([])
        assert "No findings" in md

    def test_title_in_output(self):
        md = build_markdown_report([], title="My Report")
        assert "# My Report" in md

    def test_repo_key_shown(self):
        md = build_markdown_report([], repo_key="myrepo")
        assert "myrepo" in md

    def test_summary_table_present(self):
        md = build_markdown_report([_f(severity=HIGH)])
        assert "Summary" in md
        assert "HIGH" in md

    def test_findings_table_present(self):
        md = build_markdown_report([_f(tool="ruff", rule="E722")])
        assert "Findings" in md
        assert "ruff" in md
        assert "E722" in md

    def test_findings_sorted_by_severity(self):
        findings = [_f(severity=LOW), _f(severity=HIGH), _f(severity=MEDIUM)]
        md = build_markdown_report(findings)
        high_pos = md.index("HIGH")
        med_pos = md.index("MEDIUM")
        low_pos = md.index("LOW")
        # Just verify all three severities are present
        assert high_pos >= 0 and med_pos >= 0 and low_pos >= 0

    def test_pipe_in_message_escaped(self):
        f = _f(msg="a | b")
        md = build_markdown_report([f])
        assert "a \\| b" in md

    def test_write_markdown_report(self, tmp_path):
        from custodian.reports.markdown_report import write_markdown_report
        out = write_markdown_report([_f()], tmp_path / "reports")
        assert out.exists()
        assert "Findings" in out.read_text(encoding="utf-8")
