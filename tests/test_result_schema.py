# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import json


from custodian.audit_kit.result import AuditResult, SCHEMA_VERSION


def test_audit_result_json_round_trip():
    result = AuditResult(repo_key="Sample", patterns={"C1": {"count": 1}}, total_findings=1)
    data = json.loads(result.to_json())
    assert data["schema_version"] == SCHEMA_VERSION == 1
    assert data["repo_key"] == "Sample"
    assert data["patterns"]["C1"]["count"] == 1


def test_findings_list_empty_when_no_samples():
    result = AuditResult(
        patterns={"C1": {"count": 0, "samples": []}, "C2": {"count": 0, "samples": []}},
        total_findings=0,
    )
    assert result.findings() == []


def test_findings_skips_patterns_with_count_zero_even_if_samples_present():
    # Some detectors add informational messages to samples when count=0
    result = AuditResult(
        patterns={"AI1": {"count": 0, "samples": ["# module not importable"]}},
        total_findings=0,
    )
    assert result.findings() == []


def test_findings_list_contains_code_and_sample():
    result = AuditResult(
        patterns={
            "C1": {"count": 2, "samples": ["src/a.py:1: todo", "src/b.py:3: todo"]},
            "OC7": {"count": 1, "samples": ["src/settings.py:12: dead field"]},
        },
        total_findings=3,
    )
    findings = result.findings()
    assert len(findings) == 3
    assert findings[0] == {"code": "C1", "sample": "src/a.py:1: todo"}
    assert findings[1] == {"code": "C1", "sample": "src/b.py:3: todo"}
    assert findings[2] == {"code": "OC7", "sample": "src/settings.py:12: dead field"}


def test_findings_present_in_json_output():
    result = AuditResult(
        patterns={"C3": {"count": 1, "samples": ["src/x.py:10: bare except"]}},
        total_findings=1,
    )
    data = json.loads(result.to_json())
    assert "findings" in data
    assert data["findings"] == [{"code": "C3", "sample": "src/x.py:10: bare except"}]


def test_findings_key_empty_list_when_no_findings():
    result = AuditResult(patterns={"C1": {"count": 0, "samples": []}}, total_findings=0)
    data = json.loads(result.to_json())
    assert data["findings"] == []


def test_patterns_still_present_for_backwards_compat():
    result = AuditResult(patterns={"C1": {"count": 0, "samples": []}}, total_findings=0)
    data = json.loads(result.to_json())
    assert "patterns" in data
    assert "C1" in data["patterns"]
