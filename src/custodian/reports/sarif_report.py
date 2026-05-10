# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""SARIF 2.1.0 report builder.

Produces a minimal SARIF document compatible with GitHub Code Scanning and
other SARIF consumers.  One SARIF run per tool.
"""
from __future__ import annotations

import json
from pathlib import Path

from custodian.core.finding import Finding

_SARIF_SEVERITY: dict[str, str] = {
    "critical": "error",
    "high":     "error",
    "medium":   "warning",
    "low":      "note",
}


def build_sarif_report(
    findings: list[Finding],
    *,
    tool_versions: dict[str, str] | None = None,
) -> str:
    """Return a SARIF 2.1.0 JSON string.

    Groups findings by tool, one SARIF run per tool.
    """
    # Group by tool
    by_tool: dict[str, list[Finding]] = {}
    for f in findings:
        by_tool.setdefault(f.tool, []).append(f)

    runs = []
    for tool_name, tool_findings in sorted(by_tool.items()):
        version = (tool_versions or {}).get(tool_name, "")
        rule_ids: set[str] = {f.rule for f in tool_findings}
        rules = [{"id": rid, "name": rid} for rid in sorted(rule_ids)]

        results = []
        for f in tool_findings:
            result: dict = {
                "ruleId": f.rule,
                "level": _SARIF_SEVERITY.get(f.severity, "warning"),
                "message": {"text": f.message},
            }
            if f.path:
                region: dict = {}
                if f.line:
                    region = {"startLine": f.line}
                result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.path, "uriBaseId": "%SRCROOT%"},
                            **({"region": region} if region else {}),
                        }
                    }
                ]
            results.append(result)

        run: dict = {
            "tool": {
                "driver": {
                    "name": tool_name,
                    **({"version": version} if version else {}),
                    "rules": rules,
                }
            },
            "results": results,
        }
        runs.append(run)

    doc = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def write_sarif_report(
    findings: list[Finding],
    output_dir: Path,
    *,
    tool_versions: dict[str, str] | None = None,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / "findings.sarif"
    out.write_text(build_sarif_report(findings, tool_versions=tool_versions), encoding="utf-8")
    return out
