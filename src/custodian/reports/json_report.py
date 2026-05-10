# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""JSON report builder — flat list of findings with metadata."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from custodian.core.finding import Finding


def build_json_report(
    findings: list[Finding],
    *,
    repo_key: str = "",
    tool_versions: dict[str, str] | None = None,
) -> str:
    """Return a JSON string representing the findings report.

    Schema::

        {
          "schema": "custodian-findings/v1",
          "generated_at": "<ISO-8601>",
          "repo": "<repo_key>",
          "tool_versions": {"ruff": "0.5.0", ...},
          "summary": {"total": N, "high": N, "medium": N, "low": N},
          "findings": [
            {
              "tool": "ruff",
              "rule": "E722",
              "severity": "high",
              "path": "src/foo.py",
              "line": 10,
              "message": "..."
            },
            ...
          ]
        }
    """
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    doc = {
        "schema": "custodian-findings/v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo": repo_key,
        "tool_versions": tool_versions or {},
        "summary": {
            "total": len(findings),
            **counts,
        },
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


def write_json_report(
    findings: list[Finding],
    output_dir: Path,
    *,
    repo_key: str = "",
    tool_versions: dict[str, str] | None = None,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / "findings.json"
    out.write_text(build_json_report(findings, repo_key=repo_key, tool_versions=tool_versions),
                   encoding="utf-8")
    return out
