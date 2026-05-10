# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Adapter-based audit runner — Phase 1 skeleton.

This runner is additive: it sits alongside the existing legacy runner
(custodian.cli.runner) and does not replace it yet. The CLI wires both
together from Phase 2 onward.
"""
from __future__ import annotations

from pathlib import Path

from custodian.adapters.base import ToolAdapter
from custodian.core.finding import Finding, LOW


def run_adapters(
    repo_path: Path,
    adapters: list[ToolAdapter],
    config: dict,
) -> list[Finding]:
    """Run each adapter in order, collecting findings.

    Unavailable tools produce a TOOL_UNAVAILABLE finding and are skipped.
    Tool errors produce a TOOL_ERROR finding and continue.

    Args:
        repo_path: Root of the repository.
        adapters:  Ordered list of adapters to run.
        config:    Raw .custodian.yaml dict.

    Returns:
        Flat list of all findings from all available adapters.
    """
    findings: list[Finding] = []
    for adapter in adapters:
        if not adapter.is_available():
            findings.append(Finding.tool_unavailable(adapter.name))
            continue
        try:
            findings.extend(adapter.run(repo_path, config))
        except Exception as exc:  # noqa: BLE001
            findings.append(Finding(
                tool=adapter.name,
                rule="TOOL_ERROR",
                severity=LOW,
                path=None,
                line=None,
                message=f"{adapter.name} raised an unexpected error: {exc}",
            ))
    return findings


def filter_findings(
    findings: list[Finding],
    *,
    min_severity: str | None = None,
    ignore_rules: set[str] | None = None,
    ignore_paths: set[str] | None = None,
) -> list[Finding]:
    """Apply basic filtering to a finding list.

    Args:
        findings:      Raw findings from run_adapters.
        min_severity:  Skip findings below this level ("high" | "medium" | "low").
        ignore_rules:  Set of rule codes to suppress entirely.
        ignore_paths:  Set of path prefixes (repo-relative) to suppress.
    """
    from custodian.core.finding import _SEVERITY_ORDER
    cutoff = _SEVERITY_ORDER.get(min_severity or "low", 3)
    out: list[Finding] = []
    for f in findings:
        if _SEVERITY_ORDER.get(f.severity, 99) > cutoff:
            continue
        if ignore_rules and f.rule in ignore_rules:
            continue
        if ignore_paths and f.path:
            if any(f.path.startswith(p) for p in ignore_paths):
                continue
        out.append(f)
    return out
