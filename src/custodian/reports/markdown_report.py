# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Markdown report builder — human-friendly summary table."""
from __future__ import annotations

from pathlib import Path

from custodian.core.finding import Finding, _SEVERITY_ORDER

_SEV_BADGE: dict[str, str] = {
    "critical": "🔴 CRITICAL",
    "high":     "🔴 HIGH",
    "medium":   "🟡 MEDIUM",
    "low":      "🟢 LOW",
}


def build_markdown_report(
    findings: list[Finding],
    *,
    repo_key: str = "",
    title: str = "Custodian Findings",
) -> str:
    """Return a Markdown string with a summary and findings table."""
    lines: list[str] = []
    lines.append(f"# {title}")
    if repo_key:
        lines.append(f"\n**Repo:** `{repo_key}`")

    if not findings:
        lines.append("\n✅ No findings.")
        return "\n".join(lines)

    # Summary counts
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines.append("\n## Summary\n")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("critical", "high", "medium", "low"):
        if counts.get(sev, 0) > 0:
            badge = _SEV_BADGE.get(sev, sev.upper())
            lines.append(f"| {badge} | {counts[sev]} |")
    lines.append(f"| **Total** | **{len(findings)}** |")

    # Findings table sorted by severity then path then line
    sorted_findings = sorted(
        findings,
        key=lambda f: (_SEVERITY_ORDER.get(f.severity, 99), f.path or "", f.line or 0),
    )

    lines.append("\n## Findings\n")
    lines.append("| Severity | Tool | Rule | Location | Message |")
    lines.append("|----------|------|------|----------|---------|")
    for f in sorted_findings:
        sev = _SEV_BADGE.get(f.severity, f.severity.upper())
        loc = f"{f.path}:{f.line}" if f.path and f.line else (f.path or "—")
        msg = f.message.replace("|", "\\|").replace("\n", " ")
        lines.append(f"| {sev} | `{f.tool}` | `{f.rule}` | `{loc}` | {msg} |")

    return "\n".join(lines)


def write_markdown_report(
    findings: list[Finding],
    output_dir: Path,
    *,
    repo_key: str = "",
    title: str = "Custodian Findings",
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / "findings.md"
    out.write_text(
        build_markdown_report(findings, repo_key=repo_key, title=title),
        encoding="utf-8",
    )
    return out
