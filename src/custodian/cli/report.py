# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""custodian-report — generate JSON / SARIF / Markdown audit reports."""
from __future__ import annotations

import argparse
from pathlib import Path

from custodian.cli.runner import run_repo_audit


def main():
    """
    custodian-report --format json        → findings.json in .custodian/reports/
    custodian-report --format sarif       → findings.sarif
    custodian-report --format markdown    → findings.md
    custodian-report --format all         → all three formats
    custodian-report --output-dir ./out   → custom output directory
    """
    parser = argparse.ArgumentParser(description="Generate Custodian findings reports")
    parser.add_argument("--repo", type=Path, default=Path.cwd(),
                        help="Repository root (default: cwd)")
    parser.add_argument("--format", metavar="FORMAT",
                        choices=["json", "sarif", "markdown", "all"],
                        default="json",
                        help="Report format: json, sarif, markdown, or all (default: json)")
    parser.add_argument("--output-dir", type=Path,
                        help="Output directory (default: .custodian/reports/)")
    parser.add_argument("--min-severity", metavar="LEVEL",
                        choices=["high", "medium", "low"],
                        help="Only report findings at this severity or higher")
    parser.add_argument("--skip-deprecated", action="store_true",
                        help="Skip deprecated detectors")
    args = parser.parse_args()

    output_dir = args.output_dir or (args.repo / ".custodian" / "reports")

    result = run_repo_audit(
        args.repo,
        min_severity=args.min_severity,
        skip_deprecated=args.skip_deprecated,
    )

    # Gather all findings from patterns
    from custodian.core.finding import Finding
    findings: list[Finding] = []
    for pat in result.patterns.values():
        raw = pat.get("_findings", [])
        if isinstance(raw, list):
            findings.extend(raw)

    repo_key = result.repo_key or ""
    formats = ["json", "sarif", "markdown"] if args.format == "all" else [args.format]
    written: list[Path] = []

    for fmt in formats:
        if fmt == "json":
            from custodian.reports.json_report import write_json_report
            out = write_json_report(findings, output_dir, repo_key=repo_key)
            written.append(out)
        elif fmt == "sarif":
            from custodian.reports.sarif_report import write_sarif_report
            out = write_sarif_report(findings, output_dir)
            written.append(out)
        elif fmt == "markdown":
            from custodian.reports.markdown_report import write_markdown_report
            out = write_markdown_report(findings, output_dir, repo_key=repo_key)
            written.append(out)

    for path in written:
        print(f"Wrote: {path}")


if __name__ == "__main__":
    main()
