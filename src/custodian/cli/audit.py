# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from custodian.audit_kit.result import collision_note
from custodian.cli import colors
from custodian.cli.runner import run_repo_audit

_SEVERITY_LABELS = {"high": "HIGH", "medium": "MED ", "low": "LOW "}


def _human_summary(result) -> str:
    noisy = {
        code: pat for code, pat in result.patterns.items()
        if pat.get("count", 0) > 0
    }
    sev_counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for pat in noisy.values():
        sev = pat.get("severity", "medium")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    findings_str = str(result.total_findings)
    if result.total_findings > 0:
        findings_str = colors.red(findings_str)
        sev_suffix = (
            f"  ({colors.red('HIGH=' + str(sev_counts['high']))} "
            f"{colors.yellow('MED=' + str(sev_counts['medium']))} "
            f"LOW={sev_counts['low']})"
        )
    else:
        findings_str = colors.green(findings_str)
        sev_suffix = ""
    lines = [
        f"Custodian audit — repo: {result.repo_key or '(unset)'}",
        f"  patterns: {len(result.patterns)}",
        f"  findings: {findings_str}{sev_suffix}",
    ]
    if noisy:
        lines.append("")
        for code, pat in noisy.items():
            sev_key = pat.get("severity", "medium")
            sev = _SEVERITY_LABELS.get(sev_key, "MED ")
            sev_colored = colors.severity_color(sev_key, f"[{sev}]")
            lines.append(
                f"  {sev_colored} [{code}] {pat['description']} — {pat['count']} finding(s)"
                f"{collision_note(pat)}"
            )
            for sample in pat.get("samples", [])[:3]:
                lines.append(f"        {sample}")
    return "\n".join(lines)


def _list_detectors(repo: Path) -> None:
    from custodian.audit_kit.code_health import build_code_health_detectors
    from custodian.cli.runner import load_config
    from custodian.plugins.loader import load_detectors, load_plugins
    config = load_config(repo)
    sys.path.insert(0, str(repo))
    try:
        load_plugins(config)
        extra = load_detectors(config)
    finally:
        sys.path.remove(str(repo))
    detectors = build_code_health_detectors() + extra
    print(f"{'ID':<6} {'SEV':<6} {'STATUS':<10} DESCRIPTION")
    print(f"{'-'*6} {'-'*6} {'-'*10} {'-'*40}")
    for d in detectors:
        sev = _SEVERITY_LABELS.get(d.severity, "MED ").strip()
        sev_colored = colors.severity_color(d.severity or "medium", f"{sev:<6}")
        print(f"{d.id:<6} {sev_colored} {d.status:<10} {d.description}")


def main():
    """
    custodian-audit                           → cwd, default config (human + JSON)
    custodian-audit --repo /path/to/repo      → that repo
    custodian-audit --json                    → JSON only (machine-readable)
    custodian-audit --only C1,OC7            → run only those detector IDs
    custodian-audit --min-severity high       → run only HIGH-severity detectors
    custodian-audit --fail-on-findings        → exit 1 if any findings
    custodian-audit --list-detectors          → list all available detector IDs
    """
    colors.ensure_printable_console()
    parser = argparse.ArgumentParser(description="Run a Custodian audit on a repo")
    parser.add_argument("--repo", type=Path, default=Path.cwd(),
                        help="Repository root containing .custodian.yaml (default: cwd)")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON only, no human summary header")
    parser.add_argument("--only", metavar="CODES",
                        help="Comma-separated detector IDs to run (e.g. C1,OC7). "
                             "All others are skipped.")
    parser.add_argument("--min-severity", metavar="LEVEL", choices=["high", "medium", "low"],
                        help="Only run detectors at this severity or higher "
                             "(high > medium > low). Default: low (run all).")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Exit with code 1 if any findings are present")
    parser.add_argument("--no-json", action="store_true",
                        help="Suppress JSON block; print human summary only")
    parser.add_argument("--list-detectors", action="store_true",
                        help="Print all available detector IDs and descriptions, then exit")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    # Deprecated detectors (those with a Ruff/Vulture/ty equivalent) are
    # SKIPPED BY DEFAULT since 2026-05-05. Pass --include-deprecated to
    # run them alongside their adapter equivalents — useful for parity
    # audits during migration. The legacy --skip-deprecated flag is
    # accepted as a no-op for backward compatibility.
    parser.add_argument("--include-deprecated", action="store_true",
                        help="Run deprecated detectors alongside their adapter "
                             "equivalents (Ruff/Vulture/ty). Default: skip them.")
    parser.add_argument("--skip-deprecated", action="store_true",
                        help="(Legacy, no-op since 2026-05-05; deprecated detectors "
                             "are skipped by default — use --include-deprecated to override.)")
    parser.add_argument("--enable-coverage", action="store_true",
                        help="Override config to enable the coverage adapter for this run. "
                             "Used by orchestrators (e.g. OperationsCenter dispatch) that "
                             "produce a coverage.json from a managed audit.")
    parser.add_argument("--coverage-json", metavar="PATH",
                        help="With --enable-coverage, point the adapter at this coverage.json "
                             "instead of the configured default.")
    args = parser.parse_args()

    if args.no_color:
        os.environ["NO_COLOR"] = "1"

    if args.list_detectors:
        _list_detectors(args.repo)
        return

    only: set[str] | None = None
    if args.only:
        only = {c.strip() for c in args.only.split(",") if c.strip()}

    # New default: skip deprecated. --include-deprecated flips it back on.
    result = run_repo_audit(
        args.repo,
        only=only,
        min_severity=args.min_severity,
        skip_deprecated=not getattr(args, "include_deprecated", False),
        enable_coverage=args.enable_coverage,
        coverage_json_path=args.coverage_json,
    )

    if args.json:
        print(result.to_json())
    elif args.no_json:
        print(_human_summary(result))
    else:
        print(_human_summary(result))
        print(result.to_json())

    if args.fail_on_findings and result.total_findings > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
