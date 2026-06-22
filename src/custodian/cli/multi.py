# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from custodian.audit_kit.result import collision_note
from custodian.cli import colors
from custodian.cli.runner import run_repo_audit

_SEV_LABEL = {"high": "HIGH", "medium": "MED ", "low": "LOW ", None: "    "}


def _severity_counts(patterns: dict) -> dict[str, int]:
    counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for pat in patterns.values():
        if pat.get("count", 0) > 0:
            sev = pat.get("severity", "medium")
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def main():
    """
    custodian-multi --repos /path/a /path/b ...   → audit multiple repos, print table
    custodian-multi --repos-file repos.txt         → read repo list from file (one path per line)
    custodian-multi ... --json                     → emit JSON array instead of table
    custodian-multi ... --fail-on-findings         → exit 1 if any repo has findings
    custodian-multi ... --min-severity high        → pass filter to each sub-audit
    """
    parser = argparse.ArgumentParser(
        description="Run Custodian audit across multiple repos and summarise"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--repos",
        nargs="+",
        type=Path,
        metavar="PATH",
        help="One or more repository roots to audit",
    )
    group.add_argument(
        "--repos-file",
        type=Path,
        metavar="FILE",
        help="File with one repo path per line (blank lines and # comments ignored)",
    )
    parser.add_argument("--only", metavar="CODES",
                        help="Comma-separated detector IDs to run (e.g. C1,OC7)")
    parser.add_argument("--min-severity", metavar="LEVEL", choices=["high", "medium", "low"],
                        help="Only run detectors at this severity or higher")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON array, one object per repo")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Exit 1 if any repo has findings")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="After the table, print per-repo finding details for repos with findings")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output")
    # Deprecated detectors are skipped by default since 2026-05-05.
    # --include-deprecated flips them back on (parity-audit mode).
    parser.add_argument("--include-deprecated", action="store_true",
                        help="Run deprecated detectors alongside their adapter "
                             "equivalents (Ruff/Vulture/ty). Default: skip them.")
    parser.add_argument("--skip-deprecated", action="store_true",
                        help="(Legacy, no-op since 2026-05-05.)")
    parser.add_argument("--report-dir", type=Path, metavar="DIR",
                        help="Write per-repo JSON reports to this directory")
    args = parser.parse_args()

    if args.no_color:
        os.environ["NO_COLOR"] = "1"

    if args.repos_file:
        text = args.repos_file.read_text(encoding="utf-8")
        repos = [
            Path(line.strip())
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    else:
        repos = args.repos

    only: set[str] | None = None
    if args.only:
        only = {c.strip() for c in args.only.split(",") if c.strip()}

    skip_deprecated = not getattr(args, "include_deprecated", False)

    results = []
    errors = []
    for repo in repos:
        try:
            result = run_repo_audit(
                repo, only=only, min_severity=args.min_severity,
                skip_deprecated=skip_deprecated,
            )
            results.append((repo, result, None))
        except Exception as exc:  # noqa: BLE001
            results.append((repo, None, str(exc)))
            errors.append(repo)

    if args.report_dir:
        _write_multi_reports(results, args.report_dir)

    if args.json:
        out = []
        for repo, result, err in results:
            if err or result is None:
                out.append({"repo": str(repo), "error": err or "no result"})
            else:
                data = json.loads(result.to_json())
                data["repo_path"] = str(repo)
                out.append(data)
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        _print_table(results)
        if args.verbose:
            _print_verbose(results)

    any_findings = any(
        r.total_findings > 0
        for _, r, err in results
        if r is not None and err is None
    )
    if (args.fail_on_findings and any_findings) or errors:
        sys.exit(1)


def _print_table(results: list) -> None:
    col_repo = max((len(r.repo_key or str(p)) for p, r, _ in results if r), default=12)
    col_repo = max(col_repo, 4)

    header = f"{'repo':<{col_repo}} | findings | HIGH | MED  | LOW  | status"
    sep    = f"{'-' * col_repo}-+---------+------+------+------+--------"
    print(header)
    print(sep)

    for repo, result, err in results:
        if err:
            name = str(repo)[:col_repo]
            print(f"{name:<{col_repo}} | {'ERROR':>8} | {'':4} | {'':4} | {'':4} | {err[:30]}")
            continue
        name = (result.repo_key or str(repo))[:col_repo]
        counts = _severity_counts(result.patterns)
        h, m, lo = counts["high"], counts["medium"], counts["low"]
        if result.total_findings == 0:
            status = colors.green("clean")
            findings_col = colors.green(f"{result.total_findings:>8}")
        else:
            status = colors.red("FAIL ")
            findings_col = colors.red(f"{result.total_findings:>8}")
        h_col = colors.red(f"{h:>4}") if h > 0 else f"{h:>4}"
        m_col = colors.yellow(f"{m:>4}") if m > 0 else f"{m:>4}"
        print(
            f"{name:<{col_repo}} | {findings_col} | {h_col} | {m_col} | {lo:>4} | {status}"
        )

    # Summary footer
    ok = sum(1 for _, r, e in results if r and e is None and r.total_findings == 0)
    fail = sum(1 for _, r, e in results if r and e is None and r.total_findings > 0)
    errs = sum(1 for _, _, e in results if e)
    total_findings = sum(r.total_findings for _, r, e in results if r and e is None)
    print(sep)
    parts = [f"{len(results)} repos:"]
    parts.append(colors.green(f"{ok} clean") if ok else "0 clean")
    if fail:
        parts.append(colors.red(f"{fail} failing"))
    if errs:
        parts.append(colors.red(f"{errs} errors"))
    parts.append(f"| {total_findings} total findings")
    print("  " + "  ".join(parts))


def _print_verbose(results: list) -> None:
    """Print per-finding details for repos that have findings."""
    noisy = [(repo, result, err) for repo, result, err in results
             if err or (result and result.total_findings > 0)]
    if not noisy:
        return
    print()
    for repo, result, err in noisy:
        name = result.repo_key if result else str(repo)
        print(f"── {name} {'─' * max(0, 60 - len(name))}")
        if err:
            print(f"  ERROR: {err}")
            continue
        for code, pat in result.patterns.items():
            if pat.get("count", 0) == 0:
                continue
            sev_key = pat.get("severity", "medium")
            sev = _SEV_LABEL.get(sev_key, "    ").strip()
            sev_colored = colors.severity_color(sev_key, f"[{sev}]")
            print(
                f"  {sev_colored} [{code}] {pat['description']} — {pat['count']} finding(s)"
                f"{collision_note(pat)}"
            )
            for sample in pat.get("samples", [])[:5]:
                print(f"        {sample}")
        print()


def _write_multi_reports(results: list, report_dir: Path) -> None:
    """Write per-repo JSON findings reports under report_dir/<repo-key>/."""
    from custodian.reports.json_report import write_json_report
    for repo, result, err in results:
        if err or result is None:
            continue
        repo_key = result.repo_key or repo.name
        out_dir = report_dir / repo_key
        # Gather findings from pattern _findings lists if present
        from custodian.core.finding import Finding
        findings: list[Finding] = []
        for pat in result.patterns.values():
            raw = pat.get("_findings", [])
            if isinstance(raw, list):
                findings.extend(raw)
        write_json_report(findings, out_dir, repo_key=repo_key)
        print(f"Report: {out_dir / 'findings.json'}")


if __name__ == "__main__":
    main()
