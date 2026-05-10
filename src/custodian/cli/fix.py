# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""custodian-fix — apply automated codemods to findings."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from custodian.cli.runner import run_repo_audit
from custodian.codemods.base import run_codemods


def _load_codemods():
    """Return all built-in codemods."""
    # Codemods are added here as they are implemented.
    return []


def main():
    """
    custodian-fix                       → fix current repo (dry-run by default)
    custodian-fix --apply               → actually write changes
    custodian-fix --repo /path/to/repo  → fix that repo
    custodian-fix --only F401,E722      → only fix these rule codes
    """
    parser = argparse.ArgumentParser(description="Apply automated codemods to Custodian findings")
    parser.add_argument("--repo", type=Path, default=Path.cwd(),
                        help="Repository root (default: cwd)")
    parser.add_argument("--apply", action="store_true",
                        help="Write changes to disk (default is dry-run)")
    parser.add_argument("--only", metavar="RULES",
                        help="Comma-separated rule codes to fix (e.g. F401,E722)")
    args = parser.parse_args()

    dry_run = not args.apply

    result = run_repo_audit(args.repo)
    findings = []
    for pat in result.patterns.values():
        findings.extend(pat.get("_findings", []))

    if args.only:
        allowed = {r.strip() for r in args.only.split(",") if r.strip()}
        findings = [f for f in findings if f.rule in allowed]

    codemods = _load_codemods()
    if not codemods:
        print("No codemods available yet.", file=sys.stderr)
        return

    changed = run_codemods(args.repo, findings, codemods, dry_run=dry_run)

    if not changed:
        print("No changes.")
        return

    for r in changed:
        action = "Would modify" if dry_run else "Modified"
        print(f"{action}: {r.path.relative_to(args.repo)}")
        if dry_run and r.diff:
            print(r.diff)

    if dry_run and changed:
        print(f"\n{len(changed)} file(s) would be modified. Run with --apply to write.")


if __name__ == "__main__":
    main()
