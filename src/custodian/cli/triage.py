# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""``custodian triage`` — turn an audit JSON into per-file verdicts.

Reads either ``custodian-audit --json`` output (a JSON file, ``-`` for
stdin) or runs an audit inline against a repo.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from custodian.triage import triage_result


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="custodian-triage",
        description="Group audit findings into per-file action recommendations.",
    )
    parser.add_argument(
        "source",
        help="Path to a custodian-audit --json file, or '-' to read JSON from stdin.",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human text.")
    parser.add_argument(
        "--only",
        help="Comma-separated verdicts to include (DELETE,IMPLEMENT,WIRE,REDESIGN,CLEANUP).",
    )
    args = parser.parse_args()

    if args.source == "-":
        data = json.load(sys.stdin)
    else:
        data = json.loads(Path(args.source).read_text(encoding="utf-8"))

    patterns = data.get("patterns") or {}
    verdicts = triage_result(patterns)

    if args.only:
        wanted = {v.strip().upper() for v in args.only.split(",")}
        verdicts = [v for v in verdicts if v.primary().value in wanted]

    if args.json:
        out = [
            {
                "path": v.path,
                "primary": v.primary().value,
                "verdicts": [x.value for x in v.verdicts],
                "evidence": v.evidence,
            }
            for v in verdicts
        ]
        print(json.dumps(out, indent=2, sort_keys=True, ensure_ascii=False))
        return

    if not verdicts:
        print("No triage verdicts — nothing to act on.")
        return

    print(f"Triage: {len(verdicts)} file(s) with action recommendations.\n")
    for v in verdicts:
        tags = " + ".join(x.value for x in v.verdicts)
        sources = ", ".join(sorted(v.evidence))
        print(f"[{tags}] {v.path}")
        print(f"    signals: {sources}")


if __name__ == "__main__":
    main()
