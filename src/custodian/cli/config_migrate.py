# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""custodian-config — config inspection and migration."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from custodian.cli import colors
from custodian.config.loader import _read_yaml, config_summary, has_ignore_paths, migrate_v0_to_v1


def main():
    """
    custodian-config show              → print effective config summary
    custodian-config migrate           → migrate .custodian.yaml to v1 (dry-run)
    custodian-config migrate --apply   → write migrated config
    """
    colors.ensure_printable_console()
    parser = argparse.ArgumentParser(description="Inspect or migrate .custodian.yaml")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("show", help="Print effective config summary")

    migrate_p = sub.add_parser("migrate", help="Migrate config to v1 schema")
    migrate_p.add_argument("--apply", action="store_true",
                            help="Write the migrated config (default is dry-run)")

    args = parser.parse_args()

    config_path = args.repo / ".custodian.yaml"
    if not config_path.exists():
        print(f"ERROR: {config_path} not found", file=sys.stderr)
        sys.exit(1)

    raw = _read_yaml(config_path)

    if args.cmd == "show" or args.cmd is None:
        for line in config_summary(raw):
            print(line)

    elif args.cmd == "migrate":
        version = raw.get("version")
        if version and int(version) >= 1:
            print("Config is already at v1 — nothing to do.")
            return

        new_config = migrate_v0_to_v1(raw)
        new_yaml = yaml.dump(new_config, default_flow_style=False, sort_keys=False)

        # migrate REWRITES the file, so a dropped key would vanish with no
        # trace. Say it out loud — the key never filtered anything, but the
        # operator should learn that from us, not from a diff.
        if has_ignore_paths(raw):
            print(
                "NOTE: audit.ignore_paths was dropped — it never filtered any "
                "finding. Use per-detector audit.exclude_paths instead.",
                file=sys.stderr,
            )

        if args.apply:
            backup = config_path.with_suffix(".yaml.bak")
            config_path.rename(backup)
            config_path.write_text(new_yaml, encoding="utf-8")
            print(f"Migrated {config_path} (backup at {backup})")
        else:
            print(f"# Would write to {config_path}")
            print(new_yaml)
            print("Run with --apply to write changes.")


if __name__ == "__main__":
    main()
