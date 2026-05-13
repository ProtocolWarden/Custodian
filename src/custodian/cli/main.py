# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Unified `custodian` CLI entry point.

Dispatches to subcommands:
  custodian audit     → run audit
  custodian fix       → apply codemods
  custodian report    → generate reports
  custodian config    → inspect/migrate config
  custodian doctor    → check tool availability
  custodian repograph-migration-gate → strict RepoGraph migration checks
"""
from __future__ import annotations

import sys


_COMMANDS = {
    "audit":   "custodian.cli.audit:main",
    "fix":     "custodian.cli.fix:main",
    "report":  "custodian.cli.report:main",
    "config":  "custodian.cli.config_migrate:main",
    "doctor":  "custodian.cli.doctor:main",
    "multi":   "custodian.cli.multi:main",
    "triage":  "custodian.cli.triage:main",
    "repograph-migration-gate": "custodian.cli.repograph_migration_gate:main",
}

_HELP = """\
Usage: custodian <command> [options]

Commands:
  audit     Run the audit pipeline on a repository
  fix       Apply automated codemods to findings
  report    Generate JSON / SARIF / Markdown reports
  config    Inspect or migrate .custodian.yaml
  doctor    Check tool availability and versions
  multi     Run audit across multiple repositories
  triage    Convert audit findings into per-file action recommendations
  repograph-migration-gate
            Run strict cross-repo RepoGraph migration gate checks

Run `custodian <command> --help` for command-specific options.
"""


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(_HELP)
        return

    cmd = sys.argv[1]
    if cmd not in _COMMANDS:
        print(f"ERROR: unknown command {cmd!r}\n", file=sys.stderr)
        print(_HELP, file=sys.stderr)
        sys.exit(1)

    # Remove the subcommand from argv so the target's argparse sees clean args
    sys.argv = [f"custodian-{cmd}", *sys.argv[2:]]

    module_path, func = _COMMANDS[cmd].rsplit(":", 1)
    import importlib
    mod = importlib.import_module(module_path)
    getattr(mod, func)()


if __name__ == "__main__":
    main()
