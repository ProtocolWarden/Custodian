# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Ruff adapter — runs `ruff check --output-format=json` and normalizes output."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from custodian.adapters.base import ToolAdapter, find_tool
from custodian.core.finding import HIGH, LOW, MEDIUM, Finding

# Longest-prefix-first severity table.  First match wins.
# Covers Ruff rule namespaces as of 0.x.
_PREFIX_SEVERITY: tuple[tuple[str, str], ...] = (
    # Security / injection — always high
    ("S1",   HIGH),    # S101 assert, S102 exec, S105-S108 hardcoded secrets
    ("S2",   HIGH),    # S2xx injection, S201-S202
    ("S3",   HIGH),    # S301 pickle, S307 eval, S324 weak hash
    ("S6",   HIGH),    # S602-S606 subprocess/shell
    ("BLE",  HIGH),    # BLE001 blind Exception
    # Debugger (T100) and common security errors
    ("T10",  HIGH),    # T100 breakpoint/pdb
    ("B00",  HIGH),    # B006 mutable default, B007 loop var, B008 func call in default
    ("E72",  HIGH),    # E722 bare except
    # Medium
    ("DTZ",  MEDIUM),  # datetime timezone-naive
    ("E",    MEDIUM),  # PEP-8 errors (fallback for E*)
    ("W",    MEDIUM),  # PEP-8 warnings
    ("F",    MEDIUM),  # Pyflakes
    ("B",    MEDIUM),  # Bugbear (fallback)
    ("PL",   MEDIUM),  # Pylint
    ("I",    MEDIUM),  # isort
    ("G",    MEDIUM),  # flake8-logging-format
    ("C9",   MEDIUM),  # McCabe complexity (C901)
    ("S",    MEDIUM),  # Bandit (fallback for S*)
    ("T2",   MEDIUM),  # T201 print
    # Low
    ("ANN",  LOW),     # type annotations
    ("RUF",  LOW),     # Ruff-specific
    ("SIM",  LOW),     # simplify
    ("TRY",  LOW),     # tryceratops
    ("N",    LOW),     # naming
    ("C",    LOW),     # convention (fallback)
    ("UP",   LOW),     # pyupgrade
    ("PD",   LOW),     # pandas
    ("T",    LOW),     # catch-all T*
)


def _severity_for(code: str) -> str:
    for prefix, sev in _PREFIX_SEVERITY:
        if code.startswith(prefix):
            return sev
    return LOW


def _make_relative(filename: str, repo_path: Path) -> str | None:
    # `.as_posix()`, not `str()`: on Windows the latter yields `src\foo\bar.py`,
    # which no forward-slash config glob can match. Finding paths are compared
    # against posix-authored globs, so they must be posix on every platform.
    try:
        return Path(filename).relative_to(repo_path).as_posix()
    except ValueError:
        # Not under repo_path — the tool reported a cwd-relative path. Already
        # repo-relative, but still in native separators, so normalise here too:
        # this branch decides the spelling for every tool that reports relative
        # paths, which is most of them (they run with cwd=repo_path).
        return Path(filename).as_posix() if filename else None


class RuffAdapter(ToolAdapter):
    """Runs Ruff and maps each finding to a canonical Finding."""

    name = "ruff"

    def __init__(self, ruff_args: list[str] | None = None) -> None:
        self._extra_args = ruff_args or []

    def is_available(self) -> bool:
        return find_tool("ruff") is not None

    def run(self, repo_path: Path, config: dict) -> list[Finding]:
        src_root = repo_path / config.get("src_root", "src")
        if not src_root.exists():
            src_root = repo_path

        cmd = [find_tool("ruff") or "ruff", "check", "--no-cache", "--output-format=json", str(src_root), *self._extra_args]
        env = os.environ.copy()

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=repo_path,
                env=env,
                timeout=120,
                # Parse the output regardless of exit status; a non-zero
                # code is handled per-adapter, not by raising.
                check=False,
            )
        except FileNotFoundError:
            return [Finding.tool_unavailable(self.name)]

        raw = proc.stdout.strip()
        if not raw:
            return []

        try:
            items = json.loads(raw)
        except json.JSONDecodeError:
            return [Finding(
                tool=self.name,
                rule="TOOL_ERROR",
                severity=LOW,
                path=None,
                line=None,
                message=f"ruff produced non-JSON output: {raw[:200]}",
            )]

        findings: list[Finding] = []
        for item in items:
            code = item.get("code") or "RUFF_UNKNOWN"
            message = item.get("message", "")
            filename = item.get("filename", "")
            location = item.get("location") or {}
            line = location.get("row")
            path = _make_relative(filename, repo_path)

            findings.append(Finding(
                tool=self.name,
                rule=code,
                severity=_severity_for(code),
                path=path,
                line=line,
                message=message,
            ))

        return findings
