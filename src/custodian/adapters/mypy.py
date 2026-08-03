# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""mypy adapter — fallback type-checker when ty is unavailable.

mypy output format (with --no-error-summary --show-column-numbers):
  path/file.py:line:col: error: message  [error-code]
  path/file.py:line:col: note: message
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from custodian.adapters.base import ToolAdapter, find_tool
from custodian.core.finding import HIGH, LOW, MEDIUM, Finding

# mypy: path:line:col: level: message  [code]
_LINE_RE = re.compile(
    r"^(?P<path>.+):(?P<line>\d+):\d+:\s+(?P<level>error|warning|note):\s+"
    r"(?P<message>.+?)(?:\s+\[(?P<rule>[^\]]+)\])?$"
)

_MYPY_SEVERITY: dict[str, str] = {
    "error":   HIGH,
    "warning": MEDIUM,
    "note":    LOW,
}


def _mypy_severity(level: str) -> str:
    return _MYPY_SEVERITY.get(level.lower(), MEDIUM)


class MypyAdapter(ToolAdapter):
    """Runs mypy and maps diagnostics to Finding objects.

    Intended as a fallback when ty is unavailable.
    """

    name = "mypy"

    def is_available(self) -> bool:
        return find_tool("mypy") is not None

    def run(self, repo_path: Path, config: dict) -> list[Finding]:
        src_root = repo_path / config.get("src_root", "src")
        if not src_root.exists():
            src_root = repo_path

        cmd = [
            find_tool("mypy") or "mypy",
            "--no-error-summary",
            "--show-column-numbers",
            "--output=normal",
            str(src_root),
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=repo_path,
                timeout=120,
                # Parse the output regardless of exit status; a non-zero
                # code is handled per-adapter, not by raising.
                check=False,
            )
        except FileNotFoundError:
            return [Finding.tool_unavailable(self.name)]

        findings: list[Finding] = []
        for raw_line in proc.stdout.splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            m = _LINE_RE.match(raw_line)
            if not m:
                continue
            level = m.group("level")
            if level == "note":
                continue  # skip informational notes
            path_str = m.group("path")
            try:
                # `.as_posix()`, not `str()`: on Windows the latter yields
                # `src\foo\bar.py`, which no forward-slash config glob matches.
                rel = Path(path_str).relative_to(repo_path).as_posix()
            except ValueError:
                # Not under repo_path — the tool reported a cwd-relative
                # path. Already repo-relative, but still native-separated,
                # and this branch is the one mypy actually takes: it runs
                # with cwd=repo_path, so relative_to() always raises.
                rel = Path(path_str).as_posix()
            rule = m.group("rule") or "mypy"
            findings.append(Finding(
                tool=self.name,
                rule=rule,
                severity=_mypy_severity(level),
                path=rel,
                line=int(m.group("line")),
                message=m.group("message").strip(),
            ))

        return findings
