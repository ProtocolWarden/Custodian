# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""ty adapter — runs `ty check --output-format concise` and maps diagnostics to Findings."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from custodian.adapters.base import ToolAdapter, find_tool
from custodian.core.finding import HIGH, LOW, MEDIUM, Finding

# ty concise output: path:line:col: level[rule-id] message
_LINE_RE = re.compile(
    r"^(?P<path>.+):(?P<line>\d+):\d+:\s+(?P<level>\w+)\[(?P<rule>[^\]]+)\]\s+(?P<message>.+)$"
)

_TY_SEVERITY: dict[str, str] = {
    "error":   HIGH,
    "warning": MEDIUM,
    "info":    LOW,
}


def _ty_severity(level: str) -> str:
    return _TY_SEVERITY.get(level.lower(), MEDIUM)


class TyAdapter(ToolAdapter):
    """Runs ty type-checker and maps diagnostics to Finding objects.

    ty is optional — when not installed ``is_available`` returns False.
    """

    name = "ty"

    def is_available(self) -> bool:
        return find_tool("ty") is not None

    def run(self, repo_path: Path, config: dict) -> list[Finding]:
        src_root = repo_path / config.get("src_root", "src")
        if not src_root.exists():
            src_root = repo_path

        cmd = [find_tool("ty") or "ty", "check", "--output-format", "concise", str(src_root)]

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
        # ty writes diagnostics to stderr in concise mode
        output = proc.stderr or proc.stdout
        for raw_line in output.splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            m = _LINE_RE.match(raw_line)
            if not m:
                continue
            path_str = m.group("path")
            try:
                rel = str(Path(path_str).relative_to(repo_path))
            except ValueError:
                rel = path_str
            findings.append(Finding(
                tool=self.name,
                rule=m.group("rule"),
                severity=_ty_severity(m.group("level")),
                path=rel,
                line=int(m.group("line")),
                message=m.group("message").strip(),
            ))

        return findings
