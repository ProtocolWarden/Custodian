# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Vulture adapter — advisory dead-code detection.

Vulture output format:
    path/file.py:10: unused variable 'x' (60% confidence)
    path/file.py:15: unused function 'foo' (100% confidence)

Findings from vulture are advisory (LOW severity) — they flag potential dead
code but have false-positive risk for dynamic dispatch, plugins, and public APIs.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from custodian.adapters.base import ToolAdapter, find_tool
from custodian.core.finding import LOW, Finding

# path:line: unused <type> 'name' (N% confidence)
_LINE_RE = re.compile(
    r"^(?P<path>.+):(?P<line>\d+):\s+(?P<message>unused .+)\s+\((?P<confidence>\d+)%"
)

# Extract kind from message for the rule name
_KIND_RE = re.compile(r"^unused (\w+)")

# Minimum confidence to emit a finding (below this = too noisy)
_DEFAULT_MIN_CONFIDENCE = 60


def _rule_from_message(message: str) -> str:
    m = _KIND_RE.match(message)
    if m:
        return f"UNUSED_{m.group(1).upper()}"
    return "UNUSED_CODE"


class VultureAdapter(ToolAdapter):
    """Runs Vulture for advisory dead-code detection.

    All vulture findings are LOW severity — they are hints, not hard failures.
    Use min_confidence to reduce false positives (default 60%).
    """

    name = "vulture"

    def __init__(self, min_confidence: int = _DEFAULT_MIN_CONFIDENCE) -> None:
        self._min_confidence = min_confidence

    def is_available(self) -> bool:
        return find_tool("vulture") is not None

    def run(self, repo_path: Path, config: dict) -> list[Finding]:
        src_root = repo_path / config.get("src_root", "src")
        if not src_root.exists():
            src_root = repo_path

        tests_root = repo_path / config.get("tests_root", "tests")

        min_conf = config.get("vulture_min_confidence", self._min_confidence)

        # Every PATH must precede the options. vulture's argparse rejects a
        # positional that follows `--min-confidence=`, exiting 2 with an empty
        # stdout — which used to read as "no dead code" (see the returncode
        # check below). Collect the paths first, then append the flags.
        paths = [str(src_root)]

        # Include tests so vulture can see call sites for public API functions
        if tests_root.exists():
            paths.append(str(tests_root))

        # If a whitelist file exists in the repo, include it
        whitelist = repo_path / ".vulture_whitelist.py"
        if whitelist.exists():
            paths.append(str(whitelist))

        cmd = [find_tool("vulture") or "vulture", *paths, f"--min-confidence={min_conf}"]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=repo_path,
                timeout=120,
            )
        except FileNotFoundError:
            return [Finding.tool_unavailable(self.name)]

        # vulture exits 0 with no findings, 3 when it HAS findings. Anything
        # else (2 = bad arguments) means it never analysed anything — and an
        # empty stdout would otherwise be indistinguishable from a clean repo,
        # so the adapter would report `status: pass` for a tool that never ran.
        if proc.returncode not in (0, 3) and not proc.stdout.strip():
            detail = (proc.stderr or "").strip().splitlines()
            return [Finding(
                tool=self.name,
                rule="TOOL_ERROR",
                severity=LOW,
                path=None,
                line=None,
                message=(
                    f"vulture exited {proc.returncode} without output: "
                    f"{detail[-1] if detail else 'no stderr'}"
                ),
            )]

        findings: list[Finding] = []
        for raw_line in proc.stdout.splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            m = _LINE_RE.match(raw_line)
            if not m:
                continue
            confidence = int(m.group("confidence"))
            if confidence < min_conf:
                continue
            path_str = m.group("path")
            try:
                rel = str(Path(path_str).relative_to(repo_path))
            except ValueError:
                rel = path_str
            message = m.group("message")
            findings.append(Finding(
                tool=self.name,
                rule=_rule_from_message(message),
                severity=LOW,
                path=rel,
                line=int(m.group("line")),
                message=f"{message} ({confidence}% confidence)",
            ))

        return findings
