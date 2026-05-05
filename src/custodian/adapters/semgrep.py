# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Semgrep adapter — runs `semgrep --json` and normalizes SARIF/JSON output."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from custodian.adapters.base import ToolAdapter, find_tool
from custodian.core.finding import Finding, HIGH, MEDIUM, LOW

# Semgrep severity strings → canonical severity
_SEMGREP_SEVERITY: dict[str, str] = {
    "ERROR":   HIGH,
    "WARNING": MEDIUM,
    "INFO":    LOW,
    "INVENTORY": LOW,
    "EXPERIMENT": LOW,
}


def _semgrep_severity(raw: str) -> str:
    return _SEMGREP_SEVERITY.get(raw.upper(), MEDIUM)


class SemgrepAdapter(ToolAdapter):
    """Runs Semgrep with a config directory and maps findings to Finding objects.

    Semgrep is optional — when not installed ``is_available`` returns False and
    the runner emits a TOOL_UNAVAILABLE finding without calling ``run``.
    """

    name = "semgrep"

    def __init__(self, configs: list[str] | None = None) -> None:
        self._configs = configs or []

    def is_available(self) -> bool:
        return find_tool("semgrep") is not None

    def run(self, repo_path: Path, config: dict) -> list[Finding]:
        src_root = repo_path / config.get("src_root", "src")
        if not src_root.exists():
            src_root = repo_path

        # Resolve config paths: prefer explicit adapter configs, then repo
        # rules-dir conventions. Newer convention is `.custodian/rules/
        # semgrep/` (keeps all custodian-related files under .custodian/);
        # `rules/semgrep/` is honored as a fallback.
        configs = list(self._configs)
        if not configs:
            for candidate in (
                repo_path / ".custodian" / "rules" / "semgrep",
                repo_path / "rules" / "semgrep",
            ):
                if candidate.is_dir():
                    configs = [str(candidate)]
                    break
        if not configs:
            # No rules — nothing to run
            return []
        # Resolve relative configs against repo_path so .custodian.yaml can
        # use repo-relative paths.
        configs = [
            str((repo_path / cfg).resolve()) if not Path(cfg).is_absolute() else cfg
            for cfg in configs
        ]

        cmd = [find_tool("semgrep") or "semgrep", "--json", "--quiet"]
        for cfg in configs:
            cmd += ["--config", cfg]
        cmd.append(str(src_root))

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

        raw = proc.stdout.strip()
        if not raw:
            return []

        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return [Finding(
                tool=self.name,
                rule="TOOL_ERROR",
                severity=LOW,
                path=None,
                line=None,
                message=f"semgrep produced non-JSON output: {raw[:200]}",
            )]

        findings: list[Finding] = []
        for item in data.get("results", []):
            check_id = item.get("check_id", "SEMGREP_UNKNOWN")
            rule_id = check_id.split(".")[-1] if "." in check_id else check_id
            message = item.get("extra", {}).get("message", item.get("message", ""))
            raw_sev = item.get("extra", {}).get("severity", item.get("severity", "WARNING"))
            path_str = item.get("path", "")
            try:
                rel = str(Path(path_str).relative_to(repo_path))
            except ValueError:
                rel = path_str or None
            start = item.get("start", {})
            line = start.get("line")

            findings.append(Finding(
                tool=self.name,
                rule=rule_id,
                severity=_semgrep_severity(raw_sev),
                path=rel,
                line=line,
                message=message,
            ))

        return findings
