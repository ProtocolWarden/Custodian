# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Semgrep adapter — runs `semgrep --json` and normalizes SARIF/JSON output."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from custodian.adapters.base import ToolAdapter, find_tool
from custodian.core.finding import HIGH, LOW, MEDIUM, Finding

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

    #: Where the repo is mounted inside the container. Targets and configs are
    #: passed *relative* to it, so semgrep emits repo-relative result paths.
    _MOUNT = "/src"

    def __init__(
        self,
        configs: list[str] | None = None,
        docker: bool = False,
        image: str = "semgrep/semgrep:latest",
        timeout: int = 120,
    ) -> None:
        self._configs = configs or []
        self._docker = docker
        self._image = image
        self._timeout = timeout

    def is_available(self) -> bool:
        if self._docker:
            return find_tool("docker") is not None
        return find_tool("semgrep") is not None

    def _docker_cmd(
        self, repo_path: Path, configs: list[str], src_root: Path
    ) -> list[str]:
        """Build a ``docker run`` invocation equivalent to the native call.

        Native semgrep does not work on every host. On Windows ``semgrep-core``
        fails rule validation outright (``RPC subprocess exited with code 1``)
        *and* semgrep still exits 0, so an authored rule set silently never
        executes while the config keeps asserting it does. Running the official
        image sidesteps the platform question entirely.

        Paths are passed **relative to the mount**, which also fixes result
        paths: semgrep echoes back the form it was given, so relative targets
        yield repo-relative result paths on every platform.

        Raises:
            ValueError: if a rules dir or the source root lies outside the repo,
                since only the repo is mounted.
        """
        repo_root = repo_path.resolve()

        def _rel(p: Path | str) -> str:
            try:
                return Path(p).resolve().relative_to(repo_root).as_posix()
            except ValueError:
                raise ValueError(
                    f"semgrep docker mode cannot reach a path outside the repo: {p} "
                    f"(only {repo_root} is mounted). Move the rules under the repo, "
                    "or set docker: false for this adapter."
                ) from None

        cmd = [
            find_tool("docker") or "docker", "run", "--rm",
            "-v", f"{repo_root.as_posix()}:{self._MOUNT}",
            "-w", self._MOUNT,
            self._image,
            "semgrep", "--json", "--quiet", "--metrics=off",
        ]
        for cfg in configs:
            cmd += ["--config", _rel(cfg)]
        cmd.append(_rel(src_root))
        return cmd

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

        if self._docker:
            try:
                cmd = self._docker_cmd(repo_path, configs, src_root)
            except ValueError as exc:
                return [Finding(
                    tool=self.name,
                    rule="TOOL_ERROR",
                    severity=LOW,
                    path=None,
                    line=None,
                    message=str(exc),
                )]
        else:
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
                timeout=self._timeout,
                # Parse the output regardless of exit status; a non-zero
                # code is handled per-adapter, not by raising.
                check=False,
            )
        except FileNotFoundError:
            return [Finding.tool_unavailable(self.name)]
        except subprocess.TimeoutExpired:
            return [Finding(
                tool=self.name,
                rule="TOOL_ERROR",
                severity=LOW,
                path=None,
                line=None,
                message=f"semgrep timed out after {self._timeout}s",
            )]

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
                # `.as_posix()`, not `str()`: on Windows the latter yields
                # `src\foo\bar.py`, which no forward-slash config glob matches.
                # Matches the form `_rel` already produces for docker mode.
                rel = Path(path_str).relative_to(repo_path).as_posix()
            except ValueError:
                # Not under repo_path — the tool reported a cwd-relative
                # path. Already repo-relative, but still native-separated,
                # and this branch is the one semgrep actually takes: it runs
                # with cwd=repo_path, so relative_to() always raises.
                rel = Path(path_str).as_posix() if path_str else None
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
