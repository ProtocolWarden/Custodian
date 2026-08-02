# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""markdownlint adapter — Markdown linting for headings, code fences, lists.

Uses the ``markdownlint-cli2`` binary (or its predecessor ``markdownlint``).
Operators install it via ``npm i -g markdownlint-cli2`` (or ``brew install
markdownlint-cli2``); the adapter probes for either binary and falls back
gracefully when neither is present.

R-class + DC-class detectors enforce content-shape conventions
(README structure, doc conventions). markdownlint covers the
markup-level concerns those classes intentionally don't:

  - heading hierarchy (MD001 — heading levels skip; MD003 — heading
    style mixed; MD025 — multiple H1s)
  - code-fence languages (MD040 — fenced code blocks should have a
    language specified)
  - list ordering (MD029 — ordered list item prefix)
  - line-length, trailing whitespace, etc.

Default scope: ``README.md`` plus everything under ``docs/``. Operators
override via ``tools.markdownlint.globs`` and tune the rule set via
``tools.markdownlint.config`` (path to a markdownlint config file).
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from custodian.adapters.base import ToolAdapter, find_tool
from custodian.core.finding import HIGH, LOW, MEDIUM, Finding

_DEFAULT_GLOBS: tuple[str, ...] = ("README.md", "docs/**/*.md")
_DEFAULT_TIMEOUT = 60


# Severity heuristic. markdownlint rule numbers don't carry severity
# semantics; most are style nits. Bump the few that genuinely break
# rendering or hide info from consumers.
_HIGH_RULES: frozenset[str] = frozenset({
    "MD025",   # Multiple top-level headings (breaks H1-as-title)
    "MD040",   # Fenced code without language (no syntax highlighting)
})
_MED_RULES: frozenset[str] = frozenset({
    "MD001",   # Heading levels should only increment by one
    "MD003",   # Heading style consistency
    "MD024",   # Duplicate heading content
    "MD029",   # Ordered-list item prefix
    "MD050",   # Strong style (asterisk vs underscore)
    "MD051",   # Link fragments
})


def _severity_for(rule: str) -> str:
    if rule in _HIGH_RULES:
        return HIGH
    if rule in _MED_RULES:
        return MEDIUM
    return LOW


def _binary() -> str | None:
    """Prefer markdownlint-cli2; fall back to legacy markdownlint."""
    return find_tool("markdownlint-cli2") or find_tool("markdownlint")


class MarkdownlintAdapter(ToolAdapter):
    """Wraps markdownlint-cli2 (or markdownlint) and normalizes findings."""

    name = "markdownlint"

    def __init__(
        self,
        *,
        globs: list[str] | None = None,
        config: str | None = None,
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self._globs = list(globs) if globs else list(_DEFAULT_GLOBS)
        self._config = config
        self._timeout = timeout

    def is_available(self) -> bool:
        return _binary() is not None

    def run(self, repo_path: Path, config: dict) -> list[Finding]:
        binary = _binary()
        if binary is None:
            return [Finding.tool_unavailable(self.name)]

        # Both binaries support `--json` for structured output (cli2 emits
        # JSON to stderr by default; legacy markdownlint emits to stdout
        # via -j). Build the cmd to match whichever is available.
        is_cli2 = binary.endswith("markdownlint-cli2")
        cmd: list[str] = [binary]
        if self._config:
            cmd += (["--config", self._config] if is_cli2
                    else ["--config", self._config])
        # Output flag.
        if is_cli2:
            cmd.append("--no-globs")  # we'll pass paths verbatim
            cmd += self._globs
        else:
            cmd += ["-j", *self._globs]

        env = os.environ.copy()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=repo_path,
                env=env,
                timeout=self._timeout,
            )
        except FileNotFoundError:
            return [Finding.tool_unavailable(self.name)]
        except subprocess.TimeoutExpired:
            return [Finding(
                tool=self.name, rule="TOOL_TIMEOUT", severity=MEDIUM,
                path=None, line=None,
                message=f"markdownlint timed out after {self._timeout}s",
            )]

        # Both binaries exit non-zero when findings exist. Empty stdout
        # + zero-exit is a clean run. JSON lives on stdout for legacy
        # and on stderr for cli2; try both.
        raw = proc.stdout.strip() or proc.stderr.strip()
        if not raw:
            return []

        try:
            items = json.loads(raw)
        except json.JSONDecodeError:
            # cli2 emits non-JSON when no findings — that's fine.
            return []

        return self._items_to_findings(items, is_cli2=is_cli2)

    # ── normalization ───────────────────────────────────────────────────────

    def _items_to_findings(
        self, items: object, *, is_cli2: bool,
    ) -> list[Finding]:
        # JSON-shaped input — ty narrows isinstance(x, dict) to dict[Never,Never]
        # so each .get() flags. Cast to typing.Any once at the boundary.
        from typing import Any, cast
        out: list[Finding] = []
        if is_cli2:
            # cli2 shape: list of {fileName, lineNumber, ruleNames, ruleDescription, ...}
            if not isinstance(items, list):
                return out
            for raw in items:
                if not isinstance(raw, dict):
                    continue
                item = cast(dict[str, Any], raw)
                rule_names = item.get("ruleNames") or []
                rule = rule_names[0] if rule_names else "MD000"
                out.append(Finding(
                    tool=self.name,
                    rule=str(rule),
                    severity=_severity_for(str(rule)),
                    path=str(item.get("fileName") or item.get("filename") or ""),
                    line=item.get("lineNumber"),
                    message=str(item.get("ruleDescription") or item.get("ruleName") or ""),
                ))
        else:
            # legacy markdownlint shape: {file: [issue, ...], ...}
            if not isinstance(items, dict):
                return out
            items_map = cast(dict[str, Any], items)
            for file_path, issues in items_map.items():
                if not isinstance(issues, list):
                    continue
                for raw_issue in issues:
                    if not isinstance(raw_issue, dict):
                        continue
                    issue = cast(dict[str, Any], raw_issue)
                    rule_names = issue.get("ruleNames") or []
                    rule = rule_names[0] if rule_names else "MD000"
                    out.append(Finding(
                        tool=self.name,
                        rule=str(rule),
                        severity=_severity_for(str(rule)),
                        path=str(file_path),
                        line=issue.get("lineNumber"),
                        message=str(issue.get("ruleDescription") or ""),
                    ))
        return out
