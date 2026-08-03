# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Coverage.json adapter — dynamic-execution coverage findings.

Custodian does NOT run coverage.py itself (running coverage means running the
production pipeline, which is repo-specific). Instead, this adapter consumes
a ``coverage.json`` file produced externally — typically by the consuming
repo's own end-to-end audit hook — and emits per-module / per-function
findings that an agent can act on.

Output shape mirrors the other adapters:
    CV1  module has 0% executed coverage during the recorded run
    CV2  function never executed during the recorded run

Configuration (under ``tools.coverage`` in ``.custodian.yaml``):
    enabled:        false (default — opt-in)
    json_path:      path to coverage.json relative to repo root
                    (default: "coverage.json")
    min_coverage:   integer 0-100; per-module coverage below this triggers CV3
                    (default: None — disable CV3)
    exclude_paths:  list of glob patterns (matched against the file's
                    repo-relative path) to suppress entirely

The adapter is default-OFF in the standalone ``custodian`` CLI. Consumers
that have a coverage.json producer in their pipeline (e.g. OpsCenter dispatch)
opt in via .custodian.yaml or by enabling at invocation time.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

from custodian.adapters.base import ToolAdapter
from custodian.audit_kit.glob_match import glob_match
from custodian.core.finding import LOW, Finding


class CoverageAdapter(ToolAdapter):
    """Reads ``coverage.json`` and emits dynamic-coverage findings."""

    name: ClassVar[str] = "coverage"

    def __init__(
        self,
        *,
        json_path: str = "coverage.json",
        min_coverage: int | None = None,
        exclude_paths: list[str] | None = None,
    ) -> None:
        self._json_path = json_path
        self._min_coverage = min_coverage
        self._exclude_paths = list(exclude_paths or [])

    def is_available(self) -> bool:
        # Adapter doesn't shell out to anything — it just reads JSON.
        # Availability is "is there a coverage.json to read?" decided at run time.
        return True

    def run(self, repo_path: Path, config: dict) -> list[Finding]:
        cov_path = Path(self._json_path)
        if not cov_path.is_absolute():
            cov_path = repo_path / cov_path

        if not cov_path.is_file():
            return [Finding(
                tool=self.name,
                rule="COVERAGE_JSON_MISSING",
                severity=LOW,
                path=str(cov_path),
                line=0,
                message=f"coverage.json not found at {cov_path}; nothing to analyze",
            )]

        try:
            data = json.loads(cov_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return [Finding(
                tool=self.name,
                rule="COVERAGE_JSON_INVALID",
                severity=LOW,
                path=str(cov_path),
                line=0,
                message=f"failed to read coverage.json: {exc}",
            )]

        findings: list[Finding] = []
        files: dict[str, Any] = data.get("files") or {}
        for file_path, file_data in sorted(files.items()):
            rel = self._rel_to_repo(file_path, repo_path)
            if self._is_excluded(rel):
                continue

            summary = file_data.get("summary") or {}
            num_statements = int(summary.get("num_statements") or 0)
            covered_lines = int(summary.get("covered_lines") or 0)
            percent = float(summary.get("percent_covered") or 0.0)

            if num_statements == 0:
                continue  # empty file / __init__.py — nothing to cover

            if covered_lines == 0:
                # CV1 — module entirely unexecuted
                findings.append(Finding(
                    tool=self.name,
                    rule="CV1_MODULE_UNEXECUTED",
                    severity=LOW,
                    path=rel,
                    line=0,
                    message=(
                        f"module had 0/{num_statements} statements executed during "
                        "the recorded run — likely dead in production"
                    ),
                ))
                # No point checking further details on a fully unexecuted module.
                continue

            # CV2 — per-function findings (functions block is optional in coverage.json)
            functions = file_data.get("functions") or {}
            for func_name, func_data in sorted(functions.items()):
                if not func_name:
                    continue
                func_summary = func_data.get("summary") or {}
                func_covered = int(func_summary.get("covered_lines") or 0)
                func_statements = int(func_summary.get("num_statements") or 0)
                if func_statements == 0 or func_covered > 0:
                    continue
                # Try to get line number from executed_lines / missing_lines
                missing = func_data.get("missing_lines") or []
                lineno = int(missing[0]) if missing else 0
                findings.append(Finding(
                    tool=self.name,
                    rule="CV2_FUNCTION_UNEXECUTED",
                    severity=LOW,
                    path=rel,
                    line=lineno,
                    message=f"function {func_name!r} never executed during the recorded run",
                ))

            # CV3 — module below configured min_coverage
            if self._min_coverage is not None and percent < self._min_coverage:
                findings.append(Finding(
                    tool=self.name,
                    rule="CV3_MODULE_BELOW_MIN_COVERAGE",
                    severity=LOW,
                    path=rel,
                    line=0,
                    message=(
                        f"module {percent:.0f}% covered (below configured "
                        f"min_coverage={self._min_coverage}%)"
                    ),
                ))

        return findings

    def _rel_to_repo(self, file_path: str, repo_path: Path) -> str:
        """Best-effort repo-relative path for the finding.

        `.as_posix()`, not `str()`: this path is both matched against the
        forward-slash globs in ``exclude_paths`` and emitted as the finding
        path, so on Windows `str()` would silently void every exclusion.
        """
        try:
            return Path(file_path).resolve().relative_to(repo_path.resolve()).as_posix()
        except ValueError:
            return file_path

    def _is_excluded(self, rel_path: str) -> bool:
        return any(glob_match(rel_path, p) for p in self._exclude_paths)


__all__ = ["CoverageAdapter"]
