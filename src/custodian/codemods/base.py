# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Codemod base — safe, diff-producing file transforms.

A Codemod is a targeted automated fix for a class of findings.  Each
codemod operates on a single file at a time and returns either the
transformed source or ``None`` (no change).

    class RemoveUnusedImport(Codemod):
        applies_to = {"ruff:F401", "I1"}

        def transform(self, path: Path, source: str) -> str | None:
            ...  # return new source, or None if nothing changed

Usage::

    from custodian.codemods.base import run_codemods
    changed = run_codemods(repo_path, findings, codemods, *, dry_run=False)

``run_codemods`` groups findings by file, runs applicable codemods, and
writes back only files that changed.  With ``dry_run=True`` it returns the
diff without writing.
"""
from __future__ import annotations

import difflib
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from custodian.core.finding import Finding


class Codemod(ABC):
    """Base class for all automated fixers.

    Subclasses declare which finding rules they handle via ``applies_to`` and
    implement ``transform()`` to produce a new source string.
    """

    applies_to: frozenset[str] = frozenset()

    def can_fix(self, finding: Finding) -> bool:
        """Return True if this codemod can address the given finding."""
        tool_rule = f"{finding.tool}:{finding.rule}"
        return finding.rule in self.applies_to or tool_rule in self.applies_to

    @abstractmethod
    def transform(self, path: Path, source: str, findings: list[Finding]) -> str | None:
        """Return transformed source, or None if no change is needed.

        Args:
            path:     Absolute path to the file being transformed.
            source:   Current file content.
            findings: All findings for this file that this codemod applies to.
        """


@dataclass
class CodemodeResult:
    path: Path
    original: str
    modified: str
    diff: str = field(init=False)

    def __post_init__(self) -> None:
        original_lines = self.original.splitlines(keepends=True)
        modified_lines = self.modified.splitlines(keepends=True)
        self.diff = "".join(difflib.unified_diff(
            original_lines, modified_lines,
            fromfile=str(self.path), tofile=str(self.path),
        ))


def run_codemods(
    repo_path: Path,
    findings: list[Finding],
    codemods: Sequence[Codemod],
    *,
    dry_run: bool = False,
) -> list[CodemodeResult]:
    """Run applicable codemods against findings and write changes.

    Args:
        repo_path: Repository root for resolving relative finding paths.
        findings:  List of findings from adapters/detectors.
        codemods:  Codemods to apply.
        dry_run:   If True, compute diffs but do not write files.

    Returns a list of CodemodeResult for each file that was (or would be) modified.
    """
    # Group findings by file path
    by_file: dict[Path, list[Finding]] = {}
    for f in findings:
        if f.path is None:
            continue
        abs_path = repo_path / f.path
        by_file.setdefault(abs_path, []).append(f)

    results: list[CodemodeResult] = []

    for abs_path, file_findings in by_file.items():
        if not abs_path.exists():
            continue
        try:
            source = abs_path.read_text(encoding="utf-8")
        except OSError:
            continue

        current = source
        for codemod in codemods:
            applicable = [f for f in file_findings if codemod.can_fix(f)]
            if not applicable:
                continue
            result = codemod.transform(abs_path, current, applicable)
            if result is not None and result != current:
                current = result

        if current != source:
            result = CodemodeResult(path=abs_path, original=source, modified=current)
            results.append(result)
            if not dry_run:
                abs_path.write_text(current, encoding="utf-8")

    return results
