# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""W-class workspace integrity detectors.

  W1  .console/ required files   — task.md, guidelines.md, backlog.md, log.md
                                   must all be present in .console/.
  W2  .hooks/ wiring             — if .hooks/pre-commit exists,
                                   core.hooksPath must be set to .hooks in
                                   the local git config. An unwired hook is
                                   silently ignored by git.
"""
from __future__ import annotations

import re

from pathlib import Path

from custodian.audit_kit.detector import AuditContext, Detector, DetectorResult, MEDIUM, LOW

_REQUIRED_CONSOLE_FILES = ("task.md", "guidelines.md", "backlog.md", "log.md")

_HOOKS_PATH_RE = re.compile(r"hooksPath\s*=\s*\.hooks", re.IGNORECASE)


def _detect_w1_console_structure(ctx: AuditContext) -> DetectorResult:
    console = ctx.repo_root / ".console"
    if not console.is_dir():
        return DetectorResult(count=0, samples=[])
    missing = [f for f in _REQUIRED_CONSOLE_FILES if not (console / f).exists()]
    return DetectorResult(
        count=len(missing),
        samples=[f".console/{f} is missing" for f in missing],
    )


def _detect_w2_hooks_wiring(ctx: AuditContext) -> DetectorResult:
    pre_commit = ctx.repo_root / ".hooks" / "pre-commit"
    if not pre_commit.exists():
        return DetectorResult(count=0, samples=[])

    git_config = ctx.repo_root / ".git" / "config"
    if not git_config.exists():
        return DetectorResult(count=0, samples=[])

    try:
        text = git_config.read_text()
    except OSError:
        return DetectorResult(count=0, samples=[])

    if _HOOKS_PATH_RE.search(text):
        return DetectorResult(count=0, samples=[])

    return DetectorResult(
        count=1,
        samples=[
            ".hooks/pre-commit exists but core.hooksPath is not set — "
            "run: git config core.hooksPath .hooks"
        ],
    )


def build_workspace_detectors() -> list[Detector]:
    return [
        Detector("W1", ".console/ required files present", "open", _detect_w1_console_structure, LOW),
        Detector("W2", ".hooks/ wiring (core.hooksPath must be set)", "open", _detect_w2_hooks_wiring, MEDIUM),
    ]
