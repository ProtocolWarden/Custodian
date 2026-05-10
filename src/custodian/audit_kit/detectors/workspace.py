# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""W-class workspace integrity detectors.

  W1  .console/ required files   — task.md, guidelines.md, backlog.md, log.md
                                   must all be present in .console/.
  W2  .hooks/ wiring             — if .hooks/pre-commit exists,
                                   core.hooksPath must be set to .hooks in
                                   the local git config. An unwired hook is
                                   silently ignored by git.
  W3  .hooks/pre-commit content  — the pre-commit hook must contain log.md
                                   enforcement (grep for .console/log.md).
  W4  .gitmodules branch pinning — every submodule entry in .gitmodules must
                                   declare a branch = line so that
                                   `git submodule update --remote` tracks the
                                   intended branch rather than defaulting to
                                   the remote HEAD.
  W5  .env.example present       — if .gitignore excludes .env, an
                                   .env.example must exist at the repo root so
                                   env-var contracts are documented.
  W6  .hooks/pre-commit required — if .console/ is present the repo is a
                                   managed session workspace; it must have a
                                   .hooks/pre-commit to protect it.
"""
from __future__ import annotations

import re

from pathlib import Path

from custodian.audit_kit.detector import AuditContext, Detector, DetectorResult, MEDIUM, LOW, HIGH

_REQUIRED_CONSOLE_FILES = ("task.md", "guidelines.md", "backlog.md", "log.md")

_HOOKS_PATH_RE = re.compile(r"hooksPath\s*=\s*\.hooks", re.IGNORECASE)
_LOG_GUARD_RE = re.compile(r"\.console/log\.md|console/log\.md", re.IGNORECASE)
_GITIGNORE_ENV_RE = re.compile(r"^\.env$", re.MULTILINE)
_SUBMODULE_HEADER_RE = re.compile(r"^\[submodule\s", re.MULTILINE)
_BRANCH_LINE_RE = re.compile(r"^\s*branch\s*=", re.MULTILINE)


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


def _detect_w3_hook_content(ctx: AuditContext) -> DetectorResult:
    pre_commit = ctx.repo_root / ".hooks" / "pre-commit"
    if not pre_commit.exists():
        return DetectorResult(count=0, samples=[])
    try:
        text = pre_commit.read_text()
    except OSError:
        return DetectorResult(count=0, samples=[])
    if _LOG_GUARD_RE.search(text):
        return DetectorResult(count=0, samples=[])
    return DetectorResult(
        count=1,
        samples=[
            ".hooks/pre-commit exists but contains no .console/log.md enforcement — "
            "add a log.md staged check or the hook is not guarding session records"
        ],
    )


def _detect_w4_gitmodules_branch(ctx: AuditContext) -> DetectorResult:
    gitmodules = ctx.repo_root / ".gitmodules"
    if not gitmodules.exists():
        return DetectorResult(count=0, samples=[])
    try:
        text = gitmodules.read_text()
    except OSError:
        return DetectorResult(count=0, samples=[])

    blocks = _SUBMODULE_HEADER_RE.split(text)
    missing: list[str] = []
    for block in blocks[1:]:  # first element is text before the first header
        header_line = "[submodule " + block.split("\n")[0]
        name_match = re.search(r'"([^"]+)"', header_line)
        name = name_match.group(1) if name_match else header_line.strip()
        block_end = block.find("\n[")
        chunk = block if block_end == -1 else block[:block_end]
        if not _BRANCH_LINE_RE.search(chunk):
            missing.append(f"submodule '{name}' has no branch = line in .gitmodules")
    return DetectorResult(count=len(missing), samples=missing)


def _detect_w5_env_example(ctx: AuditContext) -> DetectorResult:
    gitignore = ctx.repo_root / ".gitignore"
    if not gitignore.exists():
        return DetectorResult(count=0, samples=[])
    try:
        text = gitignore.read_text()
    except OSError:
        return DetectorResult(count=0, samples=[])
    if not _GITIGNORE_ENV_RE.search(text):
        return DetectorResult(count=0, samples=[])
    env_example = ctx.repo_root / ".env.example"
    if env_example.exists():
        return DetectorResult(count=0, samples=[])
    return DetectorResult(
        count=1,
        samples=[
            ".gitignore excludes .env but .env.example is missing — "
            "add .env.example to document the required env vars"
        ],
    )


def _detect_w6_hook_required(ctx: AuditContext) -> DetectorResult:
    console = ctx.repo_root / ".console"
    if not console.is_dir():
        return DetectorResult(count=0, samples=[])
    pre_commit = ctx.repo_root / ".hooks" / "pre-commit"
    if pre_commit.exists():
        return DetectorResult(count=0, samples=[])
    return DetectorResult(
        count=1,
        samples=[
            ".console/ is present (managed workspace) but .hooks/pre-commit is missing — "
            "add a pre-commit hook and run: git config core.hooksPath .hooks"
        ],
    )


def build_workspace_detectors() -> list[Detector]:
    return [
        Detector("W1", ".console/ required files present", "open", _detect_w1_console_structure, LOW),
        Detector("W2", ".hooks/ wiring (core.hooksPath must be set)", "open", _detect_w2_hooks_wiring, MEDIUM),
        Detector("W3", ".hooks/pre-commit contains log.md enforcement", "open", _detect_w3_hook_content, MEDIUM),
        Detector("W4", ".gitmodules submodules have branch = set", "open", _detect_w4_gitmodules_branch, MEDIUM),
        Detector("W5", ".env.example present when .gitignore excludes .env", "open", _detect_w5_env_example, LOW),
        Detector("W6", ".hooks/pre-commit required when .console/ is present", "open", _detect_w6_hook_required, MEDIUM),
    ]
