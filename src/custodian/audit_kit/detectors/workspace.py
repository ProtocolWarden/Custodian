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
  W7  .gitignore console policy  — when .console/ is present, .gitignore must
                                   use '.console/*' (not blanket '.console/')
                                   and un-exclude the four tracked files.
                                   When CLAUDE.md is present it must be
                                   listed in .gitignore.
"""
from __future__ import annotations

import re

from custodian.audit_kit.detector import LOW, MEDIUM, AuditContext, Detector, DetectorResult

_REQUIRED_CONSOLE_FILES = ("task.md", "guidelines.md", "backlog.md", "log.md")

_HOOKS_PATH_RE = re.compile(r"hooksPath\s*=\s*\.hooks", re.IGNORECASE)
_LOG_GUARD_RE = re.compile(r"\.console/log\.md|console/log\.md", re.IGNORECASE)
_GITIGNORE_ENV_RE = re.compile(r"^\.env$", re.MULTILINE)
_SUBMODULE_HEADER_RE = re.compile(r"^\[submodule\s", re.MULTILINE)
_BRANCH_LINE_RE = re.compile(r"^\s*branch\s*=", re.MULTILINE)

# W7 patterns
_CONSOLE_BLANKET_RE = re.compile(r"^\.console/$", re.MULTILINE)
_CONSOLE_STAR_RE = re.compile(r"^\.console/\*", re.MULTILINE)
_CLAUDE_MD_RE = re.compile(r"^CLAUDE\.md$", re.MULTILINE)
_CONSOLE_TRACKED_FILES = ("task.md", "guidelines.md", "backlog.md", "log.md")


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
        text = git_config.read_text(encoding="utf-8")
    except OSError:
        return DetectorResult(count=0, samples=[])

    if _HOOKS_PATH_RE.search(text):
        return DetectorResult(count=0, samples=[])

    return DetectorResult(
        count=1,
        samples=[
            (".hooks/pre-commit exists but core.hooksPath is not set — "
            "run: git config core.hooksPath .hooks")
        ],
    )


def _detect_w3_hook_content(ctx: AuditContext) -> DetectorResult:
    pre_commit = ctx.repo_root / ".hooks" / "pre-commit"
    if not pre_commit.exists():
        return DetectorResult(count=0, samples=[])
    try:
        text = pre_commit.read_text(encoding="utf-8")
    except OSError:
        return DetectorResult(count=0, samples=[])
    if _LOG_GUARD_RE.search(text):
        return DetectorResult(count=0, samples=[])
    return DetectorResult(
        count=1,
        samples=[
            (".hooks/pre-commit exists but contains no .console/log.md enforcement — "
            "add a log.md staged check or the hook is not guarding session records")
        ],
    )


def _detect_w4_gitmodules_branch(ctx: AuditContext) -> DetectorResult:
    gitmodules = ctx.repo_root / ".gitmodules"
    if not gitmodules.exists():
        return DetectorResult(count=0, samples=[])
    try:
        text = gitmodules.read_text(encoding="utf-8")
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
        text = gitignore.read_text(encoding="utf-8")
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
            (".gitignore excludes .env but .env.example is missing — "
            "add .env.example to document the required env vars")
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
            (".console/ is present (managed workspace) but .hooks/pre-commit is missing — "
            "add a pre-commit hook and run: git config core.hooksPath .hooks")
        ],
    )


def _detect_w7_gitignore_console_policy(ctx: AuditContext) -> DetectorResult:
    console = ctx.repo_root / ".console"
    claude_md = ctx.repo_root / "CLAUDE.md"
    has_console = console.is_dir()
    has_claude = claude_md.exists()

    if not has_console and not has_claude:
        return DetectorResult(count=0, samples=[])

    gitignore = ctx.repo_root / ".gitignore"
    if not gitignore.exists():
        issues = []
        if has_console:
            issues.append(".gitignore missing — .console/ has no gitignore policy")
        if has_claude:
            issues.append("CLAUDE.md present but no .gitignore to exclude it")
        return DetectorResult(count=len(issues), samples=issues)

    try:
        text = gitignore.read_text(encoding="utf-8")
    except OSError:
        return DetectorResult(count=0, samples=[])

    issues: list[str] = []

    if has_console:
        if _CONSOLE_BLANKET_RE.search(text):
            issues.append(
                ".gitignore uses '.console/' (blanket ignore) — use '.console/*' so that "
                "tracked files can be un-excluded with '!.console/<name>.md'"
            )
        elif not _CONSOLE_STAR_RE.search(text):
            issues.append(
                ".console/ directory present but .gitignore has no '.console/*' entry — "
                "add '.console/*' with !.console/{task,guidelines,backlog,log}.md exceptions"
            )
        else:
            missing_exc = [
                f"!.console/{f}" for f in _CONSOLE_TRACKED_FILES
                if f"!.console/{f}" not in text
            ]
            if missing_exc:
                issues.append(
                    ".gitignore has '.console/*' but is missing tracked-file exceptions: "
                    + ", ".join(missing_exc)
                )

    if has_claude and not _CLAUDE_MD_RE.search(text):
        issues.append("CLAUDE.md is present but not listed in .gitignore")

    return DetectorResult(count=len(issues), samples=issues)


def build_workspace_detectors() -> list[Detector]:
    return [
        Detector("W1", ".console/ required files present", "open", _detect_w1_console_structure, LOW),
        Detector("W2", ".hooks/ wiring (core.hooksPath must be set)", "open", _detect_w2_hooks_wiring, MEDIUM),
        Detector("W3", ".hooks/pre-commit contains log.md enforcement", "open", _detect_w3_hook_content, MEDIUM),
        Detector("W4", ".gitmodules submodules have branch = set", "open", _detect_w4_gitmodules_branch, MEDIUM),
        Detector("W5", ".env.example present when .gitignore excludes .env", "open", _detect_w5_env_example, LOW),
        Detector("W6", ".hooks/pre-commit required when .console/ is present", "open", _detect_w6_hook_required, MEDIUM),
        Detector("W7", ".gitignore console/CLAUDE.md policy correct", "open", _detect_w7_gitignore_console_policy, LOW),
    ]
