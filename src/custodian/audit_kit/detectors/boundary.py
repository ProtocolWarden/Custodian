# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""B-class detectors — boundary / private-repo-name leakage.

Public repos describe stable, reusable platform capabilities. Private
manifests bind those capabilities to specific private repos. A public
repo that names a private repo in its tracked artifacts leaks the
private/public boundary — operators who consume the public repo learn
which private repos the platform's owner runs.

This detector class enforces that boundary. Configure the names you
treat as private in ``.custodian/config.yaml``::

    privacy:
      private_repo_names:
        - PrivateRepoName
        - privaterepo_name
      exclude_paths:
        - "docs/history/**"
        - "config/managed_repos/local/**"
        - ".console/**"

Match is case-sensitive substring on text content. Configure both
``CamelCase`` and ``snake_case`` (or any other casing the repo's
package uses) explicitly — the detector does not normalise casing
because the leak surface is the literal string an operator sees in
tracked files. Binary files are skipped.

Detectors
─────────
B1  Tracked file under the repo root contains a configured private-repo
    name. MEDIUM severity. The detector returns one finding per
    line/match (capped at ``_MAX_SAMPLES``); the first ~8 violations
    are reported in samples.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, MEDIUM,
)
from custodian.audit_kit.glob_match import glob_match


_MAX_SAMPLES = 8
_DEFAULT_EXCLUDES: tuple[str, ...] = (
    # The Custodian config that *defines* the banned names. The literal
    # names must appear there for the rule to function — flagging them
    # would force operators to add an exclude in every consumer.
    ".custodian/config.yaml",
    ".custodian.yaml",  # legacy single-file location
    # Operator-private workspaces — historical narration may legitimately
    # reference past private bindings.
    ".console/**",
    # Gitignored overlay where the real bindings live.
    "config/managed_repos/local/**",
    # History docs that recount past events.
    "docs/history/**",
    # Custodian's own audit reports that may have captured past leaks.
    "tools/audit/report/**",
)
_BINARY_SUFFIXES: tuple[str, ...] = (
    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".tar", ".gz",
    ".whl", ".so", ".dylib", ".dll", ".exe", ".ico", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".mov", ".webm",
)


def build_boundary_detectors() -> list[Detector]:
    return [
        Detector(
            "B1",
            "Tracked file contains a private-repo name",
            "open",
            detect_b1,
            MEDIUM,
            frozenset(),
        ),
    ]


def _parse_config(config: dict) -> tuple[list[str], list[str]]:
    """Return (private_repo_names, exclude_paths) from the config."""
    block = config.get("privacy") or {}
    names = list(block.get("private_repo_names") or [])
    extra_excludes = list(block.get("exclude_paths") or [])
    excludes = list(_DEFAULT_EXCLUDES) + extra_excludes
    return names, excludes


def _tracked_files(repo_root: Path) -> list[Path]:
    """List files tracked by git, relative to repo_root.

    Falls back to a recursive walk when git isn't available so the
    detector still works on a fresh clone or in a container without
    git installed. Untracked files are scanned in fallback mode (the
    git path scopes to tracked-only by design — that is the public
    surface).
    """
    try:
        out = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=repo_root,
            capture_output=True,
            check=True,
            text=False,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return [
            p for p in repo_root.rglob("*")
            if p.is_file() and ".git" not in p.parts
        ]
    paths: list[Path] = []
    for raw in out.stdout.split(b"\x00"):
        if not raw:
            continue
        try:
            rel = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        paths.append(repo_root / rel)
    return paths


def _is_excluded(rel: Path, excludes: list[str]) -> bool:
    rel_posix = rel.as_posix()
    return any(glob_match(rel_posix, pat) for pat in excludes)


def _is_binary(path: Path) -> bool:
    return path.suffix.lower() in _BINARY_SUFFIXES


def detect_b1(context: AuditContext) -> DetectorResult:
    """Flag tracked files that contain a configured private-repo name.

    Match is case-sensitive substring against the file contents, line
    by line. Each violation is reported at ``<rel>:<lineno>: contains
    'NAME'``; only the first ~8 are surfaced as samples but the count
    reflects every match. Binary files and configured exclude paths
    are skipped.
    """
    names, excludes = _parse_config(context.config)
    if not names:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0
    for path in _tracked_files(context.repo_root):
        try:
            rel = path.relative_to(context.repo_root)
        except ValueError:
            continue
        if _is_excluded(rel, excludes):
            continue
        if _is_binary(path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        # Skip the privacy detector's own source + tests so that the
        # configured-names list inside Custodian itself doesn't trip
        # the rule. This is identified by file content rather than
        # path so consumers don't need to remember to exclude it.
        if "build_boundary_detectors" in text and "_DEFAULT_EXCLUDES" in text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for name in names:
                if name in line:
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        samples.append(
                            f"{rel}:{lineno}: contains {name!r}"
                        )
                    break  # one finding per line is enough
    return DetectorResult(count=count, samples=samples)
