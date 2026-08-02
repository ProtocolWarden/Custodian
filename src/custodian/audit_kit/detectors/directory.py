# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""A2 detector — directory structure invariants.

These detectors check filesystem shape: whether directories matching a glob
contain required files or subdirectories.  They do not parse code; they only
inspect the directory tree.

Detectors
─────────
A2  Directory structure invariants — every directory matching a declared
    ``glob`` must contain all ``required_files`` (and/or ``required_dirs``).
    Rules are expressed in ``.custodian.yaml`` under
    ``architecture.directory_structure``.  If no rules are declared the
    detector silently reports 0 findings.

    Typical use: enforce DDD/hexagonal capability folder shape (each
    capability sub-directory must have domain/, ports/, application/).

Config example::

    architecture:
      directory_structure:
        - name: "capability DDD folder shape"
          glob: "src/domain/*/capabilities/*"
          required_dirs:
            - domain
            - ports
            - application
          severity: medium   # optional, default medium
          exclude:           # optional globs relative to repo_root
            - "src/domain/*/capabilities/shared"

Globs are matched against *directory* paths relative to repo_root using
fnmatch, so ``**`` matches any number of path components.
"""
from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path, PurePosixPath

from custodian.audit_kit.detector import (
    MEDIUM,
    AuditContext,
    Detector,
    DetectorResult,
)

_MAX_SAMPLES = 8


def build_directory_detectors() -> list[Detector]:
    return [
        Detector("A2", "directory structure invariant violation", "open",
                 detect_d1, MEDIUM, frozenset()),
    ]


def _parse_dir_rules(config: dict) -> list[dict]:
    arch = config.get("architecture") or {}
    return list(arch.get("directory_structure") or [])


def _glob_match_dir(rel_dir: str, glob: str) -> bool:
    """Match a repo-relative directory path (posix) against a glob pattern.

    Uses PurePosixPath.match() so that ``*`` matches exactly one path component
    (does not cross directory boundaries).  This is correct for directory
    structure rules where ``src/capabilities/*`` means direct children only.
    For multi-level matching use ``**``, which pathlib.match() handles correctly
    as of Python 3.12 when anchored with a leading ``src/...`` segment.
    """
    return PurePosixPath(rel_dir).match(glob)


def _iter_candidate_dirs(repo_root: Path) -> Iterator[Path]:
    """Directories under *repo_root*, skipping generated/hidden trees.

    Uses ``os.walk`` with in-place pruning rather than ``Path.rglob`` because
    rglob cannot prune. It descends into every directory and yields the whole
    subtree, so a hidden directory was only skipped AFTER its contents had
    already been walked and stat'd — and the stat is what failed.

    Observed 2026-07-26: HuggingFace stores hub snapshots as symlinks into
    ``blobs/``, created inside Linux containers. Stat'ing one from Windows
    raises ``OSError`` (WinError 1920, "cannot be accessed by the system"),
    and because that happened during the walk it aborted the ENTIRE audit
    before any detector produced a finding — a repo with a model cache could
    not be audited at all. Pruning also matches this detector's stated intent
    ("skip generated/hidden directories") and is faster: nothing under
    ``.git``, ``.venv`` or a multi-GB cache is ever a directory-structure
    candidate.

    Entries that still raise while walking are skipped rather than fatal,
    consistent with how the caller already treats ``iterdir()`` failures.
    """
    def _on_error(_exc: OSError) -> None:
        return None  # unreadable subtree: skip it, never abort the audit

    for dirpath, dirnames, _ in os.walk(repo_root, onerror=_on_error):
        dirnames[:] = sorted(
            d for d in dirnames
            if not d.startswith(".") and not d.startswith("__")
        )
        for name in dirnames:
            yield Path(dirpath) / name


def detect_d1(context: AuditContext) -> DetectorResult:
    """Flag directories that violate declared structure invariants.

    Each rule in ``architecture.directory_structure`` specifies:
    - ``glob``           : pattern matching directories to check (relative to repo_root)
    - ``required_files`` : list of filenames that must exist inside the dir
    - ``required_dirs``  : list of subdirectory names that must exist inside the dir
    - ``name``           : human-readable rule name (optional, defaults to glob)
    - ``exclude``        : list of directory globs to skip (optional)

    Directories that match ``glob`` but lack any required file/dir are reported.
    """
    rules = _parse_dir_rules(context.config)
    if not rules:
        return DetectorResult(count=0, samples=[])

    repo_root = context.repo_root
    samples: list[str] = []
    count = 0

    for rule in rules:
        glob = rule.get("glob") or ""
        if not glob:
            continue
        name = rule.get("name") or glob
        required_files: list[str] = list(rule.get("required_files") or [])
        required_dirs: list[str] = list(rule.get("required_dirs") or [])
        excludes: list[str] = list(rule.get("exclude") or [])

        if not required_files and not required_dirs:
            continue

        # Walk all directories under repo_root and match against glob
        for candidate in _iter_candidate_dirs(repo_root):
            try:
                rel = candidate.relative_to(repo_root).as_posix()
            except ValueError:
                continue

            if not _glob_match_dir(rel, glob):
                continue

            # Check excludes
            if any(_glob_match_dir(rel, excl) for excl in excludes):
                continue

            # Check required contents
            try:
                children_files = {p.name for p in candidate.iterdir() if p.is_file()}
                children_dirs = {p.name for p in candidate.iterdir() if p.is_dir()}
            except OSError:
                continue

            missing_files = [f for f in required_files if f not in children_files]
            missing_dirs = [d for d in required_dirs if d not in children_dirs]
            missing = (
                [f"file:{f}" for f in missing_files]
                + [f"dir:{d}" for d in missing_dirs]
            )

            for item in missing:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(f"{rel}: missing {item} — required by {name!r}")

    return DetectorResult(count=count, samples=samples)
