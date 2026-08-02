# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""M-class detectors — repo-meta file presence.

Public repos are expected to ship a small set of meta files at the
repo root: a changelog, a contributing guide, a security disclosure
policy, and a license. GitHub surfaces these in the repo UI; missing
ones are real onboarding gaps.

Detectors
─────────
M1  ``CHANGELOG.md`` present at repo root
M2  ``CONTRIBUTING.md`` present at repo root
M3  ``SECURITY.md`` present at repo root
M4  ``LICENSE``, ``LICENSE.md``, ``LICENSE.txt``, or ``LICENCE`` present
    at repo root

All detectors are LOW severity. Each can be opted out per repo via
the ``repo_meta:`` config block — useful for repos that legitimately
don't ship one (e.g., a private library with its license vendored
elsewhere)::

    repo_meta:
      skip:
        - M1   # CHANGELOG handled in upstream repo
"""
from __future__ import annotations

import re

from custodian.audit_kit.detector import (
    LOW,
    AuditContext,
    Detector,
    DetectorResult,
)

_CHANGELOG_H1_RE = re.compile(
    r"^#\s+changelog\b", re.IGNORECASE | re.MULTILINE,
)
# Matches `## [1.2.3]`, `## [1.2.3] - 2026-05-08`, `## [Unreleased]`.
_CHANGELOG_RELEASE_RE = re.compile(
    r"^##\s+\[(?:unreleased|\d+\.\d+\.\d+(?:[-+][\w\.]+)?)\]",
    re.IGNORECASE | re.MULTILINE,
)

_LICENSE_CANDIDATES: tuple[str, ...] = (
    "LICENSE", "LICENSE.md", "LICENSE.txt",
    "LICENCE", "LICENCE.md", "LICENCE.txt",
)


def build_repo_meta_detectors() -> list[Detector]:
    return [
        Detector("M1", "CHANGELOG.md missing at repo root",
                 "open", detect_m1, LOW, frozenset()),
        Detector("M2", "CONTRIBUTING.md missing at repo root",
                 "open", detect_m2, LOW, frozenset()),
        Detector("M3", "SECURITY.md missing at repo root",
                 "open", detect_m3, LOW, frozenset()),
        Detector("M4", "LICENSE missing at repo root",
                 "open", detect_m4, LOW, frozenset()),
        Detector("M5", "CHANGELOG.md not in Keep-a-Changelog format",
                 "open", detect_m5, LOW, frozenset()),
    ]


def _skipped(ctx: AuditContext, detector_id: str) -> bool:
    """True when the operator opted this detector out via config."""
    block = ctx.config.get("repo_meta") or {}
    skip = block.get("skip") or []
    return detector_id in skip


def _flag(rel: str) -> DetectorResult:
    return DetectorResult(count=1, samples=[f"{rel}: missing at repo root"])


def detect_m1(ctx: AuditContext) -> DetectorResult:
    if _skipped(ctx, "M1"):
        return DetectorResult(count=0, samples=[])
    if (ctx.repo_root / "CHANGELOG.md").exists():
        return DetectorResult(count=0, samples=[])
    return _flag("CHANGELOG.md")


def detect_m2(ctx: AuditContext) -> DetectorResult:
    if _skipped(ctx, "M2"):
        return DetectorResult(count=0, samples=[])
    if (ctx.repo_root / "CONTRIBUTING.md").exists():
        return DetectorResult(count=0, samples=[])
    return _flag("CONTRIBUTING.md")


def detect_m3(ctx: AuditContext) -> DetectorResult:
    if _skipped(ctx, "M3"):
        return DetectorResult(count=0, samples=[])
    if (ctx.repo_root / "SECURITY.md").exists():
        return DetectorResult(count=0, samples=[])
    return _flag("SECURITY.md")


def detect_m4(ctx: AuditContext) -> DetectorResult:
    if _skipped(ctx, "M4"):
        return DetectorResult(count=0, samples=[])
    for candidate in _LICENSE_CANDIDATES:
        if (ctx.repo_root / candidate).exists():
            return DetectorResult(count=0, samples=[])
    return _flag(f"LICENSE (any of: {', '.join(_LICENSE_CANDIDATES)})")


# ── M5: CHANGELOG format ─────────────────────────────────────────────────────


def detect_m5(ctx: AuditContext) -> DetectorResult:
    """When CHANGELOG.md exists, validate Keep-a-Changelog shape.

    Two checks fold into one count:
      1. First line / early heading is ``# Changelog``
      2. At least one release section ``## [X.Y.Z]`` or ``## [Unreleased]``
         appears in the file.

    Silent when CHANGELOG.md is absent (M1 covers absence). Skip via
    ``repo_meta.skip: [M5]``.
    """
    if _skipped(ctx, "M5"):
        return DetectorResult(count=0, samples=[])
    changelog = ctx.repo_root / "CHANGELOG.md"
    if not changelog.exists():
        return DetectorResult(count=0, samples=[])
    try:
        text = changelog.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return DetectorResult(count=0, samples=[])
    samples: list[str] = []
    if not _CHANGELOG_H1_RE.search(text):
        samples.append("CHANGELOG.md:1: missing `# Changelog` H1 heading")
    if not _CHANGELOG_RELEASE_RE.search(text):
        samples.append(
            "CHANGELOG.md: no release sections "
            "(expected `## [Unreleased]` or `## [X.Y.Z]` headings)"
        )
    return DetectorResult(count=len(samples), samples=samples)
