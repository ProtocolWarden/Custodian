# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
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

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
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
