# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""R-class detectors — README structural conventions.

Enforces a consistent opening shape across repos so that newcomers and
agents both find the same orientation surface. Pure file-read; no
analysis pass needed.

Detectors
─────────
R1  README.md present at repo root.
R2  First H1 heading matches the repo name (case-insensitive, with
    common humanisations — ``OperationsCenter`` matches ``Operations Center``).
R3  An "## What X is" / "## What this repo is" H2 appears within the
    first ~60 lines.
R4  A "## What X is not" / "## What this repo is not" H2 appears
    after R3.
R5  An intro paragraph between the H1 and the first H2 is non-empty
    and contains at least one descriptive sentence (not just badges).

Severity is LOW: README hygiene matters but never blocks work.
"""
from __future__ import annotations

import re
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)


_READ_LIMIT = 80  # lines — opening section only
_MAX_SAMPLES = 4


def build_readme_detectors() -> list[Detector]:
    return [
        Detector("R1", "README.md missing at repo root", "open",
                 detect_r1, LOW, frozenset()),
        Detector("R2", "README first H1 does not match repo name", "open",
                 detect_r2, LOW, frozenset()),
        Detector("R3", "README missing 'What this repo is' section", "open",
                 detect_r3, LOW, frozenset()),
        Detector("R4", "README missing 'What this repo is not' section", "open",
                 detect_r4, LOW, frozenset()),
        Detector("R5", "README intro paragraph empty or badge-only", "open",
                 detect_r5, LOW, frozenset()),
    ]


def _readme_path(context: AuditContext) -> Path:
    return context.repo_root / "README.md"


def _read_opening(context: AuditContext) -> list[str] | None:
    path = _readme_path(context)
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    return text.splitlines()[:_READ_LIMIT]


def _normalize(s: str) -> str:
    return re.sub(r"[\s_\-]+", "", s).lower()


def _h1(lines: list[str]) -> str | None:
    for ln in lines:
        if ln.startswith("# ") and not ln.startswith("## "):
            return ln[2:].strip()
    return None


def _h2_indices(lines: list[str]) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    for idx, ln in enumerate(lines):
        if ln.startswith("## "):
            out.append((idx, ln[3:].strip()))
    return out


_WHAT_IS_PATTERNS = (
    re.compile(r"^what\s+(this\s+repo|.+?)\s+is$", re.IGNORECASE),
    re.compile(r"^what\s+(this\s+repo|.+?)\s+includes$", re.IGNORECASE),
)
_WHAT_IS_NOT_PATTERNS = (
    re.compile(r"^what\s+(this\s+repo|.+?)\s+is\s+not$", re.IGNORECASE),
)


def _matches(patterns: tuple[re.Pattern[str], ...], heading: str) -> bool:
    return any(p.match(heading) for p in patterns)


# ── R1 ─────────────────────────────────────────────────────────────────

def detect_r1(context: AuditContext) -> DetectorResult:
    if _readme_path(context).exists():
        return DetectorResult(count=0, samples=[])
    return DetectorResult(count=1, samples=["README.md: file missing at repo root"])


# ── R2 ─────────────────────────────────────────────────────────────────

def detect_r2(context: AuditContext) -> DetectorResult:
    lines = _read_opening(context)
    if lines is None:
        return DetectorResult(count=0, samples=[])
    h1 = _h1(lines)
    if h1 is None:
        return DetectorResult(count=1, samples=["README.md: no H1 heading found"])

    repo_key = context.config.get("repo_key") or context.repo_root.name
    # Allow "RepoName — tagline" / "RepoName: tagline" / "RepoName - tagline" by
    # checking only the leading segment. The repo name must appear as the H1's
    # head (case-insensitive, ignoring whitespace/underscore/hyphen).
    head = re.split(r"\s*[—\-:|]\s+", h1, maxsplit=1)[0]
    if _normalize(head) == _normalize(repo_key):
        return DetectorResult(count=0, samples=[])
    if _normalize(h1) == _normalize(repo_key):
        return DetectorResult(count=0, samples=[])
    return DetectorResult(
        count=1,
        samples=[f"README.md: H1 {h1!r} does not match repo name {repo_key!r}"],
    )


# ── R3 ─────────────────────────────────────────────────────────────────

def detect_r3(context: AuditContext) -> DetectorResult:
    lines = _read_opening(context)
    if lines is None:
        return DetectorResult(count=0, samples=[])
    for _idx, heading in _h2_indices(lines):
        if _matches(_WHAT_IS_PATTERNS, heading):
            return DetectorResult(count=0, samples=[])
    return DetectorResult(
        count=1,
        samples=["README.md: missing '## What this repo is' (or '## What X is') section in opening"],
    )


# ── R4 ─────────────────────────────────────────────────────────────────

def detect_r4(context: AuditContext) -> DetectorResult:
    lines = _read_opening(context)
    if lines is None:
        return DetectorResult(count=0, samples=[])
    for _idx, heading in _h2_indices(lines):
        if _matches(_WHAT_IS_NOT_PATTERNS, heading):
            return DetectorResult(count=0, samples=[])
    return DetectorResult(
        count=1,
        samples=["README.md: missing '## What this repo is not' (or '## What X is not') section"],
    )


# ── R5 ─────────────────────────────────────────────────────────────────

_BADGE_RE = re.compile(r"^!\[.*?\]\(.*?\)\s*$")
_HTML_BADGE_RE = re.compile(r"^<img\s.*?/?>\s*$", re.IGNORECASE)


def detect_r5(context: AuditContext) -> DetectorResult:
    lines = _read_opening(context)
    if lines is None:
        return DetectorResult(count=0, samples=[])
    h1_idx: int | None = None
    for idx, ln in enumerate(lines):
        if ln.startswith("# ") and not ln.startswith("## "):
            h1_idx = idx
            break
    if h1_idx is None:
        return DetectorResult(count=0, samples=[])

    # Find first H2 after H1
    first_h2_idx = next(
        (idx for idx, _ in _h2_indices(lines) if idx > h1_idx),
        len(lines),
    )

    # Inspect intro lines between H1 and first H2
    intro = lines[h1_idx + 1:first_h2_idx]
    descriptive: list[str] = []
    for ln in intro:
        s = ln.strip()
        if not s:
            continue
        if _BADGE_RE.match(s) or _HTML_BADGE_RE.match(s):
            continue
        if s in {"---", "***", "___"}:
            continue
        descriptive.append(s)

    if not descriptive:
        return DetectorResult(
            count=1,
            samples=["README.md: intro paragraph between H1 and first H2 is empty or badge-only"],
        )
    # At least one line of real prose
    return DetectorResult(count=0, samples=[])
