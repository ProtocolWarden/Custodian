# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
r"""DC-class detectors — documentation conventions beyond README hygiene.

R-class enforces README structural shape (presence, H1, "What X is",
intro paragraph, docs/ index). K-class enforces doc-code consistency
(phantom symbols, value drift, param drift). DC-class fills the gap
between them — repo-wide markdown conventions for design specs,
ADRs, and cross-doc references.

Detectors
─────────
DC1  Design specs in ``docs/design/`` start with a YAML front-matter
     block that declares at least ``status:``. Silently skipped when
     ``docs/design/`` doesn't exist.
DC2  Cross-doc references of the form ``\`docs/X.md\``` resolve to a
     file that exists. Scans ``README.md`` plus everything under
     ``docs/`` (excluding ``docs/history/`` and ``docs/archive/`` by
     default since historical narration commonly cites long-renamed
     paths).
DC3  ADRs under ``docs/architecture/adr/`` follow ``NNNN-kebab-case.md``
     naming (zero-padded ordinal + lowercase kebab title). Silently
     skipped when the ADR directory doesn't exist. ``readme.md``,
     ``template.md``, and ``index.md`` are exempted.
DC4  README has the conventional implementer-onboarding sections —
     "Quick start" / "Getting started" / "Quickstart" AND
     "Architecture" / "Overview" / "How it works" — at H2 level.
DC5  Backtick-quoted symbol citations in implementation contexts
     (``**Files:**`` lists, ``Implementation:`` lines) use a
     module-qualified path so readers don't have to grep. A line that
     mentions any qualified symbol (containing ``.``, ``:``, or
     ``/`` inside backticks) satisfies the rule for that line.

All detectors are LOW severity — these are conventions, not bugs. Most
repos will start with non-zero counts on the noisier detectors (DC2,
DC5); fix or formally exempt offenders to drive the count down over
time.

Configuration
─────────────
Defaults work without config. To override::

    doc_conventions:
      design_dir: docs/design                # DC1
      adr_dir: docs/architecture/adr         # DC3
      doc_scan_dirs: [docs]                  # DC2 + DC5 scan roots
      exclude_path_patterns:                  # applied to DC2 + DC5
        - "*/archive/*"
        - "*/history/*"
      required_readme_headings:               # DC4 — list of regex strs
        - "^##\\\\s+(?:Quick\\\\s+start|Quickstart|Getting\\\\s+started)\\\\b"
        - "^##\\\\s+(?:Architecture|Overview|How\\\\s+it\\\\s+works)\\\\b"
"""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)


_MAX_SAMPLES = 8

_DEFAULT_DESIGN_DIR = "docs/design"
_DEFAULT_ADR_DIR = "docs/architecture/adr"
_DEFAULT_SCAN_DIRS: tuple[str, ...] = ("docs",)
_DEFAULT_EXCLUDE_PATTERNS: tuple[str, ...] = ("*/archive/*", "*/history/*")

_DEFAULT_README_HEADINGS: tuple[str, ...] = (
    r"^##\s+(?:Quick\s+start|Quickstart|Getting\s+started)\b",
    r"^##\s+(?:Architecture|Overview|How\s+it\s+works)\b",
)
_README_HEADING_LABELS: tuple[str, ...] = (
    "Quick start / Getting started",
    "Architecture / Overview",
)

_DOC_REF_RE = re.compile(r"`(docs/[a-z0-9_/\-]+\.md)`")
_ADR_NAME_RE = re.compile(r"^\d{4}-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
_IMPL_CONTEXT_RE = re.compile(r"\*\*Files:\*\*|\bImplementation:", re.IGNORECASE)
_BARE_SYMBOL_RE = re.compile(r"`([_a-z][a-zA-Z0-9_]{4,})\(?\)?`")


def build_doc_convention_detectors() -> list[Detector]:
    return [
        Detector("DC1",
                 "design specs missing YAML front matter / status",
                 "open", detect_dc1, LOW, frozenset()),
        Detector("DC2",
                 "cross-doc references that don't resolve",
                 "open", detect_dc2, LOW, frozenset()),
        Detector("DC3",
                 "ADRs not following NNNN-kebab-case.md",
                 "open", detect_dc3, LOW, frozenset()),
        Detector("DC4",
                 "README missing required sections",
                 "open", detect_dc4, LOW, frozenset()),
        Detector("DC5",
                 "bare symbol citations in implementation contexts",
                 "open", detect_dc5, LOW, frozenset()),
    ]


def _config(ctx: AuditContext) -> dict:
    return ctx.config.get("doc_conventions") or {}


def _is_excluded(rel: Path, patterns: list[str]) -> bool:
    rel_posix = rel.as_posix()
    return any(fnmatch.fnmatch(rel_posix, pat) for pat in patterns)


# ── DC1: design-spec front matter ────────────────────────────────────────────

def detect_dc1(ctx: AuditContext) -> DetectorResult:
    cfg = _config(ctx)
    design_dir = ctx.repo_root / cfg.get("design_dir", _DEFAULT_DESIGN_DIR)
    if not design_dir.exists():
        return DetectorResult(count=0, samples=[])
    samples: list[str] = []
    for md in sorted(design_dir.glob("*.md")):
        rel = md.relative_to(ctx.repo_root)
        try:
            text = md.read_text(errors="replace")
        except OSError:
            continue
        if not text.startswith("---"):
            samples.append(f"{rel}:1: missing YAML front matter (`---` block at top)")
            continue
        try:
            end = text.index("---", 3)
        except ValueError:
            samples.append(f"{rel}:1: front matter has no closing `---`")
            continue
        front = text[3:end]
        if not re.search(r"^\s*status\s*:", front, re.MULTILINE):
            samples.append(f"{rel}:1: front matter present but `status:` field missing")
    return DetectorResult(count=len(samples), samples=samples[:_MAX_SAMPLES])


# ── DC2: cross-doc references resolve ────────────────────────────────────────

def detect_dc2(ctx: AuditContext) -> DetectorResult:
    cfg = _config(ctx)
    scan_dirs = list(cfg.get("doc_scan_dirs") or _DEFAULT_SCAN_DIRS)
    excludes = list(cfg.get("exclude_path_patterns") or _DEFAULT_EXCLUDE_PATTERNS)

    files: list[Path] = []
    readme = ctx.repo_root / "README.md"
    if readme.exists():
        files.append(readme)
    for sub in scan_dirs:
        d = ctx.repo_root / sub
        if d.exists():
            files.extend(d.rglob("*.md"))

    samples: list[str] = []
    for f in files:
        try:
            rel = f.relative_to(ctx.repo_root)
        except ValueError:
            continue
        if _is_excluded(rel, excludes):
            continue
        try:
            for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                for m in _DOC_REF_RE.finditer(line):
                    target = ctx.repo_root / m.group(1)
                    if not target.exists():
                        samples.append(f"{rel}:{i}: dead reference `{m.group(1)}`")
                        if len(samples) >= _MAX_SAMPLES * 2:
                            return DetectorResult(
                                count=len(samples), samples=samples[:_MAX_SAMPLES],
                            )
        except OSError:
            continue
    return DetectorResult(count=len(samples), samples=samples[:_MAX_SAMPLES])


# ── DC3: ADR naming convention ───────────────────────────────────────────────

def detect_dc3(ctx: AuditContext) -> DetectorResult:
    cfg = _config(ctx)
    adr_dir = ctx.repo_root / cfg.get("adr_dir", _DEFAULT_ADR_DIR)
    if not adr_dir.exists():
        return DetectorResult(count=0, samples=[])
    samples: list[str] = []
    for md in sorted(adr_dir.glob("*.md")):
        if md.name.lower() in {"readme.md", "template.md", "index.md"}:
            continue
        if not _ADR_NAME_RE.match(md.name):
            samples.append(
                f"{md.relative_to(ctx.repo_root)}: doesn't match NNNN-kebab-case.md"
            )
    return DetectorResult(count=len(samples), samples=samples[:_MAX_SAMPLES])


# ── DC4: README required sections ────────────────────────────────────────────

def detect_dc4(ctx: AuditContext) -> DetectorResult:
    readme = ctx.repo_root / "README.md"
    if not readme.exists():
        # R1 already flags the missing-README case; DC4 stays silent
        # to avoid double-counting.
        return DetectorResult(count=0, samples=[])
    try:
        text = readme.read_text(errors="replace")
    except OSError:
        return DetectorResult(count=0, samples=[])
    cfg = _config(ctx)
    raw_patterns = list(cfg.get("required_readme_headings") or _DEFAULT_README_HEADINGS)
    # Pair each pattern with a label. When the operator overrides the
    # pattern list we lose the friendly default labels; fall back to
    # "section #N" for those.
    if raw_patterns is _DEFAULT_README_HEADINGS or list(raw_patterns) == list(
        _DEFAULT_README_HEADINGS,
    ):
        labels = list(_README_HEADING_LABELS)
    else:
        labels = [f"section #{i + 1}" for i in range(len(raw_patterns))]
    missing: list[str] = []
    for pat, label in zip(raw_patterns, labels, strict=False):
        try:
            rx = re.compile(pat, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue
        if not rx.search(text):
            missing.append(f"README.md: missing section ({label})")
    return DetectorResult(count=len(missing), samples=missing[:_MAX_SAMPLES])


# ── DC5: bare-symbol citations in implementation contexts ────────────────────

def detect_dc5(ctx: AuditContext) -> DetectorResult:
    """Symbols cited inside ``**Files:**`` or ``Implementation:`` lines without
    a module-qualified path. Bare ``foo_bar`` forces the reader to grep;
    ``module.foo_bar`` or ``module/path.py:foo_bar`` is the convention.
    """
    cfg = _config(ctx)
    scan_dirs = list(cfg.get("doc_scan_dirs") or _DEFAULT_SCAN_DIRS)
    excludes = list(cfg.get("exclude_path_patterns") or _DEFAULT_EXCLUDE_PATTERNS)

    # DC5 only inspects the design + architecture sub-trees of each
    # configured scan root by default — that's where Files: / Implementation:
    # callouts live. Operators can override scan_dirs to broaden it.
    files: list[Path] = []
    for sub in scan_dirs:
        for nested in ("design", "architecture"):
            d = ctx.repo_root / sub / nested
            if d.exists():
                files.extend(d.rglob("*.md"))
    samples: list[str] = []
    for f in files:
        try:
            rel = f.relative_to(ctx.repo_root)
        except ValueError:
            continue
        if _is_excluded(rel, excludes):
            continue
        try:
            for i, line in enumerate(f.read_text(errors="replace").splitlines(), 1):
                if not _IMPL_CONTEXT_RE.search(line):
                    continue
                if re.search(r"`[^`]*[./:][^`]*`", line):
                    continue
                if _BARE_SYMBOL_RE.search(line):
                    samples.append(f"{rel}:{i}: bare symbol citation in Files: line")
                    if len(samples) >= _MAX_SAMPLES * 2:
                        return DetectorResult(
                            count=len(samples), samples=samples[:_MAX_SAMPLES],
                        )
        except OSError:
            continue
    return DetectorResult(count=len(samples), samples=samples[:_MAX_SAMPLES])
