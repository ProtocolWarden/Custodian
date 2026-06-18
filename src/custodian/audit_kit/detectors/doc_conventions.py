# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
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

import re
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)
from custodian.audit_kit.glob_match import glob_match


_MAX_SAMPLES = 8

_DEFAULT_DESIGN_DIR = "docs/design"
_DEFAULT_ADR_DIR = "docs/architecture/adr"
_DEFAULT_SCAN_DIRS: tuple[str, ...] = ("docs",)
_DEFAULT_EXCLUDE_PATTERNS: tuple[str, ...] = ("**/archive/**", "**/history/**")

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

# DC10 — claims-INTEGRATED-while-deferring-the-integration. Narrowly the #313
# self-contradiction: a doc asserts the feature is wired end-to-end / fully
# integrated, yet the SAME doc still lists the integration (wiring the consumer)
# as deferred work. Deliberately NOT the broad "complete + next steps" pattern —
# "Stage 1 complete, Stage 2 next" is legitimate staged work, not a bug.
_DC10_INTEGRATED_RE = re.compile(
    r"(?:end[- ]to[- ]end\s+(?:integration|integrated|wired|complete)"
    r"|fully\s+(?:integrated|wired|end[- ]to[- ]end)"
    r"|integration\s+complete|wired\s+end[- ]to[- ]end)",
    re.IGNORECASE,
)
_DC10_DEFERS_INTEGRATION_RE = re.compile(
    r"(?:integration\s+(?:deferred|is\s+deferred|to\s+follow|pending|tracked\s+separately)"
    r"|defer(?:red)?\s+(?:the\s+)?integration"
    r"|not\s+yet\s+(?:wired|integrated|called)"
    r"|wir(?:e|ing)\s+(?:up\s+)?(?:them|it|this|the\s+\w+)\b"
    r"|update\s+\S+[^\n]*\bto\s+call\s+\w+"
    r"|stage\s+\d+[^\n]*\b(?:wire|integrat))",
    re.IGNORECASE,
)
_DC10_DEFAULT_GLOBS: tuple[str, ...] = (".console/*.md", "docs/**/*.md")


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
        Detector("DC6",
                 "docs/ subdirectory not in the configured taxonomy",
                 "open", detect_dc6, LOW, frozenset()),
        Detector("DC7",
                 "orphan markdown file under docs/ (not linked from any tracked doc)",
                 "open", detect_dc7, LOW, frozenset()),
        Detector("DC8",
                 "README sections out of conventional order",
                 "open", detect_dc8, LOW, frozenset()),
        Detector("DC9",
                 "doc in an index-required dir not cited from docs/README.md",
                 "open", detect_dc9, LOW, frozenset()),
        # DC10 ships OPT-IN (deprecated=True → skipped by default; enable with
        # --include-deprecated). NOT tool-deprecated — the flag is reused as the
        # "off by default" lever so a new heuristic detector doesn't red-wall
        # consumers that audit against Custodian@main. Catches the planner-level
        # #313 failure: a doc claiming a feature COMPLETE while the same doc still
        # lists it as deferred / Next-Steps / Stage-N work.
        Detector("DC10",
                 "doc claims COMPLETE while it also lists the same work as deferred/Next-Steps",
                 "open", detect_dc10, LOW, frozenset(), deprecated=True),
    ]


def _config(ctx: AuditContext) -> dict:
    return ctx.config.get("doc_conventions") or {}


def _is_excluded(rel: Path, patterns: list[str]) -> bool:
    rel_posix = rel.as_posix()
    return any(glob_match(rel_posix, pat) for pat in patterns)


# ── DC1: design-spec + per-dir front matter ────────────────────────────────

def _check_front_matter(
    md: Path, required_fields: list[str], rel: Path,
) -> list[str]:
    """Return one message per failing condition for a single file.

    A file with no ``---`` front matter is reported once with an explicit
    "missing block" message (rather than one message per missing field) —
    the operator's first action is to add the block, not to enumerate the
    fields it should carry.
    """
    try:
        text = md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if not text.startswith("---"):
        return [f"{rel}:1: missing YAML front matter (`---` block at top)"]
    try:
        end = text.index("---", 3)
    except ValueError:
        return [f"{rel}:1: front matter has no closing `---`"]
    front = text[3:end]
    missing: list[str] = []
    for field in required_fields:
        # Match `field:` at the start of any line, allowing leading
        # whitespace (operators sometimes indent for readability).
        rx = re.compile(rf"^\s*{re.escape(field)}\s*:", re.MULTILINE)
        if not rx.search(front):
            missing.append(f"{rel}:1: front matter missing `{field}:` field")
    return missing


def detect_dc1(ctx: AuditContext) -> DetectorResult:
    """Two checks on YAML front matter, both fold into DC1's count.

    1. Default check — files in ``design_dir`` (default ``docs/design``)
       must declare ``status:``. Skipped silently when the dir is absent.
    2. Per-dir schemas — when ``doc_conventions.front_matter_schemas``
       is configured, every tracked .md matching one of its glob patterns
       must declare every listed field.

    Example::

        doc_conventions:
          front_matter_schemas:
            docs/architecture/adr/*.md: [date, status, deciders]
            docs/operator/runbook-*.md: [status, owner, last_reviewed]
    """
    cfg = _config(ctx)
    samples: list[str] = []

    # ── (1) default design_dir status check ──
    design_dir = ctx.repo_root / cfg.get("design_dir", _DEFAULT_DESIGN_DIR)
    if design_dir.exists():
        for md in sorted(design_dir.glob("*.md")):
            rel = md.relative_to(ctx.repo_root)
            samples.extend(_check_front_matter(md, ["status"], rel))

    # ── (2) per-dir schemas from config ──
    schemas = cfg.get("front_matter_schemas") or {}
    for pattern, required in schemas.items():
        if not isinstance(required, list) or not required:
            continue
        for md in sorted(ctx.repo_root.glob(pattern)):
            if not md.is_file() or md.suffix.lower() != ".md":
                continue
            try:
                rel = md.relative_to(ctx.repo_root)
            except ValueError:
                continue
            # ADR template / index files are exempt from schema checks
            # the way DC3 already exempts them from the naming check.
            if md.name.lower() in {"readme.md", "template.md", "index.md"}:
                continue
            samples.extend(_check_front_matter(md, [str(x) for x in required], rel))

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
            for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
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
        text = readme.read_text(encoding="utf-8", errors="replace")
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
            for i, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
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


# ── DC6: docs/ subdirectory taxonomy ─────────────────────────────────────────

def detect_dc6(ctx: AuditContext) -> DetectorResult:
    """Flag docs/ subdirectories not in the configured allowlist.

    Opt-in: silently passes when ``allowed_doc_subdirs`` isn't configured.
    Operators set the list in ``.custodian/config.yaml``::

        doc_conventions:
          allowed_doc_subdirs:
            - architecture
            - operator
            - usage
            - design
            - history
            - adr

    Only the *direct* subdirs of ``docs/`` are checked; nested
    structure inside an allowed subdir is the operator's call.
    """
    cfg = _config(ctx)
    allowed = cfg.get("allowed_doc_subdirs")
    if not allowed:
        return DetectorResult(count=0, samples=[])
    docs_root = ctx.repo_root / "docs"
    if not docs_root.exists():
        return DetectorResult(count=0, samples=[])
    allowed_set = {name.strip("/").lower() for name in allowed}
    samples: list[str] = []
    for entry in sorted(docs_root.iterdir()):
        if not entry.is_dir():
            continue
        if entry.name.lower() not in allowed_set:
            samples.append(
                f"docs/{entry.name}/: not in allowed taxonomy "
                f"({sorted(allowed_set)})"
            )
    return DetectorResult(count=len(samples), samples=samples[:_MAX_SAMPLES])


# ── DC7: orphan markdown files under docs/ ───────────────────────────────────

_MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)\s]+\.md)(?:#[^)]*)?\)")
_BACKTICK_PATH_RE = re.compile(r"`(docs/[a-z0-9_/\-]+\.md)`")


def detect_dc7(ctx: AuditContext) -> DetectorResult:
    r"""Flag .md files under docs/ that no tracked .md links to.

    A doc is "linked" when any other tracked .md file (under docs/, the
    repo root README, or anywhere else in the working tree) cites it
    via a markdown link ``[label](path/to.md)`` or a backticked path
    ``\`docs/path.md\```. ``docs/README.md`` itself is exempt since
    it's the canonical index and gets cited by linkage *to* it.

    Honors the same exclude patterns as DC2/DC5 so historical /
    archived narration doesn't produce false orphans.
    """
    cfg = _config(ctx)
    excludes = list(cfg.get("exclude_path_patterns") or _DEFAULT_EXCLUDE_PATTERNS)
    docs_root = ctx.repo_root / "docs"
    if not docs_root.exists():
        return DetectorResult(count=0, samples=[])

    # All candidate orphans — every .md under docs/ except history/archive.
    candidates: list[Path] = []
    for md in docs_root.rglob("*.md"):
        try:
            rel = md.relative_to(ctx.repo_root)
        except ValueError:
            continue
        if rel.name.lower() == "readme.md":
            # docs/**/README.md acts as a section index; not an orphan
            # candidate even if nothing links to it directly.
            continue
        if _is_excluded(rel, excludes):
            continue
        candidates.append(md)

    if not candidates:
        return DetectorResult(count=0, samples=[])

    # Build the set of paths cited by any tracked .md file. The corpus
    # is README.md + every .md under docs/ — that's the surface where
    # cross-doc links live in our convention.
    corpus: list[Path] = []
    readme = ctx.repo_root / "README.md"
    if readme.exists():
        corpus.append(readme)
    corpus.extend(docs_root.rglob("*.md"))

    referenced: set[str] = set()
    for f in corpus:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            f_rel = f.relative_to(ctx.repo_root)
        except ValueError:
            continue
        # Markdown links — paths may be relative to the citing file.
        for m in _MD_LINK_RE.finditer(text):
            target_str = m.group(1)
            target = (f.parent / target_str).resolve()
            try:
                referenced.add(target.relative_to(ctx.repo_root.resolve()).as_posix())
            except ValueError:
                continue
        # Backticked docs/... paths — repo-root-relative by convention.
        for m in _BACKTICK_PATH_RE.finditer(text):
            referenced.add(m.group(1))
        # A doc that cites itself (via TOC anchors etc.) doesn't count
        # toward its own non-orphan status, but other docs in the same
        # directory's index do — handled implicitly by walking corpus.
        del f_rel

    samples: list[str] = []
    for md in sorted(candidates):
        rel = md.relative_to(ctx.repo_root).as_posix()
        if rel not in referenced:
            samples.append(f"{rel}: orphan — not linked from any tracked doc")
    return DetectorResult(count=len(samples), samples=samples[:_MAX_SAMPLES])


# ── DC8: README section ordering ─────────────────────────────────────────────

# Default expected order. Each entry is a (label, regex) pair — labels
# are surfaced in samples, regexes match the H2 line. Sections that
# don't match any entry are ignored (operators may have any number of
# repo-specific sections in the middle).
_DEFAULT_SECTION_ORDER: tuple[tuple[str, str], ...] = (
    ("What X is",        r"^##\s+What\s+.+?\bis\b(?!\s+not\b)"),
    ("What X is not",    r"^##\s+What\s+.+?\bis\s+not\b"),
    ("Quick start",      r"^##\s+(?:Quick\s+start|Quickstart|Getting\s+started)\b"),
    ("Architecture",     r"^##\s+(?:Architecture|Overview|How\s+it\s+works)\b"),
    ("License",          r"^##\s+License\b"),
)


def detect_dc8(ctx: AuditContext) -> DetectorResult:
    """Flag README sections that appear out of the conventional order.

    The convention reads top-to-bottom: ``What X is`` → ``What X is
    not`` → ``Quick start`` → ``Architecture`` → (anything else) →
    ``License``. Sections that don't match any entry in the order are
    ignored — operators may have any number of repo-specific H2s
    sandwiched between the framework sections.

    Override the order via config::

        doc_conventions:
          required_section_order:
            - ["What X is",     "^##\\s+What\\s+.+?\\bis\\b(?!\\s+not\\b)"]
            - ["Public API",    "^##\\s+Public\\s+API\\b"]
            - ["License",       "^##\\s+License\\b"]

    Each entry is ``[label, regex]``. Labels appear in samples; regexes
    are matched (case-insensitive, multiline) against the README text.
    """
    readme = ctx.repo_root / "README.md"
    if not readme.exists():
        return DetectorResult(count=0, samples=[])
    try:
        text = readme.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return DetectorResult(count=0, samples=[])

    cfg = _config(ctx)
    raw_order = cfg.get("required_section_order")
    if raw_order:
        order: list[tuple[str, str]] = []
        for entry in raw_order:
            if isinstance(entry, list) and len(entry) >= 2:
                order.append((str(entry[0]), str(entry[1])))
            elif isinstance(entry, dict):
                lbl = entry.get("label")
                rx = entry.get("regex")
                if isinstance(lbl, str) and isinstance(rx, str):
                    order.append((lbl, rx))
    else:
        order = list(_DEFAULT_SECTION_ORDER)

    # Find the line number where each ordered section first appears.
    # Sections not present are skipped — DC4 covers required-section
    # presence, DC8 only enforces ordering between the ones that exist.
    positions: list[tuple[str, int]] = []
    for label, pattern in order:
        try:
            rx = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        except re.error:
            continue
        m = rx.search(text)
        if m is None:
            continue
        # Convert character offset to line number.
        lineno = text[:m.start()].count("\n") + 1
        positions.append((label, lineno))

    samples: list[str] = []
    # Detect order violations: any later-in-config section that appears
    # at an earlier line than a section configured to come before it.
    for i in range(1, len(positions)):
        for j in range(i):
            label_i, line_i = positions[i]
            label_j, line_j = positions[j]
            if line_i < line_j:
                samples.append(
                    f"README.md:{line_i}: '{label_i}' should come after "
                    f"'{label_j}' (line {line_j})"
                )
                break  # one finding per out-of-order section is enough
    return DetectorResult(count=len(samples), samples=samples[:_MAX_SAMPLES])


# ── DC9: docs missing from the docs/README.md index ──────────────────────────

def detect_dc9(ctx: AuditContext) -> DetectorResult:
    r"""Flag docs in index-required dirs that ``docs/README.md`` doesn't cite.

    DC7 catches *orphans* (linked from nowhere) — but a doc cited only by a
    sibling doc still sails past it while staying invisible from the canonical
    index. For each dir in ``doc_conventions.dc9_index_dirs`` (repo-root
    relative), every non-README ``.md`` under it must be cited from
    ``docs/README.md`` via a markdown link or backticked ``docs/...`` path.

    Opt-in (DC6 precedent): silent when ``dc9_index_dirs`` is unset. Silent
    when ``docs/README.md`` doesn't exist (no index convention to enforce).
    Honors the DC2/DC5/DC7 exclude patterns.
    """
    cfg = _config(ctx)
    index_dirs = list(cfg.get("dc9_index_dirs") or [])
    if not index_dirs:
        return DetectorResult(count=0, samples=[])
    index_md = ctx.repo_root / "docs" / "README.md"
    if not index_md.is_file():
        return DetectorResult(count=0, samples=[])
    excludes = list(cfg.get("exclude_path_patterns") or _DEFAULT_EXCLUDE_PATTERNS)

    # Paths the index cites: markdown links resolved relative to docs/, plus
    # backticked repo-root-relative docs/... paths.
    text = index_md.read_text(encoding="utf-8", errors="replace")
    referenced: set[str] = set()
    for m in _MD_LINK_RE.finditer(text):
        target = (index_md.parent / m.group(1)).resolve()
        try:
            referenced.add(target.relative_to(ctx.repo_root.resolve()).as_posix())
        except ValueError:
            continue
    for m in _BACKTICK_PATH_RE.finditer(text):
        referenced.add(m.group(1))

    samples: list[str] = []
    count = 0
    for index_dir in index_dirs:
        root = ctx.repo_root / index_dir
        if not root.is_dir():
            continue
        for md in sorted(root.rglob("*.md")):
            rel = md.relative_to(ctx.repo_root)
            if rel.name.lower() == "readme.md":
                continue
            if _is_excluded(rel, excludes):
                continue
            if rel.as_posix() not in referenced:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"{rel.as_posix()}: not cited from docs/README.md "
                        f"(index-required dir {index_dir})"
                    )
    return DetectorResult(count=count, samples=samples)


# ── DC10: claims-complete-while-deferring ────────────────────────────────────

def detect_dc10(ctx: AuditContext) -> DetectorResult:
    """Flag a doc that claims a feature COMPLETE while the same doc still lists
    the work as deferred / Next-Steps / Stage-N.

    The planner-level failure behind OperationsCenter#313: the backlog asserted
    "✅ IMPLEMENTATION COMPLETE & VERIFIED / end-to-end" while a "Next Steps —
    Stage 5 (Ready to Start)" section listed the integration as still to do. A
    truly-complete feature has no Ready-to-Start / deferred work for itself.

    Low-FP by construction: the completion claim must be STRONG (``complete &
    verified`` / ``production-ready`` / ``end-to-end integration`` / ``✅ …
    complete``), not a bare "done"; and a deferred/Next-Steps marker must also be
    present in the same file. Scans ``audit.dc10_scan_globs`` (default the
    .console truth files + docs/), honours ``audit.exclude_paths.DC10`` and an
    ``audit.dc10_baseline`` ratchet of accepted relative paths.
    """
    audit_cfg = ctx.config.get("audit") or {}
    globs = list(audit_cfg.get("dc10_scan_globs") or _DC10_DEFAULT_GLOBS)
    excludes = list((audit_cfg.get("exclude_paths") or {}).get("DC10") or [])
    baseline = set(audit_cfg.get("dc10_baseline") or [])

    seen: set[Path] = set()
    samples: list[str] = []
    count = 0
    for g in globs:
        for f in sorted(ctx.repo_root.glob(g)):
            if not f.is_file() or f in seen:
                continue
            seen.add(f)
            try:
                rel = f.relative_to(ctx.repo_root)
            except ValueError:
                continue
            rel_posix = rel.as_posix()
            if rel_posix in baseline:
                continue
            if excludes and any(glob_match(rel_posix, p) for p in excludes):
                continue
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            cm = _DC10_INTEGRATED_RE.search(text)
            dm = _DC10_DEFERS_INTEGRATION_RE.search(text)
            if cm and dm:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    line = text[: cm.start()].count("\n") + 1
                    samples.append(
                        f"{rel_posix}:{line}: claims integrated "
                        f"({cm.group(0).strip()[:30]!r}) but defers the integration "
                        f"({dm.group(0).strip()[:40]!r})"
                    )
    return DetectorResult(count=count, samples=samples)
