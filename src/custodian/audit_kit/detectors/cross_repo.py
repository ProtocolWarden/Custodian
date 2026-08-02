# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""X-class detectors — cross-repo flow audits.

These detectors validate the local repo against PlatformManifest data
loaded from a sibling repo or installed package. They turn what was
previously informal cross-repo coupling into machine-checked invariants.

Detectors
─────────
X1  Public-label reference in tracked source — a tracked .py / .md / .yaml
    file references a PlatformManifest disclosure-safe label instead of
    the canonical repo name (e.g. ``OperationsCenterPublic`` when the
    canonical name is ``OperationsCenter``). The label should be looked
    up via the manifest rather than hard-coded.

X2  Undeclared cross-repo import — a .py file imports a package that maps
    to a platform repo but no edge is declared from this repo to that
    target in the manifest's ``edges`` block. Requires ``repo_key`` to be
    set in the repo's ``.custodian/config.yaml``.

X3  Stale GitHub URL in docs — a .md file contains a GitHub URL pointing
    to a platform repo via a stale public label
    (e.g. ``github.com/ProtocolWarden/OperationsCenterPublic``).  Complements X1's
    string-name drift check with URL-level drift detection.

Configuration
─────────────
Cross-repo detectors silently skip when no PlatformManifest data is
available. Configure a path or a sibling-repo location under the
``audit.cross_repo`` block::

    audit:
      cross_repo:
        # One of:
        platform_manifest_path: ../PlatformManifest/src/platform_manifest/data/platform_manifest.yaml
        platform_manifest_repo: ../PlatformManifest

The detector loads the YAML directly without depending on the
PlatformManifest package — keeping Custodian dependency-free.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from custodian.audit_kit.detector import (
    LOW,
    AuditContext,
    Detector,
    DetectorResult,
)
from custodian.audit_kit.glob_match import glob_match

_MAX_SAMPLES = 8

_DEFAULT_MANIFEST_SUBPATHS: tuple[str, ...] = (
    "src/platform_manifest/data/platform_manifest.yaml",
    "data/platform_manifest.yaml",
    "platform_manifest.yaml",
)

_IMPORT_RE = re.compile(r'^\s*(?:import|from)\s+([A-Za-z_][A-Za-z0-9_]*)', re.MULTILINE)


@dataclass
class _ManifestInfo:
    label_to_canonical: dict[str, str]            # X1: {public_label: canonical_name}
    entry_key_to_canonical: dict[str, str]        # X2: {entry_key: canonical_name}
    edges: frozenset[tuple[str, str]]             # X2: {(from_canonical, to_canonical)}
    stale_url_to_canonical: dict[str, str]        # X3: {stale_url: canonical_url}
    path: Path


def build_cross_repo_detectors() -> list[Detector]:
    return [
        Detector("X1",
                 "tracked file references a PlatformManifest public label "
                 "instead of the canonical repo name",
                 "open", detect_x1, LOW, frozenset()),
        Detector("X2",
                 "Python file imports a cross-repo package not declared as "
                 "an edge in PlatformManifest",
                 "open", detect_x2, LOW, frozenset()),
        Detector("X3",
                 "doc file contains a GitHub URL using a legacy repo name "
                 "instead of the PlatformManifest canonical",
                 "open", detect_x3, LOW, frozenset()),
    ]


# ---------------------------------------------------------------------------
# Manifest loading
# ---------------------------------------------------------------------------

def _find_manifest_path(repo_root: Path, audit_cfg: dict) -> Path | None:
    cfg = (audit_cfg.get("cross_repo") or {})
    explicit = cfg.get("platform_manifest_path")
    sibling = cfg.get("platform_manifest_repo")

    candidates: list[Path] = []
    if explicit:
        candidates.append(repo_root / explicit)
    if sibling:
        sib_root = repo_root / sibling
        candidates.extend(sib_root / sub for sub in _DEFAULT_MANIFEST_SUBPATHS)

    for p in candidates:
        if p.is_file():
            return p
    return None


def _load_manifest_info(
    repo_root: Path, audit_cfg: dict,
) -> _ManifestInfo | None:
    """Parse the manifest into all derived maps used by X1/X2/X3.

    Returns ``None`` when no manifest is found or PyYAML is unavailable.
    """
    manifest_path = _find_manifest_path(repo_root, audit_cfg)
    if manifest_path is None:
        return None

    try:
        import yaml
    except ImportError:  # pragma: no cover
        return None

    try:
        text = manifest_path.read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
    except (OSError, UnicodeDecodeError):
        return None

    repos = (data.get("repos") or {}) if isinstance(data, dict) else {}

    label_to_canonical: dict[str, str] = {}
    entry_key_to_canonical: dict[str, str] = {}
    canonical_to_github_url: dict[str, str] = {}

    if isinstance(repos, dict):
        for entry_key, entry in repos.items():
            if not isinstance(entry, dict):
                continue
            canonical = entry.get("canonical_name")
            if not isinstance(canonical, str) or not canonical:
                continue
            entry_key_to_canonical[entry_key] = canonical

            github_url = entry.get("github_url")
            if isinstance(github_url, str) and github_url:
                canonical_to_github_url[canonical] = github_url

            public_label = entry.get("public_label")
            if isinstance(public_label, str) and public_label and public_label != canonical:
                label_to_canonical[public_label] = canonical

    # Build edges set: {(from_canonical, to_canonical)}
    raw_edges = (data.get("edges") or []) if isinstance(data, dict) else []
    edges: set[tuple[str, str]] = set()
    if isinstance(raw_edges, list):
        for edge in raw_edges:
            if not isinstance(edge, dict):
                continue
            frm = edge.get("from")
            to = edge.get("to")
            if isinstance(frm, str) and isinstance(to, str) and frm and to:
                edges.add((frm, to))

    # Build stale URL map: {stale_url: canonical_url}
    stale_url_to_canonical: dict[str, str] = {}
    for legacy, canonical in label_to_canonical.items():
        canonical_url = canonical_to_github_url.get(canonical)
        if not canonical_url:
            continue
        stale_url = canonical_url.replace(canonical, legacy)
        if stale_url != canonical_url:
            stale_url_to_canonical[stale_url] = canonical_url

    return _ManifestInfo(
        label_to_canonical=label_to_canonical,
        entry_key_to_canonical=entry_key_to_canonical,
        edges=frozenset(edges),
        stale_url_to_canonical=stale_url_to_canonical,
        path=manifest_path,
    )


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

_SKIP_PARTS = frozenset({
    ".venv", "__pycache__", "node_modules", "build", "dist", ".git",
    "history", "archive", ".console",
})


def _extra_skip_roots(repo_root: Path, audit_cfg: dict) -> frozenset[Path]:
    """Resolved sibling paths that happen to fall inside repo_root (test layout).

    In production the PlatformManifest repo is at ``../PlatformManifest``
    (outside repo_root) so rglob never reaches it. In tests it is placed
    under tmp_path == repo_root; resolve it and exclude it from scanning.
    """
    cfg = (audit_cfg.get("cross_repo") or {})
    roots: set[Path] = set()
    for key in ("platform_manifest_repo", "platform_manifest_path"):
        raw = cfg.get(key)
        if not raw:
            continue
        resolved = (repo_root / raw).resolve()
        # Only skip when the sibling is genuinely inside repo_root
        try:
            resolved.relative_to(repo_root.resolve())
            roots.add(resolved)
        except ValueError:
            pass
    return frozenset(roots)


def _is_under_skip(path: Path, skip_roots: frozenset[Path]) -> bool:
    rp = path.resolve()
    return any(rp == sr or sr in rp.parents for sr in skip_roots)


def _scan_paths(
    repo_root: Path,
    src_root: Path,
    skip_roots: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Files X1 inspects: .py under src + repo .md/.yaml/.yml docs.

    Skips .venv, __pycache__, vendor/, build artefacts, any path
    containing 'history' or 'archive', and any configured manifest
    sibling that happens to live inside repo_root (test layout).
    """
    out: list[Path] = []
    if src_root.is_dir():
        out.extend(src_root.rglob("*.py"))
    out.extend(repo_root.rglob("*.md"))
    out.extend(repo_root.rglob("*.yaml"))
    out.extend(repo_root.rglob("*.yml"))

    def _ok(p: Path) -> bool:
        if not p.is_file():
            return False
        if set(p.parts) & _SKIP_PARTS:
            return False
        return not (skip_roots and _is_under_skip(p, skip_roots))

    return [p for p in out if _ok(p)]


def _python_src_paths(
    repo_root: Path,
    src_root: Path,
    skip_roots: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Only .py files under src_root, skipping noise directories."""
    out: list[Path] = []
    if src_root.is_dir():
        out.extend(src_root.rglob("*.py"))

    def _ok(p: Path) -> bool:
        if not p.is_file():
            return False
        if set(p.parts) & _SKIP_PARTS:
            return False
        return not (skip_roots and _is_under_skip(p, skip_roots))

    return [p for p in out if _ok(p)]


def _markdown_paths(
    repo_root: Path,
    skip_roots: frozenset[Path] = frozenset(),
) -> list[Path]:
    """Only .md files under repo_root, skipping noise directories."""
    out = list(repo_root.rglob("*.md"))

    def _ok(p: Path) -> bool:
        if not p.is_file():
            return False
        if set(p.parts) & _SKIP_PARTS:
            return False
        return not (skip_roots and _is_under_skip(p, skip_roots))

    return [p for p in out if _ok(p)]


# ---------------------------------------------------------------------------
# X1 — public label references
# ---------------------------------------------------------------------------

def detect_x1(context: AuditContext) -> DetectorResult:
    """Flag tracked files referencing a PlatformManifest public label.

    When a repo has been renamed in PlatformManifest, callers should
    resolve the canonical name through the manifest rather than
    hard-coding the label. X1 catches stale references.

    Configurable exclude paths via ``audit.exclude_paths.X1``.
    """
    audit_cfg = context.config.get("audit") or {}
    info = _load_manifest_info(context.repo_root, audit_cfg)
    if not info or not info.label_to_canonical:
        return DetectorResult(count=0, samples=[])

    excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("X1") or [])
    skip_roots = _extra_skip_roots(context.repo_root, audit_cfg)

    pattern = r"\b(?:" + "|".join(re.escape(n) for n in info.label_to_canonical) + r")\b"
    matcher = re.compile(pattern)

    samples: list[str] = []
    count = 0
    seen: set[tuple[str, int, str]] = set()

    for path in _scan_paths(context.repo_root, context.src_root, skip_roots):
        rel = path.relative_to(context.repo_root)
        rel_posix = rel.as_posix()
        if excludes and any(glob_match(rel_posix, g) for g in excludes):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for match in matcher.finditer(line):
                label = match.group(0)
                key = (rel_posix, i, label)
                if key in seen:
                    continue
                seen.add(key)
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    canonical = info.label_to_canonical[label]
                    samples.append(
                        f"{rel}:{i}: public label `{label}` — "
                        f"PlatformManifest canonical is `{canonical}`"
                    )
    return DetectorResult(count=count, samples=samples)


# ---------------------------------------------------------------------------
# X2 — undeclared cross-repo imports
# ---------------------------------------------------------------------------

def detect_x2(context: AuditContext) -> DetectorResult:
    """Flag Python imports that cross a repo boundary without a manifest edge.

    Uses the manifest's ``edges`` block as enforced architectural law.
    If a .py file imports a package that maps to a platform repo but no
    edge is declared from this repo to that target, the dependency is
    undeclared.

    Requires ``repo_key`` in the repo's config to identify the current
    repo's canonical name in the manifest.

    Silently skips when no manifest is configured, PyYAML is missing, or
    ``repo_key`` is absent from the config.

    Configurable exclude paths via ``audit.exclude_paths.X2``.
    """
    current_repo = context.config.get("repo_key")
    if not current_repo:
        return DetectorResult(count=0, samples=[])

    audit_cfg = context.config.get("audit") or {}
    info = _load_manifest_info(context.repo_root, audit_cfg)
    if not info or not info.entry_key_to_canonical:
        return DetectorResult(count=0, samples=[])

    # Canonical names this repo is allowed to import from (declared edges)
    declared_targets: set[str] = {
        to for (frm, to) in info.edges if frm == current_repo
    }

    # entry_key → canonical for repos we can check imports against
    # exclude the current repo itself (self-imports are always fine)
    current_entry_key = next(
        (k for k, v in info.entry_key_to_canonical.items() if v == current_repo),
        None,
    )
    importable: dict[str, str] = {
        k: v for k, v in info.entry_key_to_canonical.items()
        if k != current_entry_key
    }
    if not importable:
        return DetectorResult(count=0, samples=[])

    excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("X2") or [])
    skip_roots = _extra_skip_roots(context.repo_root, audit_cfg)

    samples: list[str] = []
    count = 0
    seen: set[tuple[str, str]] = set()

    for path in _python_src_paths(context.repo_root, context.src_root, skip_roots):
        rel = path.relative_to(context.repo_root)
        rel_posix = rel.as_posix()
        if excludes and any(glob_match(rel_posix, g) for g in excludes):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _IMPORT_RE.finditer(text):
            pkg = match.group(1)
            target_canonical = importable.get(pkg)
            if not target_canonical:
                continue
            if target_canonical in declared_targets:
                continue
            key = (rel_posix, target_canonical)
            if key in seen:
                continue
            seen.add(key)
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(
                    f"{rel}: imports `{pkg}` ({target_canonical}) "
                    f"but no edge declared from `{current_repo}` → "
                    f"`{target_canonical}` in PlatformManifest"
                )
    return DetectorResult(count=count, samples=samples)


# ---------------------------------------------------------------------------
# X3 — stale GitHub URLs in docs
# ---------------------------------------------------------------------------

def detect_x3(context: AuditContext) -> DetectorResult:
    """Flag markdown docs containing GitHub URLs that use legacy repo names.

    Complements X1 (string-name drift) with URL-level drift detection.
    Scans .md files for URLs like ``github.com/ProtocolWarden/ControlPlane``
    when PlatformManifest says the canonical URL is
    ``github.com/ProtocolWarden/OperationsCenter``.

    Configurable exclude paths via ``audit.exclude_paths.X3``.
    """
    audit_cfg = context.config.get("audit") or {}
    info = _load_manifest_info(context.repo_root, audit_cfg)
    if not info or not info.stale_url_to_canonical:
        return DetectorResult(count=0, samples=[])

    excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("X3") or [])
    skip_roots = _extra_skip_roots(context.repo_root, audit_cfg)

    # Build a regex matching any stale URL (without https:// prefix, for flexibility)
    stale_patterns = {
        url.removeprefix("https://").removeprefix("http://"): canonical
        for url, canonical in info.stale_url_to_canonical.items()
    }
    pattern = "|".join(re.escape(p) for p in stale_patterns)
    if not pattern:
        return DetectorResult(count=0, samples=[])
    matcher = re.compile(pattern)

    samples: list[str] = []
    count = 0
    seen: set[tuple[str, int, str]] = set()

    for path in _markdown_paths(context.repo_root, skip_roots):
        rel = path.relative_to(context.repo_root)
        rel_posix = rel.as_posix()
        if excludes and any(glob_match(rel_posix, g) for g in excludes):
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for match in matcher.finditer(line):
                stale_fragment = match.group(0)
                key = (rel_posix, i, stale_fragment)
                if key in seen:
                    continue
                seen.add(key)
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    canonical_url = stale_patterns[stale_fragment]
                    samples.append(
                        f"{rel}:{i}: stale GitHub URL `{stale_fragment}` — "
                        f"PlatformManifest canonical is `{canonical_url}`"
                    )
    return DetectorResult(count=count, samples=samples)
