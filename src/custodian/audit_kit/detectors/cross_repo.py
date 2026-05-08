# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""X-class detectors — cross-repo flow audits.

These detectors validate the local repo against PlatformManifest data
loaded from a sibling repo or installed package. They turn what was
previously informal cross-repo coupling into machine-checked invariants.

Detectors
─────────
X1  Legacy-name reference in tracked source — a tracked .py / .md file
    references a name that PlatformManifest declares as a *legacy* alias
    of a different repo (e.g. ``ControlPlane`` when the canonical name
    is now ``OperationsCenter``). The legacy name should be looked up
    via the manifest's resolver rather than hard-coded.

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
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)
from custodian.audit_kit.glob_match import glob_match


_MAX_SAMPLES = 8

_DEFAULT_MANIFEST_SUBPATHS: tuple[str, ...] = (
    "src/platform_manifest/data/platform_manifest.yaml",
    "data/platform_manifest.yaml",
    "platform_manifest.yaml",
)


def build_cross_repo_detectors() -> list[Detector]:
    return [
        Detector("X1",
                 "tracked file references a PlatformManifest legacy alias "
                 "instead of the canonical repo name",
                 "open", detect_x1, LOW, frozenset()),
    ]


def _load_platform_manifest(
    repo_root: Path, audit_cfg: dict,
) -> tuple[dict[str, str], Path | None]:
    """Return ``({legacy_name: canonical_name}, manifest_path)``.

    Returns ``({}, None)`` when no PlatformManifest is found or PyYAML
    isn't available — silent skip.
    """
    cfg = (audit_cfg.get("cross_repo") or {})
    explicit = cfg.get("platform_manifest_path")
    sibling = cfg.get("platform_manifest_repo")

    candidates: list[Path] = []
    if explicit:
        candidates.append(repo_root / explicit)
    if sibling:
        sib_root = repo_root / sibling
        candidates.extend(sib_root / sub for sub in _DEFAULT_MANIFEST_SUBPATHS)

    manifest_path: Path | None = None
    for p in candidates:
        if p.is_file():
            manifest_path = p
            break

    if manifest_path is None:
        return {}, None

    try:
        import yaml  # local import — no hard dep
    except ImportError:  # pragma: no cover
        return {}, None

    try:
        text = manifest_path.read_text(encoding="utf-8")
        data = yaml.safe_load(text) or {}
    except (OSError, UnicodeDecodeError) as _:
        return {}, manifest_path

    legacy_to_canonical: dict[str, str] = {}
    repos = (data.get("repos") or {}) if isinstance(data, dict) else {}
    if isinstance(repos, dict):
        for entry in repos.values():
            if not isinstance(entry, dict):
                continue
            canonical = entry.get("canonical_name")
            legacy_names = entry.get("legacy_names") or []
            if not isinstance(canonical, str) or not isinstance(legacy_names, list):
                continue
            for name in legacy_names:
                if isinstance(name, str) and name and name != canonical:
                    legacy_to_canonical[name] = canonical
    return legacy_to_canonical, manifest_path


def _scan_paths(repo_root: Path, src_root: Path) -> list[Path]:
    """Tracked files X1 inspects: .py under src + repo .md docs.

    Skips .venv, __pycache__, vendor/, build artefacts, and any path
    containing 'history' or 'archive' (those reference renamed repos
    intentionally as historical record).
    """
    out: list[Path] = []
    if src_root.is_dir():
        out.extend(src_root.rglob("*.py"))
    out.extend(repo_root.rglob("*.md"))

    skip_parts = {".venv", "__pycache__", "node_modules", "build", "dist", ".git",
                  "history", "archive", ".console"}

    def _ok(p: Path) -> bool:
        if not p.is_file():
            return False
        return not (set(p.parts) & skip_parts)

    return [p for p in out if _ok(p)]


def detect_x1(context: AuditContext) -> DetectorResult:
    """Flag tracked files referencing a PlatformManifest legacy alias.

    When a repo has been renamed in PlatformManifest, callers should
    resolve the new canonical name through the manifest rather than
    hard-coding the old name. X1 catches stale references.

    Configurable exclude paths via ``audit.exclude_paths.X1``.
    """
    audit_cfg = context.config.get("audit") or {}
    legacy_map, manifest_path = _load_platform_manifest(
        context.repo_root, audit_cfg,
    )
    if not legacy_map or manifest_path is None:
        return DetectorResult(count=0, samples=[])

    excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("X1") or [])
    # Always exempt the manifest itself plus this repo's own legacy mention
    # (the local repo's own legacy_names live in the source of truth).

    # Build a single regex that matches any legacy name as a whole word.
    pattern = r"\b(?:" + "|".join(re.escape(n) for n in legacy_map) + r")\b"
    matcher = re.compile(pattern)

    samples: list[str] = []
    count = 0
    seen: set[tuple[str, int, str]] = set()

    for path in _scan_paths(context.repo_root, context.src_root):
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
                legacy = match.group(0)
                key = (rel_posix, i, legacy)
                if key in seen:
                    continue
                seen.add(key)
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    canonical = legacy_map[legacy]
                    samples.append(
                        f"{rel}:{i}: legacy name `{legacy}` — "
                        f"PlatformManifest canonical is `{canonical}`"
                    )
    return DetectorResult(count=count, samples=samples)
