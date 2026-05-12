# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
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

Boundary sources may also be provided indirectly, so public repos do not
need to hardcode private names in tracked config:

* ``privacy.boundary_artifact_file`` — RepoGraph boundary artifact path
* ``$REPOGRAPH_BOUNDARY_ARTIFACT_FILE`` — path to that artifact
* ``$REPOGRAPH_BOUNDARY_ARTIFACT`` — inline JSON/YAML artifact payload
* legacy compatibility:
  ``privacy.private_repo_names_file``, ``$CUSTODIAN_PRIVATE_REPO_NAMES_FILE``,
  ``$CUSTODIAN_PRIVATE_REPO_NAMES``

Detectors
─────────
B1  Tracked file under the repo root contains a configured private-repo
    name. MEDIUM severity. The detector returns one finding per
    line/match (capped at ``_MAX_SAMPLES``); the first ~8 violations
    are reported in samples.
B2  Privacy blocklist is required but no private-repo names source is
    configured. MEDIUM severity. Used by public repos to make the
    private-name gate mandatory.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, MEDIUM,
)
from custodian.audit_kit.glob_match import glob_match


_MAX_SAMPLES = 8
_ARTIFACT_FILE_ENV = "REPOGRAPH_BOUNDARY_ARTIFACT_FILE"
_ARTIFACT_TEXT_ENV = "REPOGRAPH_BOUNDARY_ARTIFACT"
_NAMES_FILE_ENV = "CUSTODIAN_PRIVATE_REPO_NAMES_FILE"
_NAMES_TEXT_ENV = "CUSTODIAN_PRIVATE_REPO_NAMES"
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
        Detector(
            "B2",
            "Private repo name blocklist is required but not configured",
            "open",
            detect_b2,
            MEDIUM,
            frozenset(),
        ),
    ]


def _parse_config(config: dict) -> tuple[list[str], list[str], bool, str | None]:
    """Return (forbidden_names, exclude_paths, require_source, provenance)."""
    block = config.get("privacy") or {}
    names: list[str] = []
    provenance: str | None = None
    artifact_payload, provenance = _load_boundary_artifact_payload(block)
    if artifact_payload is not None:
        names.extend(_parse_boundary_artifact_names(artifact_payload))
    names.extend(list(block.get("private_repo_names") or []))
    names.extend(_load_names_from_file(block.get("private_repo_names_file")))
    names.extend(_load_names_from_file(_env_str(_NAMES_FILE_ENV)))
    names.extend(_parse_names_blob(_env_str(_NAMES_TEXT_ENV)))
    names = _dedupe_preserve_order(name for name in names if name)
    extra_excludes = list(block.get("exclude_paths") or [])
    excludes = list(_DEFAULT_EXCLUDES) + extra_excludes
    require_names_source = bool(
        block.get("require_boundary_artifact", False)
        or block.get("require_private_repo_name_source", False)
    )
    return names, excludes, require_names_source, provenance


def _names_source_paths(config: dict) -> list[Path]:
    block = config.get("privacy") or {}
    paths: list[Path] = []
    for raw in (
        block.get("boundary_artifact_file"),
        _env_str(_ARTIFACT_FILE_ENV),
        block.get("private_repo_names_file"),
        _env_str(_NAMES_FILE_ENV),
    ):
        if not raw:
            continue
        paths.append(Path(str(raw)).expanduser().resolve())
    return paths


def _env_str(name: str) -> str | None:
    import os

    value = os.environ.get(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _load_names_from_file(raw_path: Any) -> list[str]:
    if not raw_path:
        return []
    path = Path(str(raw_path)).expanduser()
    if not path.is_file():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    return _parse_names_document(text)


def _load_boundary_artifact_payload(block: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    file_path = block.get("boundary_artifact_file") or _env_str(_ARTIFACT_FILE_ENV)
    if file_path:
        path = Path(str(file_path)).expanduser()
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                return None, None
            payload = _parse_boundary_artifact_document(text)
            if payload is not None:
                return payload, _artifact_provenance(payload, fallback=str(path))
    inline = block.get("boundary_artifact") or _env_str(_ARTIFACT_TEXT_ENV)
    if inline:
        payload = _parse_boundary_artifact_document(str(inline))
        if payload is not None:
            return payload, _artifact_provenance(payload, fallback="inline-artifact")
    return None, None


def _parse_boundary_artifact_document(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    if not stripped:
        return None
    parsed: Any = None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        parsed = None
    if parsed is None:
        try:
            import yaml
        except ImportError:
            parsed = None
        else:
            try:
                parsed = yaml.safe_load(stripped)
            except yaml.YAMLError:
                parsed = None
    if not isinstance(parsed, dict):
        return None
    names = parsed.get("forbidden_names")
    if not isinstance(names, list):
        return None
    return parsed


def _parse_boundary_artifact_names(payload: dict[str, Any]) -> list[str]:
    values = payload.get("forbidden_names") or []
    return [str(item).strip() for item in values if str(item).strip()]


def _artifact_provenance(payload: dict[str, Any], *, fallback: str) -> str:
    source = payload.get("source_graph_id") or fallback
    ref = payload.get("source_ref_or_commit")
    return f"{source}@{ref}" if ref else str(source)


def _parse_names_document(text: str) -> list[str]:
    stripped = text.strip()
    if not stripped:
        return []

    parsed: Any = None
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        parsed = None

    if parsed is None:
        try:
            import yaml
        except ImportError:
            parsed = None
        else:
            try:
                parsed = yaml.safe_load(stripped)
            except yaml.YAMLError:
                parsed = None

    if isinstance(parsed, dict):
        values = parsed.get("private_repo_names") or []
        if isinstance(values, list):
            return [str(item).strip() for item in values if str(item).strip()]
    if isinstance(parsed, list):
        return [str(item).strip() for item in parsed if str(item).strip()]

    return _parse_names_blob(stripped)


def _parse_names_blob(blob: str | None) -> list[str]:
    if not blob:
        return []
    parts: list[str] = []
    for raw in blob.replace(",", "\n").splitlines():
        item = raw.strip()
        if not item or item.startswith("#"):
            continue
        parts.append(item)
    return parts


def _dedupe_preserve_order(values) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


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
    names, excludes, _require, provenance = _parse_config(context.config)
    source_paths = set(_names_source_paths(context.config))
    if not names:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0
    for path in _tracked_files(context.repo_root):
        try:
            rel = path.relative_to(context.repo_root)
        except ValueError:
            continue
        try:
            if path.resolve() in source_paths:
                continue
        except OSError:
            pass
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
                            + (f" [boundary={provenance}]" if provenance else "")
                        )
                    break  # one finding per line is enough
    return DetectorResult(count=count, samples=samples)


def detect_b2(context: AuditContext) -> DetectorResult:
    """Fail when a repo requires a private-name source but none is configured."""
    names, _excludes, require, _provenance = _parse_config(context.config)
    if not require or names:
        return DetectorResult(count=0, samples=[])
    samples = [
        "privacy.require_boundary_artifact/require_private_repo_name_source=true but no "
        "boundary source was provided via privacy.boundary_artifact_file, "
        f"${_ARTIFACT_FILE_ENV}, ${_ARTIFACT_TEXT_ENV}, privacy.private_repo_names, "
        f"privacy.private_repo_names_file, ${_NAMES_FILE_ENV}, or ${_NAMES_TEXT_ENV}"
    ]
    return DetectorResult(count=1, samples=samples)
