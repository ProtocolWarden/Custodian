# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""B-class detectors — boundary artifact leakage enforcement.

Public repos describe stable, reusable platform capabilities. Private
manifests bind those capabilities to specific private repos. A public
repo that names a private repo in its tracked artifacts leaks the
private/public boundary — operators who consume the public repo learn
which private repos the platform's owner runs.

This detector class enforces that boundary via RepoGraph artifacts.
Configure the artifact source in ``.custodian/config.yaml``::

    privacy:
      require_boundary_artifact: true
      boundary_artifact_file: /path/to/boundary_disclosure_artifact.json
      exclude_paths:
        - "docs/history/**"
        - "config/managed_repos/local/**"
        - ".console/**"

Match is case-sensitive substring on text content. Configure both
``CamelCase`` and ``snake_case`` (or any other casing the repo's
package uses) explicitly — the detector does not normalise casing
because the leak surface is the literal string an operator sees in
tracked files. Binary files are skipped.

Boundary sources must be provided as a file so provenance stays
auditable:

* ``privacy.boundary_artifact_file`` — RepoGraph boundary artifact path
* ``$REPOGRAPH_BOUNDARY_ARTIFACT_FILE`` — path to that artifact

Detectors
─────────
B1  Tracked file under the repo root contains a configured private-repo
    name. MEDIUM severity. The detector returns one finding per
    line/match (capped at ``_MAX_SAMPLES``); the first ~8 violations
    are reported in samples.
B2  Boundary artifact is required but no boundary source is
    configured. MEDIUM severity. Used by public repos to make the
    private-name gate mandatory.
"""
from __future__ import annotations

import json
import subprocess
from hashlib import sha256
from pathlib import Path

from custodian.audit_kit.detector import (
    MEDIUM,
    AuditContext,
    Detector,
    DetectorResult,
)
from custodian.audit_kit.glob_match import glob_match

_MAX_SAMPLES = 8
_ARTIFACT_FILE_ENV = "REPOGRAPH_BOUNDARY_ARTIFACT_FILE"
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
            "Boundary artifact is required but not configured",
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
    artifact_payload, provenance, error = _load_boundary_artifact_payload(block)
    if error:
        return [], list(_DEFAULT_EXCLUDES) + list(block.get("exclude_paths") or []), bool(block.get("require_boundary_artifact", False)), error
    if artifact_payload is not None:
        names.extend(_parse_boundary_artifact_names(artifact_payload))
    names = _dedupe_preserve_order(name for name in names if name)
    extra_excludes = list(block.get("exclude_paths") or [])
    excludes = list(_DEFAULT_EXCLUDES) + extra_excludes
    require_names_source = bool(block.get("require_boundary_artifact", False))
    return names, excludes, require_names_source, provenance


def _names_source_paths(config: dict) -> list[Path]:
    block = config.get("privacy") or {}
    paths: list[Path] = []
    for raw in (
        block.get("boundary_artifact_file"),
        _env_str(_ARTIFACT_FILE_ENV),
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


def _load_boundary_artifact_payload(block: dict[str, object]) -> tuple[dict[str, object] | None, str | None, str | None]:
    file_path = block.get("boundary_artifact_file") or _env_str(_ARTIFACT_FILE_ENV)
    if not file_path:
        return None, None, None
    path = Path(str(file_path)).expanduser()
    if not path.is_file():
        return None, None, f"boundary artifact file not found: {path}"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None, None, f"boundary artifact file unreadable: {path}"
    payload, error = _parse_boundary_artifact_document(text)
    if error:
        return None, None, error
    if payload is not None:
        return payload, _artifact_provenance(payload, fallback=str(path)), None
    return None, None, "boundary artifact document is empty"


def _parse_boundary_artifact_document(text: str) -> tuple[dict[str, object] | None, str | None]:
    stripped = text.strip()
    if not stripped:
        return None, "boundary artifact document is empty"
    parsed: object = None
    try:
        parsed = json.loads(stripped)
    except (json.JSONDecodeError, ValueError):
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
        return None, "boundary artifact document is not a JSON/YAML object"
    names = parsed.get("forbidden_names")
    if not isinstance(names, list):
        return None, "boundary artifact missing forbidden_names list"
    schema_kind = parsed.get("schema_kind")
    schema_version = parsed.get("schema_version")
    artifact_kind = parsed.get("artifact_kind")
    if schema_kind != "boundary_artifact":
        return None, "boundary artifact schema_kind must be 'boundary_artifact'"
    if schema_version != "1.0.0":
        return None, f"boundary artifact schema_version unsupported: {schema_version!r}"
    if artifact_kind != "boundary_disclosure_artifact":
        return None, "boundary artifact_kind must be 'boundary_disclosure_artifact'"
    required = ("source_graph_id", "generated_at")
    missing = [key for key in required if not parsed.get(key)]
    if missing:
        return None, f"boundary artifact missing required fields: {missing}"
    artifact_hash = parsed.get("artifact_hash")
    if artifact_hash:
        expected = _boundary_artifact_hash(parsed)
        if artifact_hash != expected:
            return None, "boundary artifact hash mismatch"
    if parsed.get("signature"):
        return None, "boundary artifact signature present but no verifier is configured"
    return parsed, None


def _parse_boundary_artifact_names(payload: dict[str, object]) -> list[str]:
    raw = payload.get("forbidden_names")
    values = list(raw) if isinstance(raw, list) else []
    return [str(item).strip() for item in values if str(item).strip()]


def _derive_abbreviations(names) -> list[str]:
    """Derive word-boundary abbreviations from CamelCase forbidden names.

    Spec §1 mandates a bare word-boundary alias (e.g. ``MR`` for a
    ``MediaRuntime``-style name) even though the artifact lists only the
    full CamelCase / ``snake_case`` forms. The alias is the sequence of
    upper-case initials of a multi-word CamelCase name (``MediaRuntime``
    → ``MR``); it is *derived*, never a second hardcoded copy, so the
    artifact stays the single source of truth (AC1). Single-word names
    and the ``snake_case`` duplicates yield no alias.
    """
    out: list[str] = []
    for name in names:
        caps = [c for c in name if c.isupper()]
        if len(caps) >= 2:
            out.append("".join(caps))
    return out


def load_scrub_targets(config: dict) -> list[str]:
    """Return the §1 scrub-target vocabulary from the single source of truth.

    The scrub-target set (the "public-leak names" vocabulary) is derived
    from the *same* boundary artifact B1 already loads — its
    ``forbidden_names`` list (the one populated key the artifact actually
    ships). This is deliberately the only place the set is defined; no
    detector keeps a second hardcoded copy, so changing the artifact
    changes detection everywhere (AC1), and it matches the key
    ContextLifecycle's ``cl reconcile`` reads, so both detection paths
    share one source.

    The full literal names supply CamelCase + ``snake_case`` forms; their
    word-boundary abbreviations (``MediaRuntime`` → ``MR``, spec §1) are
    *derived* from those same names rather than hardcoded. An optional
    ``scrub_targets`` list, when present, overrides the derived set (used
    by tests to inject a synthetic vocabulary without the real artifact).

    Returns an empty list when no boundary artifact is configured or it
    cannot be parsed — R-class detectors that depend on it then silently
    no-op rather than raising.
    """
    block = config.get("privacy") or {}
    payload, _provenance, error = _load_boundary_artifact_payload(block)
    if error or payload is None:
        return []
    override = payload.get("scrub_targets")
    if isinstance(override, list):
        values = [str(item).strip() for item in override if str(item).strip()]
        return _dedupe_preserve_order(values)
    names = _parse_boundary_artifact_names(payload)
    return _dedupe_preserve_order([*names, *_derive_abbreviations(names)])


def _artifact_provenance(payload: dict[str, object], *, fallback: str) -> str:
    source = payload.get("source_graph_id") or fallback
    ref = payload.get("source_ref_or_commit")
    return f"{source}@{ref}" if ref else str(source)


def _boundary_artifact_hash(payload: dict[str, object]) -> str:
    material = {
        key: value
        for key, value in payload.items()
        if key not in {"artifact_hash", "signature", "signed_at", "public_projection_redaction_report"}
    }
    canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256(canonical.encode("utf-8")).hexdigest()


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
    if isinstance(provenance, str) and provenance.startswith("boundary artifact"):
        return DetectorResult(count=1, samples=[provenance])
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
                            f"{rel.as_posix()}:{lineno}: contains {name!r}"
                            + (f" [boundary={provenance}]" if provenance else "")
                        )
                    break  # one finding per line is enough
    return DetectorResult(count=count, samples=samples)


def detect_b2(context: AuditContext) -> DetectorResult:
    """Fail when a repo requires a boundary artifact file but none is configured."""
    names, _excludes, require, provenance = _parse_config(context.config)
    if isinstance(provenance, str) and provenance.startswith("boundary artifact"):
        return DetectorResult(count=1, samples=[provenance])
    if not require or names:
        return DetectorResult(count=0, samples=[])
    # require=true, zero usable names, and no load error. Distinguish the two
    # ways this happens so the operator knows where to look: a content-less
    # artifact (provided + parsed, but its forbidden_names list was empty) vs
    # nothing provided at all. The first is a *secret/data* problem (the
    # artifact resolved but carries no boundary names — e.g. a stale or empty
    # disclosure export); the second is a *config* problem. Conflating them
    # sent operators hunting for a missing file when the file was present but
    # empty.
    if provenance:  # a real artifact loaded (provenance is its source id), but yielded no names
        samples = [
            ("privacy.require_boundary_artifact=true and a boundary artifact was "
            f"provided ({provenance}), but it contains zero forbidden_names — the "
            "artifact is content-less (regenerate the disclosure export so it lists "
            "the private boundary names)")
        ]
    else:
        samples = [
            ("privacy.require_boundary_artifact=true but no "
            "boundary artifact file was provided via privacy.boundary_artifact_file "
            f"or ${_ARTIFACT_FILE_ENV}")
        ]
    return DetectorResult(count=1, samples=samples)
