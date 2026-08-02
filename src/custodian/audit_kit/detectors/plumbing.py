# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""P-class detectors — artifact plumbing enforcement.

These detectors verify that JSON artifacts written by one component are read
by another using the same key vocabulary. They are fully config-driven and
operate on concrete file paths, not import graphs.

Detectors
─────────
P1  Writer key audit — every key in ``written_keys`` must appear as a
    word-boundary token in at least one file matched by ``writer_glob``.
    Catches silent key removal on the writer side.

P2  Reader key drift — every string key accessed in the reader file (via
    subscript or ``.get()``) inside functions whose body contains
    ``path_fragment`` as a string literal must be declared in
    ``written_keys``. Catches stale reads after a writer rename.

P3  Path coverage — ``path_fragment`` must appear as a string literal in
    both writer files and the reader file. Catches abandoned artifact paths
    when one side removes the path without the other noticing.

Configuration
─────────────
Under ``audit.plumbing`` in ``.custodian/config.yaml``::

    audit:
      plumbing:
        - id: usage
          writer_glob: "src/my_service/usage_store.py"
          reader_path: "../Consumer/src/consumer/status_pane.py"
          written_keys: [updated_at, events, hourly_count]
          path_fragment: "usage.json"
        - id: heartbeat
          writer_glob: "src/my_service/entrypoints/*/main.py"
          reader_path: "../Consumer/src/consumer/status_pane.py"
          written_keys: [role, at, status]
          path_fragment: "heartbeat_"

All detectors silently skip when ``audit.plumbing`` is absent or empty.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from custodian.audit_kit.detector import (
    MEDIUM,
    AuditContext,
    Detector,
    DetectorResult,
)

_MAX_SAMPLES = 8


def build_plumbing_detectors() -> list[Detector]:
    return [
        Detector(
            "P1",
            "artifact written_key absent from writer source — writer may have dropped a key",
            "open",
            detect_p1,
            MEDIUM,
            frozenset(),
        ),
        Detector(
            "P2",
            "reader accesses a JSON key not declared in written_keys — potential stale read",
            "open",
            detect_p2,
            MEDIUM,
            frozenset(),
        ),
        Detector(
            "P3",
            "artifact path_fragment missing from writer or reader — abandoned artifact path",
            "open",
            detect_p3,
            MEDIUM,
            frozenset(),
        ),
    ]


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------

def _plumbing_specs(context: AuditContext) -> list[dict[str, Any]]:
    """Return the list of plumbing artifact specs from config, or []."""
    audit_cfg = context.config.get("audit") or {}
    specs = audit_cfg.get("plumbing") or []
    return specs if isinstance(specs, list) else []


def _expand_writer_files(repo_root: Path, writer_glob: str) -> list[Path]:
    """Glob writer files relative to repo_root."""
    try:
        matched = list(repo_root.glob(writer_glob))
    except (ValueError, OSError):
        return []
    return [p for p in matched if p.is_file()]


def _resolve_reader(repo_root: Path, reader_path: str) -> Path | None:
    p = (repo_root / reader_path).resolve()
    return p if p.is_file() else None


# ---------------------------------------------------------------------------
# P1 — Writer key audit
# ---------------------------------------------------------------------------

def detect_p1(context: AuditContext) -> DetectorResult:
    """Flag written_keys that have no word-boundary token in any writer file."""
    specs = _plumbing_specs(context)
    if not specs:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for spec in specs:
        artifact_id = spec.get("id", "?")
        writer_glob = spec.get("writer_glob", "")
        written_keys: list[str] = list(spec.get("written_keys") or [])

        if not writer_glob or not written_keys:
            continue

        writer_files = _expand_writer_files(context.repo_root, writer_glob)
        if not writer_files:
            continue

        # Read all writer file contents once
        writer_texts: list[str] = []
        for wf in writer_files:
            try:
                writer_texts.append(wf.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                pass

        for key in written_keys:
            pattern = re.compile(r'\b' + re.escape(key) + r'\b')
            found = any(pattern.search(text) for text in writer_texts)
            if not found:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"[{artifact_id}] key '{key}' not found in any writer "
                        f"file matching '{writer_glob}'"
                    )

    return DetectorResult(count=count, samples=samples)


# ---------------------------------------------------------------------------
# P2 — Reader key drift
# ---------------------------------------------------------------------------

# All-uppercase identifiers (e.g. COLOR["DIM"], os.environ.get("ENV_VAR"))
# are never JSON artifact keys — skip them to avoid noisy false positives.
_ALL_CAPS_RE = re.compile(r'^[A-Z][A-Z0-9_]*$')


def _collect_json_keys_in_functions(
    tree: ast.Module,
    path_fragment: str,
    ignore_keys: frozenset[str] = frozenset(),
) -> set[str]:
    """Return string keys accessed via subscript or .get() within functions
    that reference path_fragment as a string literal."""
    keys: set[str] = set()

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        # Check if this function body contains path_fragment as a string constant
        has_fragment = False
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                if path_fragment in child.value:
                    has_fragment = True
                    break
        if not has_fragment:
            continue

        # Collect all string subscript and .get() call accesses in this function
        for child in ast.walk(node):
            # data["key"] or data['key']
            if (
                isinstance(child, ast.Subscript)
                and isinstance(child.slice, ast.Constant)
                and isinstance(child.slice.value, str)
            ):
                k = child.slice.value
                if not _ALL_CAPS_RE.match(k) and k not in ignore_keys:
                    keys.add(k)

            # data.get("key") or data.get("key", default)
            if (
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Attribute)
                and child.func.attr == "get"
                and child.args
                and isinstance(child.args[0], ast.Constant)
                and isinstance(child.args[0].value, str)
            ):
                k = child.args[0].value
                if not _ALL_CAPS_RE.match(k) and k not in ignore_keys:
                    keys.add(k)

    return keys


def detect_p2(context: AuditContext) -> DetectorResult:
    """Flag reader-side JSON key accesses not declared in written_keys."""
    specs = _plumbing_specs(context)
    if not specs:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for spec in specs:
        artifact_id = spec.get("id", "?")
        reader_path_str = spec.get("reader_path", "")
        written_keys: set[str] = set(spec.get("written_keys") or [])
        path_fragment: str = spec.get("path_fragment", "")

        if not reader_path_str or not path_fragment:
            continue

        reader_path = _resolve_reader(context.repo_root, reader_path_str)
        if reader_path is None:
            continue

        try:
            source = reader_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        try:
            tree = ast.parse(source, filename=str(reader_path))
        except SyntaxError:
            continue

        ignore_keys: frozenset[str] = frozenset(spec.get("ignore_keys") or [])
        accessed_keys = _collect_json_keys_in_functions(tree, path_fragment, ignore_keys)

        for key in sorted(accessed_keys):
            if key not in written_keys:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    rel = reader_path.relative_to(context.repo_root) if reader_path.is_relative_to(context.repo_root) else reader_path
                    samples.append(
                        f"[{artifact_id}] reader '{rel}' accesses key '{key}' "
                        f"not in written_keys (fragment: '{path_fragment}')"
                    )

    return DetectorResult(count=count, samples=samples)


# ---------------------------------------------------------------------------
# P3 — Path coverage
# ---------------------------------------------------------------------------

def _has_string_literal(text: str, fragment: str) -> bool:
    """True if fragment appears anywhere in text (simple substring check)."""
    return fragment in text


def detect_p3(context: AuditContext) -> DetectorResult:
    """Flag artifacts where path_fragment is absent from writer or reader."""
    specs = _plumbing_specs(context)
    if not specs:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for spec in specs:
        artifact_id = spec.get("id", "?")
        writer_glob = spec.get("writer_glob", "")
        reader_path_str = spec.get("reader_path", "")
        path_fragment: str = spec.get("path_fragment", "")

        if not path_fragment:
            continue

        # Check writer side
        if writer_glob:
            writer_files = _expand_writer_files(context.repo_root, writer_glob)
            if not writer_files:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"[{artifact_id}] writer_glob '{writer_glob}' matches no files "
                        f"— cannot verify path_fragment '{path_fragment}' on writer side"
                    )
            else:
                found_in_writer = False
                for wf in writer_files:
                    try:
                        text = wf.read_text(encoding="utf-8", errors="replace")
                    except OSError:
                        continue
                    if _has_string_literal(text, path_fragment):
                        found_in_writer = True
                        break
                if not found_in_writer:
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        samples.append(
                            f"[{artifact_id}] path_fragment '{path_fragment}' absent "
                            f"from all writer files (glob: '{writer_glob}')"
                        )

        # Check reader side
        if reader_path_str:
            reader_path = _resolve_reader(context.repo_root, reader_path_str)
            if reader_path is None:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"[{artifact_id}] reader '{reader_path_str}' not found "
                        f"— cannot verify path_fragment '{path_fragment}' on reader side"
                    )
            else:
                try:
                    text = reader_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = ""
                if not _has_string_literal(text, path_fragment):
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        rel = reader_path.relative_to(context.repo_root) if reader_path.is_relative_to(context.repo_root) else reader_path
                        samples.append(
                            f"[{artifact_id}] path_fragment '{path_fragment}' absent "
                            f"from reader '{rel}'"
                        )

    return DetectorResult(count=count, samples=samples)
