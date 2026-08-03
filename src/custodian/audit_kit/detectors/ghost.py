# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""G-class detectors — ghost work (stale references in comments and metadata).

Detectors
─────────
G1  TODO/FIXME comments that reference a CamelCase name no longer present
    anywhere in the source tree.  These are "ghost work" items — the task
    they describe may have been invalidated by a rename or removal, leaving
    a dangling work item that will never be actionable.

    Detection approach:
      1. Scan every .py file for lines containing ``# TODO`` or ``# FIXME``.
      2. Extract CamelCase tokens from the comment text (words that start
         with an uppercase letter and contain at least one more uppercase
         letter — e.g. ``MyClass``, ``FooBarService``).
      3. Flag comments that reference at least one CamelCase name that
         does not appear anywhere in any source file as a text token.

    Conservative by design: only CamelCase names are checked (snake_case
    identifiers match too many common English words).  The check is
    against ``all_text_tokens`` (every identifier-like word in every
    source file), not just definitions, so a name that appears in a
    string or comment elsewhere is not flagged.
"""
from __future__ import annotations

import re

from custodian.audit_kit.detector import (
    LOW,
    AuditContext,
    Detector,
    DetectorResult,
)

_MAX_SAMPLES = 8
_NEEDS = frozenset({"symbol_index"})

_TODO_LINE_RE = re.compile(r"#\s*(?:TODO|FIXME)\b(.*)", re.IGNORECASE)
# CamelCase: starts uppercase, contains at least one more uppercase letter
_CAMEL_RE = re.compile(r"\b([A-Z][a-z0-9]+(?:[A-Z][a-zA-Z0-9]*)+)\b")

# Short common English words that happen to be CamelCase-ish — ignore them.
_COMMON_WORDS = frozenset({
    "None", "True", "False", "Ok", "Id",
    "TypeError", "ValueError", "KeyError", "IndexError", "RuntimeError",
    "NotImplementedError", "AttributeError", "OSError", "IOError",
    "StopIteration", "Exception", "BaseException",
})


def build_ghost_detectors() -> list[Detector]:
    return [
        Detector("G1", "TODO/FIXME references a CamelCase name no longer in source", "open",
                 detect_g1, LOW, _NEEDS),
    ]


def detect_g1(context: AuditContext) -> DetectorResult:
    """Flag TODO/FIXME comments whose CamelCase references have vanished from src."""
    if context.graph is None or context.graph.symbol_index is None:
        return DetectorResult(count=0, samples=[])

    all_tokens = context.graph.symbol_index.all_text_tokens
    samples: list[str] = []
    count = 0

    for path in sorted(context.src_root.rglob("*.py")):
        if not path.is_file():
            continue
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        rel = path.relative_to(context.repo_root).as_posix()
        for lineno, line in enumerate(lines, 1):
            m = _TODO_LINE_RE.search(line)
            if not m:
                continue
            comment_text = m.group(1)
            ghost_names = [
                name for name in _CAMEL_RE.findall(comment_text)
                if name not in _COMMON_WORDS and name not in all_tokens
            ]
            if ghost_names:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    first = ghost_names[0]
                    samples.append(
                        f"{rel}:{lineno}: '{first}' not found in src — {line.strip()[:80]}"
                    )

    return DetectorResult(count=count, samples=samples)
