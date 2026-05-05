# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Parse audit-result samples and group them by file path.

Sample format (set by detectors): ``"path/to/file.py:42: message"`` or
``"path/to/file.py: message"`` (no line number). Anything that doesn't
match is dropped from the per-file index — it can't be triaged.
"""
from __future__ import annotations

import re
from collections import defaultdict

# "path:line:" or "path:" prefix; path captures up to the first ':'.
_SAMPLE_RE = re.compile(r"^(?P<path>[^:\s][^:]*\.py)(?::(?P<line>\d+))?:\s*(?P<msg>.*)$")


def parse_sample(sample: str) -> tuple[str, int | None, str] | None:
    """Return ``(path, line, message)`` for a detector sample, or None."""
    m = _SAMPLE_RE.match(sample)
    if not m:
        return None
    line = int(m["line"]) if m["line"] else None
    return m["path"], line, m["msg"]


def group_findings_by_file(patterns: dict) -> dict[str, dict[str, list[tuple[int | None, str]]]]:
    """Group {detector_id -> [(line, message), ...]} per file path.

    ``patterns`` is the ``AuditResult.patterns`` dict (or its JSON form).
    Detectors with ``count == 0`` are skipped. Adapter findings (RUFF, TY,
    VULTURE) are included — they share the ``path:line:`` format.
    """
    by_file: dict[str, dict[str, list[tuple[int | None, str]]]] = defaultdict(lambda: defaultdict(list))
    for det_id, pat in patterns.items():
        if pat.get("count", 0) == 0:
            continue
        for sample in pat.get("samples", []):
            parsed = parse_sample(sample)
            if parsed is None:
                continue
            path, line, msg = parsed
            by_file[path][det_id].append((line, msg))
    return by_file
