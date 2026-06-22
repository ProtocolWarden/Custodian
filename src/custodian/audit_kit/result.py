# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import json

SCHEMA_VERSION = 1

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}


def _severity_rank(severity: str | None) -> int:
    return _SEVERITY_RANK.get(severity or "low", 1)


@dataclass
class AuditResult:
    schema_version: int = SCHEMA_VERSION
    repo_key: str = ""
    scanned_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    patterns: dict = field(default_factory=dict)
    total_findings: int = 0

    def add_pattern(self, code: str, entry: dict) -> None:
        """Register a detector/adapter result, merging on ID collision.

        Detector IDs are assumed unique, but families can collide by
        accident — e.g. the builtin ``readme`` and ``reconcile`` detectors
        both ship ``R1``/``R2``, and a repo's custom plugin may add a third.
        Plain ``patterns[code] = entry`` then lets a later, count-0 instance
        silently overwrite an earlier instance that *found something*, while
        ``total_findings`` (summed independently) still counts it — a
        "phantom" finding that never appears in the patterns map or
        ``findings()``. That masking once hid a real boundary-leak (R2)
        finding. Merge instead so the visible pattern always reflects every
        instance's count and samples, keeping the map consistent with
        ``total_findings``.

        Merge rules: sum ``count``, concatenate ``samples`` (deduped,
        order-preserving), take the highest ``severity``, and mark the entry
        as a collision so consumers can surface it.
        """
        existing = self.patterns.get(code)
        if existing is None:
            self.patterns[code] = entry
            return
        merged_samples: list = list(existing.get("samples", []))
        seen = set(merged_samples)
        for s in entry.get("samples", []):
            if s not in seen:
                merged_samples.append(s)
                seen.add(s)
        existing["count"] = existing.get("count", 0) + entry.get("count", 0)
        existing["samples"] = merged_samples
        if _severity_rank(entry.get("severity")) > _severity_rank(existing.get("severity")):
            existing["severity"] = entry.get("severity")
        existing["collision"] = True
        sources = existing.setdefault("collision_sources", [existing.get("source")])
        if entry.get("source") not in sources:
            sources.append(entry.get("source"))

    def findings(self) -> list[dict]:
        """Flat list of {code, sample} for every sample across all patterns.

        Only includes patterns where ``count > 0`` — some detectors add
        informational messages to ``samples`` even when they found nothing
        (e.g. "module not importable"). Preserves detector order so consumers
        can group by code without sorting.
        """
        out: list[dict] = []
        for code, pat in self.patterns.items():
            if pat.get("count", 0) == 0:
                continue
            for sample in pat.get("samples", []):
                out.append({"code": code, "sample": sample})
        return out

    def to_json(self) -> str:
        """Emit stable, explicit JSON for downstream aggregation.

        Includes a top-level ``findings`` list — a flat enumeration of every
        sample across all patterns — so callers can do ``data["findings"]``
        without iterating ``patterns``.  The ``patterns`` dict is still
        present for backwards compatibility.
        """
        d = asdict(self)
        d["findings"] = self.findings()
        return json.dumps(d, indent=2, sort_keys=True, ensure_ascii=False)


def collision_note(pattern: dict) -> str:
    """A short marker for a finding whose detector-id collided with another's.

    When two detectors share an id (e.g. the builtin ``readme`` R2 and a repo's
    custom ``.console`` R2), ``AuditResult.add_pattern`` merges them under one
    entry whose displayed ``description`` is just the FIRST-registered detector's —
    so the finding can be silently MISATTRIBUTED (a ``.console/task.md`` violation
    shown as "README first H1 …"). This surfaces the collision in the output so a
    reader knows the title may not match the finding and should read the samples.

    Returns ``""`` for a non-colliding pattern."""
    if not pattern.get("collision"):
        return ""
    sources = [str(s) for s in (pattern.get("collision_sources") or []) if s]
    where = ", ".join(sources) if sources else "multiple detectors"
    return (
        f"  [⚠ DETECTOR-ID COLLISION across: {where} — the title above is only the "
        "first-registered detector's; the real finding may be a different one, see samples]"
    )
