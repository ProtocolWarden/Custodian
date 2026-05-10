# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import json

SCHEMA_VERSION = 1


@dataclass
class AuditResult:
    schema_version: int = SCHEMA_VERSION
    repo_key: str = ""
    scanned_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    patterns: dict = field(default_factory=dict)
    total_findings: int = 0

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
