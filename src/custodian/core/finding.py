# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Canonical Finding model — all adapters emit this type."""
from __future__ import annotations

from dataclasses import asdict, dataclass

CRITICAL = "critical"
HIGH = "high"
MEDIUM = "medium"
LOW = "low"

_SEVERITY_ORDER: dict[str, int] = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}


@dataclass(frozen=True)
class Finding:
    """One normalized finding from any tool or policy check.

    Attributes:
        tool:     Name of the adapter that produced this (e.g. "ruff", "semgrep").
        rule:     Rule or detector code (e.g. "E722", "S1", "TOOL_UNAVAILABLE").
        severity: "critical" | "high" | "medium" | "low"
        path:     Repo-relative file path, or None for repo-level findings.
        line:     1-based line number, or None.
        message:  Human-readable description.
    """

    tool: str
    rule: str
    severity: str
    path: str | None
    line: int | None
    message: str

    def at_least(self, severity: str) -> bool:
        """Return True if this finding's severity is >= the given level."""
        return _SEVERITY_ORDER.get(self.severity, 99) <= _SEVERITY_ORDER.get(severity, 99)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(
            tool=str(d["tool"]),
            rule=str(d["rule"]),
            severity=str(d.get("severity", LOW)),
            path=d.get("path"),
            line=d.get("line"),
            message=str(d.get("message", "")),
        )

    @staticmethod
    def tool_unavailable(tool_name: str) -> Finding:
        return Finding(
            tool=tool_name,
            rule="TOOL_UNAVAILABLE",
            severity=LOW,
            path=None,
            line=None,
            message=f"{tool_name!r} is not installed or not on PATH — findings skipped",
        )
