# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Finding filter — applies severity floor, ignore-rules, and ignore-paths."""
from __future__ import annotations

import re

from custodian.core.finding import Finding, _SEVERITY_ORDER


def _glob_to_re(pattern: str) -> re.Pattern[str]:
    """Convert a glob-style pattern to a compiled regex.

    Supports ``*`` (any chars except /) and ``**`` (any chars including /).
    """
    parts = pattern.split("**")
    escaped = [re.escape(p).replace(r"\*", "[^/]*") for p in parts]
    joined = ".*".join(escaped)
    return re.compile(f"^{joined}$")


def _path_matches_any(path: str, patterns: list[re.Pattern[str]]) -> bool:
    norm = path.replace("\\", "/")
    return any(pat.search(norm) for pat in patterns)


def apply_policy(
    findings: list[Finding],
    *,
    min_severity: str | None = None,
    ignore_rules: list[str] | None = None,
    ignore_paths: list[str] | None = None,
) -> list[Finding]:
    """Filter a list of findings according to policy.

    Args:
        findings:      Raw findings from adapters.
        min_severity:  Drop findings below this level (high > medium > low > critical).
                       None means keep all.
        ignore_rules:  Rule codes to suppress entirely (e.g. ["F401", "ANN001"]).
        ignore_paths:  Glob patterns for paths to suppress (e.g. ["tests/**", "*.pyi"]).

    Returns a new list — original list is not mutated.
    """
    floor_rank = _SEVERITY_ORDER.get(min_severity or "low", 3)
    blocked_rules: set[str] = set(ignore_rules or [])
    path_patterns: list[re.Pattern[str]] = [_glob_to_re(p) for p in (ignore_paths or [])]

    out: list[Finding] = []
    for f in findings:
        if _SEVERITY_ORDER.get(f.severity, 99) > floor_rank:
            continue
        if f.rule in blocked_rules:
            continue
        if f.path and path_patterns and _path_matches_any(f.path, path_patterns):
            continue
        out.append(f)
    return out


def policy_from_config(config: dict) -> dict:
    """Extract the policy sub-config from a .custodian.yaml dict.

    Supports both old and new schema layouts:
      - New: config["policy"]
      - Old: config["audit"] (min_severity, ignore_rules, ignore_paths)
    """
    if "policy" in config:
        return config["policy"]
    # Old schema compatibility
    audit = config.get("audit") or {}
    return {
        "min_severity": audit.get("min_severity"),
        "ignore_rules": audit.get("ignore_rules", []),
        "ignore_paths": audit.get("ignore_paths", []),
    }
