# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Architecture boundary policy — enforce import restrictions declared in config.

Config schema (under ``policy.architecture`` or ``architecture``):

    policy:
      architecture:
        rules:
          - description: "domain must not import from adapters"
            from_glob: "src/domain/**"
            forbid_import_prefix:
              - "adapters."
              - "custodian.adapters."
          - description: "CLI must not import from domain internals"
            from_glob: "src/cli/**"
            forbid_import_prefix:
              - "domain.internal"

Violations are emitted as Finding(tool="policy", rule="ARCH_VIOLATION", severity="high").
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from custodian.core.finding import Finding, HIGH


def _glob_to_re(pattern: str) -> re.Pattern[str]:
    parts = pattern.split("**")
    escaped = [re.escape(p).replace(r"\*", "[^/]*") for p in parts]
    return re.compile("^" + ".*".join(escaped) + "$")


def _check_architecture(
    repo_root: Path,
    src_root: Path,
    rules: list[dict],
) -> list[Finding]:
    findings: list[Finding] = []

    py_files = list(src_root.rglob("*.py")) if src_root.is_dir() else []

    for arch_rule in rules:
        from_pat = _glob_to_re(arch_rule.get("from_glob", "**"))
        forbidden: list[str] = arch_rule.get("forbid_import_prefix", [])
        description = arch_rule.get("description", "architecture violation")

        for py_file in py_files:
            try:
                rel = str(py_file.relative_to(repo_root)).replace("\\", "/")
            except ValueError:
                rel = str(py_file)

            if not from_pat.match(rel):
                continue

            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
            except (OSError, SyntaxError):
                continue

            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        for prefix in forbidden:
                            if alias.name.startswith(prefix):
                                findings.append(Finding(
                                    tool="policy",
                                    rule="ARCH_VIOLATION",
                                    severity=HIGH,
                                    path=rel,
                                    line=node.lineno,
                                    message=f"{description}: import {alias.name!r} forbidden",
                                ))
                elif isinstance(node, ast.ImportFrom):
                    module = node.module or ""
                    for prefix in forbidden:
                        if module.startswith(prefix):
                            findings.append(Finding(
                                tool="policy",
                                rule="ARCH_VIOLATION",
                                severity=HIGH,
                                path=rel,
                                line=node.lineno,
                                message=f"{description}: from {module!r} import forbidden",
                            ))
    return findings


def run_architecture_policy(repo_root: Path, config: dict) -> list[Finding]:
    """Run architecture boundary checks from config.

    Reads rules from ``policy.architecture.rules`` (new schema) or
    ``architecture.rules`` (old schema).
    """
    policy = config.get("policy", {})
    arch_cfg = policy.get("architecture") or config.get("architecture") or {}
    rules: list[dict] = arch_cfg.get("rules", [])
    if not rules:
        return []

    src_root = repo_root / config.get("src_root", "src")
    return _check_architecture(repo_root, src_root, rules)
