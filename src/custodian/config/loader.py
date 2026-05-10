# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Config loader with dual-schema support and migration utilities.

Supports two schemas:

  Old schema (v0 — current in-repo format):
    repo_key: "my-repo"
    src_root: "src"
    tests_root: "tests"
    audit:
      min_severity: "medium"
      ignore_rules: [...]
      ignore_paths: [...]
    architecture:
      layers: [...]
      invariants: [...]

  New schema (v1 — post-refactor):
    version: 1
    repo:
      key: "my-repo"
      src_root: "src"
      tests_root: "tests"
    tools:
      ruff: {enabled: true}
      semgrep: {enabled: true, configs: [...]}
      ty: {enabled: true}
      vulture: {enabled: true, min_confidence: 80}
    policy:
      min_severity: "medium"
      ignore_rules: [...]
      ignore_paths: [...]
      architecture:
        rules: [...]
    reports:
      formats: [json, sarif]
      output_dir: ".custodian/reports"
"""
from __future__ import annotations

import warnings
from pathlib import Path
from typing import Any

try:
    import yaml as _yaml
    yaml: Any = _yaml
except ImportError:  # pragma: no cover
    yaml = None


_SCHEMA_VERSION_KEY = "version"
_CURRENT_VERSION = 1


def load_config(repo_root: Path) -> dict:
    """Load .custodian.yaml from repo_root.

    Returns a normalized v1 config dict regardless of which schema the file
    uses.  Old-schema files emit a DeprecationWarning describing the migration
    path.

    Raises FileNotFoundError if .custodian.yaml is absent.
    """
    config_path = repo_root / ".custodian.yaml"
    raw = _read_yaml(config_path)
    version = raw.get(_SCHEMA_VERSION_KEY)

    if version is None or int(version) < _CURRENT_VERSION:
        warnings.warn(
            f"{config_path}: using old config schema (v0). "
            "Run `custodian-config migrate` to upgrade to v1.",
            DeprecationWarning,
            stacklevel=2,
        )
        return _normalize_v0(raw)

    return raw


def _read_yaml(path: Path) -> dict:
    if yaml is None:  # pragma: no cover
        raise ImportError("pyyaml is required to load .custodian.yaml")
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _normalize_v0(raw: dict) -> dict:
    """Convert a v0 config to the normalized v1 shape (in-memory only)."""
    audit = raw.get("audit") or {}
    arch = raw.get("architecture") or {}

    normalized: dict[str, Any] = {
        "version": 0,  # retain original version to signal old schema
        "repo": {
            "key": raw.get("repo_key", ""),
            "src_root": raw.get("src_root", "src"),
            "tests_root": raw.get("tests_root", "tests"),
        },
        "tools": {
            "ruff":    {"enabled": True},
            "semgrep": {"enabled": True},
            "ty":      {"enabled": True},
            "vulture": {"enabled": True, "min_confidence": 80},
        },
        "policy": {
            "min_severity": audit.get("min_severity"),
            "ignore_rules": audit.get("ignore_rules", []),
            "ignore_paths": audit.get("ignore_paths", []),
            "architecture": {"rules": arch.get("layers", []) or arch.get("rules", [])},
        },
        "reports": {
            "formats": ["json"],
            "output_dir": ".custodian/reports",
        },
        # Preserve original keys so existing code that reads raw config still works
        **{k: v for k, v in raw.items()},
    }
    return normalized


def migrate_v0_to_v1(raw: dict) -> dict:
    """Return a fresh v1 config dict from an old v0 dict.

    This produces the YAML-ready dict; the caller handles writing.
    """
    audit = raw.get("audit") or {}
    arch = raw.get("architecture") or {}
    semgrep_cfg = raw.get("semgrep") or {}

    new: dict[str, Any] = {
        "version": 1,
        "repo": {
            "key": raw.get("repo_key", ""),
            "src_root": raw.get("src_root", "src"),
            "tests_root": raw.get("tests_root", "tests"),
        },
        "tools": {
            "ruff":    {"enabled": True},
            "semgrep": {
                "enabled": True,
                **({"configs": semgrep_cfg.get("configs")}
                   if semgrep_cfg.get("configs") else {}),
            },
            "ty":      {"enabled": True},
            "vulture": {"enabled": True, "min_confidence": 80},
        },
        "policy": {
            "min_severity": audit.get("min_severity", "low"),
            "ignore_rules": audit.get("ignore_rules", []),
            "ignore_paths": audit.get("ignore_paths", []),
        },
        "reports": {
            "formats": ["json"],
            "output_dir": ".custodian/reports",
        },
    }

    # Carry architecture rules over if present
    layers = arch.get("layers") or arch.get("rules") or []
    invariants = arch.get("invariants") or []
    if layers or invariants:
        new["policy"]["architecture"] = {}
        if layers:
            new["policy"]["architecture"]["rules"] = layers
        if invariants:
            new["policy"]["architecture"]["invariants"] = invariants

    return new


def config_summary(config: dict) -> list[str]:
    """Return a human-readable summary of effective config values."""
    lines = []
    version = config.get("version", 0)
    lines.append(f"Schema version: {version}")

    repo = config.get("repo") or {}
    lines.append(f"Repo key:    {repo.get('key') or config.get('repo_key', '(unset)')}")
    lines.append(f"src_root:    {repo.get('src_root') or config.get('src_root', 'src')}")
    lines.append(f"tests_root:  {repo.get('tests_root') or config.get('tests_root', 'tests')}")

    policy = config.get("policy") or {}
    lines.append(f"min_severity: {policy.get('min_severity', 'low')}")
    ignored_rules = policy.get("ignore_rules", [])
    if ignored_rules:
        lines.append(f"ignore_rules: {', '.join(ignored_rules)}")
    ignored_paths = policy.get("ignore_paths", [])
    if ignored_paths:
        lines.append(f"ignore_paths: {', '.join(ignored_paths)}")

    tools = config.get("tools") or {}
    enabled = [t for t, cfg in tools.items() if cfg.get("enabled", True)]
    disabled = [t for t, cfg in tools.items() if not cfg.get("enabled", True)]
    if enabled:
        lines.append(f"tools on:    {', '.join(enabled)}")
    if disabled:
        lines.append(f"tools off:   {', '.join(disabled)}")

    return lines
