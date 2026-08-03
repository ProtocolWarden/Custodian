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
      exclude_paths: {C2: [...]}
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
      architecture:
        rules: [...]
    reports:
      formats: [json, sarif]
      output_dir: ".custodian/reports"

Path scoping
────────────
There is no repo-wide "ignore these paths" key. Path exemptions are
PER-DETECTOR, via ``audit.exclude_paths`` — a mapping of detector id to
globs, applied by ``audit_kit.code_health._exclude_globs`` and validated
by ``custodian doctor``::

    audit:
      exclude_paths:
        C2: ["src/cli/**"]
        T6: ["src/legacy/**"]

An ``audit.ignore_paths`` key was parsed into ``policy`` and echoed by
``config_summary`` until 2026-08-03, but nothing ever read it to filter a
finding — a repo that set it saw its exemptions confirmed in the summary
while every finding under those paths kept reporting. It was REMOVED
rather than implemented: detector findings carry no structured path
(``DetectorResult`` is a count plus free-form sample strings, capped at
8), so a path filter could suppress samples but never correct the count.
See ``tests/test_config_loader.py::TestIgnorePathsRemoved``.
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


def find_duplicate_keys(text: str) -> list[str]:
    """Return dotted paths of keys that appear more than once in the same mapping.

    PyYAML's ``safe_load`` silently keeps the LAST of a duplicate pair, so a second
    ``audit:`` / ``capabilities:`` block can drop an ``enforce: true`` or a
    suppression with no error — exactly the PrivateManifest incident where duplicate
    ``audit:`` keys silently disabled findings. ``compose`` preserves the raw node
    tree (pre-collapse), so duplicates are visible here even though the loaded dict
    has already lost them. Returns [] on malformed YAML (a separate concern).
    """
    if yaml is None:  # pragma: no cover
        return []
    try:
        root = yaml.compose(text)
    except yaml.YAMLError:
        return []
    # Capture the node classes as locals here (yaml is narrowed non-None in this
    # scope); the closure below would otherwise see yaml as `Any | None`.
    mapping_node = yaml.MappingNode
    sequence_node = yaml.SequenceNode
    dups: list[str] = []

    def _walk(node: object, prefix: str) -> None:
        if isinstance(node, mapping_node):
            seen: set[str] = set()
            for key_node, val_node in node.value:
                key = getattr(key_node, "value", None)
                if not isinstance(key, str):
                    continue
                path = f"{prefix}{key}"
                if key in seen:
                    dups.append(path)
                seen.add(key)
                _walk(val_node, f"{path}.")
        elif isinstance(node, sequence_node):
            for i, item in enumerate(node.value):
                _walk(item, f"{prefix}{i}.")

    if root is not None:
        _walk(root, "")
    return dups


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


def has_ignore_paths(config: dict) -> bool:
    """True if the config still carries the retired ``ignore_paths`` key.

    Both spellings are checked because ``config_summary`` is handed the RAW
    file dict by ``custodian-config show`` (v0 puts the key under ``audit``)
    as well as dicts that went through ``_normalize_v0`` (v1 spelling, under
    ``policy``). Callers use this to WARN — the key filters nothing, and
    saying so is the point of removing it. See the module docstring.
    """
    for section in ("audit", "policy"):
        block = config.get(section)
        if isinstance(block, dict) and block.get("ignore_paths"):
            return True
    return False


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
    if has_ignore_paths(config):
        # Deliberately NOT an echo of the configured globs. Listing them back
        # reads as confirmation the exemption took effect, which is exactly the
        # false signal this key gave for its whole life.
        lines.append(
            "WARNING: audit.ignore_paths is not a supported key — it filters "
            "nothing. Use per-detector audit.exclude_paths instead."
        )

    tools = config.get("tools") or {}
    enabled = [t for t, cfg in tools.items() if cfg.get("enabled", True)]
    disabled = [t for t, cfg in tools.items() if not cfg.get("enabled", True)]
    if enabled:
        lines.append(f"tools on:    {', '.join(enabled)}")
    if disabled:
        lines.append(f"tools off:   {', '.join(disabled)}")

    return lines
