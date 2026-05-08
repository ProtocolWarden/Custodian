# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""E-class detectors — env-var contract enforcement.

  E1  Env-var drift — every key read by src via os.environ.get/os.getenv/
                      os.environ[...] must appear in .env.example so that the
                      env-var contract is documented. Well-known system vars are
                      exempt. Configure additional skip_keys under envvar: in
                      .custodian/config.yaml.

                      Silently skips when .env.example is absent (W5 covers
                      the missing-example gap).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from custodian.audit_kit.detector import AuditContext, Detector, DetectorResult, LOW

_SYSTEM_VARS: frozenset[str] = frozenset({
    # Standard Unix
    "HOME", "PATH", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "LC_MESSAGES",
    "TERM", "TMPDIR", "TMP", "TEMP", "PWD", "OLDPWD", "HOSTNAME",
    # Color / display
    "NO_COLOR", "COLORTERM", "DISPLAY", "FORCE_COLOR", "TERM_PROGRAM",
    # CI / GitHub Actions
    "CI", "GITHUB_ACTIONS", "GITHUB_TOKEN", "GITHUB_SHA",
    "GITHUB_WORKFLOW", "GITHUB_REF", "GITHUB_RUN_ID",
    # Python runtime
    "PYTHONPATH", "VIRTUAL_ENV", "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED",
    # XDG
    "XDG_RUNTIME_DIR", "XDG_DATA_HOME", "XDG_CONFIG_HOME",
})

# Lines in .env.example that document a key, including commented-out examples.
_EXAMPLE_KEY_RE = re.compile(r"^#?\s*([A-Z][A-Z0-9_]+)\s*=", re.MULTILINE)


def _collect_env_keys_from_src(src_root: Path) -> dict[str, list[str]]:
    """Return {KEY: [file:lineno, ...]} for all env keys read by src code."""
    results: dict[str, list[str]] = {}
    for py_file in src_root.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        rel = str(py_file)
        for node in ast.walk(tree):
            key = _extract_env_key(node)
            if key:
                results.setdefault(key, []).append(f"{rel}:{node.lineno}")
    return results


def _extract_env_key(node: ast.AST) -> str | None:
    """Extract a string env key from os.environ.get(...), os.getenv(...),
    or os.environ[...] AST nodes."""
    # os.environ.get("KEY") or os.environ.get("KEY", default)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and isinstance(node.func.value, ast.Attribute)
        and node.func.value.attr == "environ"
        and isinstance(node.func.value.value, ast.Name)
        and node.func.value.value.id == "os"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        return node.args[0].value

    # os.getenv("KEY") or os.getenv("KEY", default)
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "getenv"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        return node.args[0].value

    # os.environ["KEY"]
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.value, ast.Attribute)
        and node.value.attr == "environ"
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "os"
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
    ):
        return node.slice.value

    return None


def _collect_example_keys(env_example: Path) -> frozenset[str]:
    """Return all key names documented in .env.example."""
    try:
        text = env_example.read_text(encoding="utf-8")
    except OSError:
        return frozenset()
    return frozenset(m.group(1) for m in _EXAMPLE_KEY_RE.finditer(text))


def _parse_config(config: dict) -> frozenset[str]:
    """Return extra skip_keys from envvar: config block."""
    block = config.get("envvar") or {}
    return frozenset(block.get("skip_keys") or [])


def detect_e1(context: AuditContext) -> DetectorResult:
    env_example = context.repo_root / ".env.example"
    if not env_example.exists():
        return DetectorResult(count=0, samples=[])

    documented = _collect_example_keys(env_example)
    extra_skip = _parse_config(context.config)
    skip = _SYSTEM_VARS | extra_skip

    used = _collect_env_keys_from_src(context.src_root)
    missing: list[str] = []
    for key, locations in sorted(used.items()):
        if key in skip or key in documented:
            continue
        missing.append(f"{key} (used at {locations[0]}) not in .env.example")

    return DetectorResult(count=len(missing), samples=missing)


def build_envvar_detectors() -> list[Detector]:
    return [
        Detector(
            "E1",
            "env key read by src not documented in .env.example",
            "open",
            detect_e1,
            LOW,
        ),
    ]
