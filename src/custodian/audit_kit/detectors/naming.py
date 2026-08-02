# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""N-class detectors — naming convention violations.

Detectors
─────────
N1  Custom exception class with a non-conventional name.  Exception
    subclasses should end in ``Error``, ``Exception``, or ``Warning``
    (following PEP 8 and Python stdlib convention).  Classes whose names
    end with ``Stop``, ``Abort``, ``Cancel``, or ``Signal`` are excluded
    — these are legitimately named control-flow signals, not errors.

N2  Test function in a ``test_*.py`` or ``*_test.py`` file whose name does
    not start with ``test_``.  Pytest only collects functions named
    ``test_*``; a function like ``check_behaviour`` or ``verify_result``
    in a test file is silently skipped — it never executes.  Private helpers
    (starting with ``_``) are excluded — they are intentionally not collected.
    Methods inside test classes are not flagged here (class-level collection
    rules differ).
"""
from __future__ import annotations

import ast
import re

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)

_MAX_SAMPLES = 8

_EXCEPTION_BASES = frozenset({
    "Exception", "BaseException",
    "ValueError", "RuntimeError", "TypeError", "OSError", "IOError",
    "KeyError", "AttributeError", "NotImplementedError", "StopIteration",
    "PermissionError", "FileNotFoundError", "TimeoutError", "ConnectionError",
    "LookupError", "ArithmeticError", "UnicodeError", "ImportError",
    "AssertionError", "EnvironmentError", "IndexError", "NameError",
    "OverflowError", "RecursionError", "SystemError", "ZeroDivisionError",
})

_CONVENTIONAL_SUFFIXES = ("Error", "Exception", "Warning")
_CONTROL_FLOW_SUFFIXES = ("Stop", "Abort", "Cancel", "Signal", "Interrupt")


def build_naming_detectors() -> list[Detector]:
    return [
        # KEEP — no tool equivalent (pytest collection rules)
        Detector("N2", "test function in test file not named test_* (invisible to pytest)",
                 "open", detect_n2, LOW),
        # DEPRECATED — Ruff N818 covers
        Detector("N1", "exception class name does not follow Error/Exception/Warning convention",
                 "open", detect_n1, LOW, deprecated=True),  # Ruff N818
    ]


def detect_n1(context: AuditContext) -> DetectorResult:
    """Flag custom exception classes whose names don't end in Error/Exception/Warning."""
    audit_cfg = context.config.get("audit") or {}
    globs: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("N1") or [])

    from pathlib import PurePosixPath
    from custodian.audit_kit.code_health import _py_files

    samples: list[str] = []
    count = 0

    for path in _py_files(context, "N1"):
        if globs:
            rel = path.relative_to(context.repo_root).as_posix()
            if any(PurePosixPath(rel).match(g) for g in globs):
                continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            base_names: set[str] = set()
            for base in node.bases:
                if isinstance(base, ast.Name):
                    base_names.add(base.id)
                elif isinstance(base, ast.Attribute):
                    base_names.add(base.attr)
            if not (base_names & _EXCEPTION_BASES):
                continue
            name = node.name
            if any(name.endswith(s) for s in _CONVENTIONAL_SUFFIXES):
                continue
            if any(name.endswith(s) for s in _CONTROL_FLOW_SUFFIXES):
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                rel = path.relative_to(context.repo_root)
                samples.append(f"{rel}:{node.lineno}: class {name} (inherits from exception, should end in Error/Exception)")

    return DetectorResult(count=count, samples=samples)


# ── N2 ────────────────────────────────────────────────────────────────────────

_TEST_MODULE_RE = re.compile(r"(^|[\\/])test_[^/\\]+\.py$|[^/\\]+_test\.py$")


def detect_n2(context: AuditContext) -> DetectorResult:
    """Flag module-level functions in test files not named test_* (invisible to pytest).

    Pytest only collects functions whose names start with ``test_``.  A
    function like ``check_foo`` or ``verify_result`` in a test file silently
    never executes — it produces no failure and no collection warning.

    Exclusions:
    - Private helpers (names starting with ``_``)
    - Methods inside classes (class-level collection uses ``Test*`` prefix rules)
    - Common fixture/hook names: ``setup``, ``teardown``, ``conftest``-style names
    - Pytest hook names (``pytest_*``)

    Exclude paths via ``audit.exclude_paths.N2``.
    """
    audit_cfg = context.config.get("audit") or {}
    globs: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("N2") or [])

    from pathlib import PurePosixPath

    _PYTEST_HOOKS = frozenset({
        "setup", "teardown", "setup_module", "teardown_module",
        "setup_function", "teardown_function", "setup_method", "teardown_method",
        "setup_class", "teardown_class",
        "main",
    })

    samples: list[str] = []
    count = 0

    tests_root = context.tests_root
    # Only scan files under tests_root — src files named test_*.py are
    # production code (e.g. test_shape.py detector module), not test files.
    candidates: list = []
    if tests_root.is_dir():
        for path in tests_root.rglob("*.py"):
            rel_str = path.relative_to(context.repo_root).as_posix()
            if globs and any(PurePosixPath(rel_str).match(g) for g in globs):
                continue
            # Only flag functions in files that look like test files, not
            # fixture helpers or conftest.py (which are support infrastructure)
            fname = path.name
            if fname == "conftest.py" or not _TEST_MODULE_RE.search(str(path).replace("\\", "/")):
                continue
            candidates.append(path)

    for path in candidates:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)

        def _is_fixture(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
            for dec in func_node.decorator_list:
                if isinstance(dec, ast.Name) and dec.id == "fixture":
                    return True
                if isinstance(dec, ast.Attribute) and dec.attr == "fixture":
                    return True
                # fixture(scope=...) call form: pytest.fixture decorator used as a call
                if isinstance(dec, ast.Call):
                    f = dec.func
                    if isinstance(f, ast.Name) and f.id == "fixture":
                        return True
                    if isinstance(f, ast.Attribute) and f.attr == "fixture":
                        return True
            return False

        for node in tree.body:  # only module-level
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            name = node.name
            if name.startswith("_"):
                continue  # private helper
            if name.startswith("test_") or name.startswith("pytest_"):
                continue  # correctly named
            if name in _PYTEST_HOOKS:
                continue
            if _is_fixture(node):
                continue  # pytest fixture — intentionally not named test_
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(
                    f"{rel}:{node.lineno}: {name}() — not prefixed test_; pytest will not collect it"
                )

    return DetectorResult(count=count, samples=samples)
