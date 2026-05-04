# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for T6 (untested module), T7 (parallel test file), T8 (dangling test)."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.test_shape import (
    detect_t6,
    detect_t7,
    detect_t8,
)
from custodian.audit_kit.passes.ast_forest import AstForest
from custodian.audit_kit.passes.tests_forest import build_tests_forest


def _write(tmp_path: Path, rel: str, content: str = "") -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


def _ctx(tmp_path: Path, *, config: dict | None = None) -> AuditContext:
    src_root = tmp_path / "src"
    tests_root = tmp_path / "tests"
    src_root.mkdir(parents=True, exist_ok=True)
    tests_root.mkdir(parents=True, exist_ok=True)

    forest = AstForest()
    for path in sorted(src_root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        forest.trees[path] = ast.parse(text)
        forest.sources[path] = text

    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tests_root,
        config=config or {},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=forest, tests_forest=build_tests_forest(tests_root)),
    )


# ─── T6 ─────────────────────────────────────────────────────────────────────


class TestT6UntestedModule:
    def test_module_imported_passes(self, tmp_path: Path):
        _write(tmp_path, "src/foo/__init__.py")
        _write(tmp_path, "src/foo/bar.py", "def hello(): pass")
        _write(tmp_path, "tests/test_bar.py", "from foo.bar import hello\ndef test_x(): assert hello() is None")
        result = detect_t6(_ctx(tmp_path))
        assert result.count == 0

    def test_module_not_imported_flagged(self, tmp_path: Path):
        _write(tmp_path, "src/foo/__init__.py")
        _write(tmp_path, "src/foo/bar.py", "def hello(): pass")
        _write(tmp_path, "tests/test_other.py", "def test_x(): assert True")
        result = detect_t6(_ctx(tmp_path))
        assert result.count == 1
        assert "foo.bar" in result.samples[0]

    def test_init_files_skipped(self, tmp_path: Path):
        _write(tmp_path, "src/foo/__init__.py", "x = 1")
        _write(tmp_path, "src/foo/bar.py", "def hello(): pass")
        _write(tmp_path, "tests/test_bar.py", "from foo.bar import hello\ndef test_x(): assert True")
        # foo (package) IS imported transitively via "from foo.bar"
        result = detect_t6(_ctx(tmp_path))
        assert result.count == 0

    def test_partial_dotted_match_via_prefixes(self, tmp_path: Path):
        # `from foo.bar import x` should mark `foo`, `foo.bar`, `foo.bar.x` as imported
        _write(tmp_path, "src/foo/__init__.py")
        _write(tmp_path, "src/foo/bar.py", "thing = 1")
        _write(tmp_path, "tests/test_x.py", "from foo.bar import thing\ndef test_x(): assert thing == 1")
        result = detect_t6(_ctx(tmp_path))
        assert result.count == 0

    def test_relative_imports_dont_count(self, tmp_path: Path):
        _write(tmp_path, "src/foo/__init__.py")
        _write(tmp_path, "src/foo/bar.py", "def x(): pass")
        # Relative imports in tests are skipped — should still flag foo.bar
        _write(tmp_path, "tests/__init__.py")
        _write(tmp_path, "tests/test_x.py", "from .helpers import h\ndef test_x(): assert True")
        result = detect_t6(_ctx(tmp_path))
        assert result.count >= 1

    def test_exclude_paths(self, tmp_path: Path):
        _write(tmp_path, "src/foo/__init__.py")
        _write(tmp_path, "src/foo/bar.py", "def hello(): pass")
        _write(tmp_path, "tests/test_other.py", "def test_x(): assert True")
        ctx = _ctx(tmp_path, config={"audit": {"exclude_paths": {"T6": ["src/foo/bar.py"]}}})
        result = detect_t6(ctx)
        assert result.count == 0


# ─── T7 ─────────────────────────────────────────────────────────────────────


class TestT7ParallelTestFile:
    def test_flat_test_passes(self, tmp_path: Path):
        _write(tmp_path, "src/foo/bar.py", "def x(): pass")
        _write(tmp_path, "tests/test_bar.py", "def test_x(): assert True")
        result = detect_t7(_ctx(tmp_path))
        assert result.count == 0

    def test_mirrored_unit_test_passes(self, tmp_path: Path):
        _write(tmp_path, "src/foo/bar.py", "def x(): pass")
        _write(tmp_path, "tests/unit/foo/test_bar.py", "def test_x(): assert True")
        result = detect_t7(_ctx(tmp_path))
        assert result.count == 0

    def test_no_test_flagged(self, tmp_path: Path):
        _write(tmp_path, "src/foo/bar.py", "def x(): pass")
        _write(tmp_path, "tests/test_unrelated.py", "def test_x(): assert True")
        result = detect_t7(_ctx(tmp_path))
        assert result.count == 1
        assert "src/foo/bar.py" in result.samples[0]

    def test_init_files_skipped(self, tmp_path: Path):
        _write(tmp_path, "src/foo/__init__.py", "x = 1")
        result = detect_t7(_ctx(tmp_path))
        assert result.count == 0

    def test_dunder_files_skipped(self, tmp_path: Path):
        _write(tmp_path, "src/__main__.py", "if True: pass")
        result = detect_t7(_ctx(tmp_path))
        assert result.count == 0

    def test_custom_test_dirs(self, tmp_path: Path):
        _write(tmp_path, "src/foo/bar.py", "def x(): pass")
        _write(tmp_path, "tests/smoke/test_bar.py", "def test_x(): assert True")
        ctx = _ctx(tmp_path, config={"audit": {"t7_test_dirs": ["smoke"]}})
        result = detect_t7(ctx)
        assert result.count == 0

    def test_exclude_paths(self, tmp_path: Path):
        _write(tmp_path, "src/foo/bar.py", "def x(): pass")
        ctx = _ctx(tmp_path, config={"audit": {"exclude_paths": {"T7": ["src/foo/*.py"]}}})
        result = detect_t7(ctx)
        assert result.count == 0


# ─── T8 ─────────────────────────────────────────────────────────────────────


class TestT8DanglingTest:
    def test_test_imports_src_passes(self, tmp_path: Path):
        _write(tmp_path, "src/foo/__init__.py")
        _write(tmp_path, "src/foo/bar.py", "def x(): pass")
        _write(tmp_path, "tests/test_bar.py", "from foo.bar import x\ndef test_x(): assert True")
        result = detect_t8(_ctx(tmp_path))
        assert result.count == 0

    def test_test_with_no_src_imports_flagged(self, tmp_path: Path):
        _write(tmp_path, "src/foo/__init__.py")
        _write(tmp_path, "src/foo/bar.py", "def x(): pass")
        _write(tmp_path, "tests/test_orphan.py", "import json\ndef test_x(): assert json.dumps({}) == '{}'")
        result = detect_t8(_ctx(tmp_path))
        assert result.count == 1
        assert "test_orphan.py" in result.samples[0]

    def test_conftest_skipped(self, tmp_path: Path):
        _write(tmp_path, "src/foo/__init__.py")
        _write(tmp_path, "tests/conftest.py", "import pytest\n@pytest.fixture\ndef f(): return 1")
        result = detect_t8(_ctx(tmp_path))
        assert result.count == 0

    def test_init_skipped(self, tmp_path: Path):
        _write(tmp_path, "src/foo/__init__.py")
        _write(tmp_path, "tests/__init__.py", "")
        result = detect_t8(_ctx(tmp_path))
        assert result.count == 0

    def test_src_prefix_import_passes(self, tmp_path: Path):
        # Some repos use `from src.foo import x` style.
        _write(tmp_path, "src/foo/__init__.py")
        _write(tmp_path, "src/foo/bar.py", "def x(): pass")
        _write(tmp_path, "tests/test_bar.py", "from src.foo.bar import x\ndef test_x(): assert True")
        result = detect_t8(_ctx(tmp_path))
        assert result.count == 0

    def test_no_src_packages_returns_zero(self, tmp_path: Path):
        # No src/ contents at all → cannot determine packages → no findings.
        _write(tmp_path, "tests/test_orphan.py", "def test_x(): assert True")
        result = detect_t8(_ctx(tmp_path))
        assert result.count == 0

    def test_exempt_via_audit_t8_exempt(self, tmp_path: Path):
        _write(tmp_path, "src/foo/__init__.py")
        _write(tmp_path, "src/foo/bar.py", "def x(): pass")
        _write(tmp_path, "tests/test_orphan.py", "def test_x(): assert True")
        ctx = _ctx(tmp_path, config={"audit": {"t8_exempt": ["tests/test_orphan.py"]}})
        result = detect_t8(ctx)
        assert result.count == 0
