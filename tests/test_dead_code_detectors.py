# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for D-class and F-class detectors: D2, D4, F2."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path


from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.dead_code import detect_d1, detect_d4, detect_d5, detect_d6, detect_f2, detect_f3
from custodian.audit_kit.passes.ast_forest import AstForest
from custodian.audit_kit.passes.call_graph import build_call_graph


def _forest_from_source(src: str, tmp_path: Path, name: str = "module.py") -> AstForest:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    path = src_root / name
    src = textwrap.dedent(src)
    path.write_text(src, encoding="utf-8")
    tree = ast.parse(src)
    forest = AstForest()
    forest.trees[path] = tree
    forest.sources[path] = src
    return forest


def _make_context(tmp_path: Path, forest: AstForest) -> AuditContext:
    graph = AnalysisGraph(ast_forest=forest)
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=graph,
    )


# D2 (unnecessary else after terminal if-branch) was retired 2026-05-05.


# ── D4 tests ──────────────────────────────────────────────────────────────────

class TestD4:
    def test_no_forest_returns_zero(self, tmp_path):
        ctx = _make_context(tmp_path, AstForest())
        ctx.graph = AnalysisGraph(ast_forest=None)
        assert detect_d4(ctx).count == 0

    def test_code_after_return_flagged(self, tmp_path):
        forest = _forest_from_source("""
            def foo():
                return 1
                x = 2
        """, tmp_path)
        result = detect_d4(_make_context(tmp_path, forest))
        assert result.count == 1

    def test_code_after_raise_flagged(self, tmp_path):
        forest = _forest_from_source("""
            def foo():
                raise ValueError
                return 1
        """, tmp_path)
        result = detect_d4(_make_context(tmp_path, forest))
        assert result.count == 1

    def test_no_unreachable_code_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            def foo():
                x = 1
                return x
        """, tmp_path)
        result = detect_d4(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_conditional_return_not_flagged(self, tmp_path):
        # return inside an if — code after is reachable
        forest = _forest_from_source("""
            def foo(x):
                if x < 0:
                    return -1
                return x
        """, tmp_path)
        result = detect_d4(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_unreachable_in_nested_block(self, tmp_path):
        forest = _forest_from_source("""
            def foo(items):
                for item in items:
                    return item
                    x = 1
        """, tmp_path)
        result = detect_d4(_make_context(tmp_path, forest))
        assert result.count == 1

    def test_async_function_flagged(self, tmp_path):
        forest = _forest_from_source("""
            async def foo():
                return 1
                await something()
        """, tmp_path)
        result = detect_d4(_make_context(tmp_path, forest))
        assert result.count == 1

    def test_sample_text_contains_function_name(self, tmp_path):
        forest = _forest_from_source("""
            def dead_zone():
                return 0
                print("never")
        """, tmp_path)
        result = detect_d4(_make_context(tmp_path, forest))
        assert result.count == 1
        assert "dead_zone" in result.samples[0]


# ── F2 tests ──────────────────────────────────────────────────────────────────

class TestF2:
    def test_no_forest_returns_zero(self, tmp_path):
        ctx = _make_context(tmp_path, AstForest())
        ctx.graph = AnalysisGraph(ast_forest=None)
        assert detect_f2(ctx).count == 0

    def test_unused_private_constant_flagged(self, tmp_path):
        forest = _forest_from_source("""
            _THRESHOLD = 0.5
        """, tmp_path)
        result = detect_f2(_make_context(tmp_path, forest))
        assert result.count == 1

    def test_used_private_constant_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            _THRESHOLD = 0.5

            def check(x):
                return x > _THRESHOLD
        """, tmp_path)
        result = detect_f2(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_public_constant_not_flagged(self, tmp_path):
        # F2 only matches _PRIVATE_CAPS (leading underscore required)
        forest = _forest_from_source("""
            THRESHOLD = 0.5
        """, tmp_path)
        result = detect_f2(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_exported_via_all_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            _THRESHOLD = 0.5
            __all__ = ["_THRESHOLD"]
        """, tmp_path)
        result = detect_f2(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_annotated_assignment_flagged(self, tmp_path):
        forest = _forest_from_source("""
            _LIMIT: int = 10
        """, tmp_path)
        result = detect_f2(_make_context(tmp_path, forest))
        assert result.count == 1

    def test_mixed_caps_lowercase_not_flagged(self, tmp_path):
        # _CamelCase or _mixed_lower don't match _ALL_CAPS pattern
        forest = _forest_from_source("""
            _my_value = 1
            _MyClass = object
        """, tmp_path)
        result = detect_f2(_make_context(tmp_path, forest))
        assert result.count == 0

    def test_sample_text_contains_name(self, tmp_path):
        forest = _forest_from_source("""
            _DEAD_CONSTANT = 42
        """, tmp_path)
        result = detect_f2(_make_context(tmp_path, forest))
        assert result.count == 1
        assert "_DEAD_CONSTANT" in result.samples[0]


def _cg_context(tmp_path: Path, src_text: str) -> AuditContext:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    (src_root / "module.py").write_text(textwrap.dedent(src_text), encoding="utf-8")
    cg = build_call_graph(src_root)
    from custodian.audit_kit.detector import AnalysisGraph
    graph = AnalysisGraph(call_graph=cg)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=graph,
    )


class TestD1:
    def test_uncalled_public_function_flagged(self, tmp_path):
        ctx = _cg_context(tmp_path, "def orphan_func():\n    pass\n")
        assert detect_d1(ctx).count == 1

    def test_called_function_not_flagged(self, tmp_path):
        ctx = _cg_context(tmp_path, "def used():\n    pass\nused()\n")
        assert detect_d1(ctx).count == 0

    def test_private_function_not_flagged(self, tmp_path):
        ctx = _cg_context(tmp_path, "def _private():\n    pass\n")
        assert detect_d1(ctx).count == 0

    def test_framework_decorated_function_not_flagged(self, tmp_path):
        src = "app = object()\n\n@app.command('run')\ndef cmd_run():\n    pass\n"
        ctx = _cg_context(tmp_path, src)
        assert detect_d1(ctx).count == 0

    def test_pytest_decorated_function_not_flagged(self, tmp_path):
        src = "import pytest\n\n@pytest.fixture\ndef my_fixture():\n    pass\n"
        ctx = _cg_context(tmp_path, src)
        assert detect_d1(ctx).count == 0


# ── D5 helpers ────────────────────────────────────────────────────────────────

def _d5_context(tmp_path: Path, src_text: str) -> AuditContext:
    """Build an AuditContext with both call_graph and ast_forest populated."""
    import ast as _ast
    from custodian.audit_kit.passes.ast_forest import AstForest

    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    path = src_root / "module.py"
    src_dedented = textwrap.dedent(src_text)
    path.write_text(src_dedented, encoding="utf-8")

    cg = build_call_graph(src_root)
    forest = AstForest()
    tree = _ast.parse(src_dedented)
    forest.trees[path] = tree
    forest.sources[path] = src_dedented

    graph = AnalysisGraph(call_graph=cg, ast_forest=forest)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=graph,
    )


class TestD5:
    def test_unreferenced_class_flagged(self, tmp_path):
        ctx = _d5_context(tmp_path, "class Orphan:\n    pass\n")
        assert detect_d5(ctx).count == 1

    def test_instantiated_class_not_flagged(self, tmp_path):
        ctx = _d5_context(tmp_path, "class Used:\n    pass\nobj = Used()\n")
        assert detect_d5(ctx).count == 0

    def test_private_class_not_flagged(self, tmp_path):
        ctx = _d5_context(tmp_path, "class _Internal:\n    pass\n")
        assert detect_d5(ctx).count == 0

    def test_test_class_not_flagged(self, tmp_path):
        ctx = _d5_context(tmp_path, "class TestFoo:\n    pass\n")
        assert detect_d5(ctx).count == 0

    def test_exception_class_not_flagged(self, tmp_path):
        ctx = _d5_context(tmp_path, "class FooError(Exception):\n    pass\n")
        assert detect_d5(ctx).count == 0

    def test_protocol_class_not_flagged(self, tmp_path):
        src = "from typing import Protocol\nclass MyPort(Protocol):\n    def do(self) -> None: ...\n"
        ctx = _d5_context(tmp_path, src)
        assert detect_d5(ctx).count == 0

    def test_abc_class_not_flagged(self, tmp_path):
        src = "from abc import ABC\nclass MyBase(ABC):\n    pass\n"
        ctx = _d5_context(tmp_path, src)
        assert detect_d5(ctx).count == 0

    def test_class_in_all_not_flagged(self, tmp_path):
        src = '__all__ = ["MyClass"]\nclass MyClass:\n    pass\n'
        ctx = _d5_context(tmp_path, src)
        assert detect_d5(ctx).count == 0

    def test_subclassed_class_not_flagged(self, tmp_path):
        ctx = _d5_context(tmp_path, "class Base:\n    pass\nclass Child(Base):\n    pass\n")
        # Base is referenced as a base class (Name Load); Child is unreferenced
        result = detect_d5(ctx)
        names = " ".join(result.samples)
        assert "Base" not in names
        assert "Child" in names

    def test_no_graph_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path,
            src_root=tmp_path / "src",
            tests_root=tmp_path / "tests",
            config={},
            plugin_modules=[],
            graph=None,
        )
        assert detect_d5(ctx).count == 0


# ── D6 helpers ────────────────────────────────────────────────────────────────

def _d6_context(
    tmp_path: Path,
    src_text: str,
    extra_constructed: set[str] | None = None,
    extra_called: set[str] | None = None,
) -> AuditContext:
    """Build an AuditContext with call_graph and ast_forest for D6 tests.

    extra_constructed and extra_called allow injecting names directly into the
    call graph to simulate annotation-only references without constructing.
    """
    import ast as _ast
    from custodian.audit_kit.passes.ast_forest import AstForest

    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    path = src_root / "module.py"
    src_dedented = textwrap.dedent(src_text)
    path.write_text(src_dedented, encoding="utf-8")

    cg = build_call_graph(src_root)

    if extra_called:
        cg.called_names.update(extra_called)
    if extra_constructed:
        cg.constructed_names.update(extra_constructed)

    forest = AstForest()
    tree = _ast.parse(src_dedented)
    forest.trees[path] = tree
    forest.sources[path] = src_dedented

    graph = AnalysisGraph(call_graph=cg, ast_forest=forest)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=graph,
    )


class TestD6:
    def test_unreferenced_class_not_flagged_by_d6(self, tmp_path):
        # D5 catches unreferenced classes; D6 must NOT double-flag them
        ctx = _d6_context(tmp_path, "class Orphan:\n    pass\n")
        assert detect_d6(ctx).count == 0

    def test_instantiated_class_not_flagged(self, tmp_path):
        ctx = _d6_context(tmp_path, "class Used:\n    pass\nobj = Used()\n")
        assert detect_d6(ctx).count == 0

    def test_annotation_only_class_flagged(self, tmp_path):
        # MyDto is referenced (in called_names) but never constructed
        src = "class MyDto:\n    pass\n"
        ctx = _d6_context(tmp_path, src, extra_called={"MyDto"})
        # constructed_names does NOT include MyDto — should be flagged
        assert detect_d6(ctx).count == 1

    def test_annotation_only_sample_message(self, tmp_path):
        src = "class MyDto:\n    pass\n"
        ctx = _d6_context(tmp_path, src, extra_called={"MyDto"})
        result = detect_d6(ctx)
        assert result.count == 1
        assert "MyDto" in result.samples[0]
        assert "never constructed" in result.samples[0]

    def test_private_class_not_flagged(self, tmp_path):
        src = "class _Internal:\n    pass\n"
        ctx = _d6_context(tmp_path, src, extra_called={"_Internal"})
        assert detect_d6(ctx).count == 0

    def test_test_class_not_flagged(self, tmp_path):
        src = "class TestFoo:\n    pass\n"
        ctx = _d6_context(tmp_path, src, extra_called={"TestFoo"})
        assert detect_d6(ctx).count == 0

    def test_exception_class_not_flagged(self, tmp_path):
        src = "class FooError(Exception):\n    pass\n"
        ctx = _d6_context(tmp_path, src, extra_called={"FooError"})
        assert detect_d6(ctx).count == 0

    def test_protocol_class_not_flagged(self, tmp_path):
        src = "from typing import Protocol\nclass MyPort(Protocol):\n    def do(self) -> None: ...\n"
        ctx = _d6_context(tmp_path, src, extra_called={"MyPort"})
        assert detect_d6(ctx).count == 0

    def test_abc_class_not_flagged(self, tmp_path):
        src = "from abc import ABC\nclass MyBase(ABC):\n    pass\n"
        ctx = _d6_context(tmp_path, src, extra_called={"MyBase"})
        assert detect_d6(ctx).count == 0

    def test_no_graph_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path,
            src_root=tmp_path / "src",
            tests_root=tmp_path / "tests",
            config={},
            plugin_modules=[],
            graph=None,
        )
        assert detect_d6(ctx).count == 0


# ── F3 tests ──────────────────────────────────────────────────────────────────

class TestF3:
    def _ctx(self, src: str, tmp_path: Path) -> AuditContext:
        src_root = tmp_path / "src"
        src_root.mkdir(parents=True, exist_ok=True)
        path = src_root / "mod.py"
        src = textwrap.dedent(src)
        path.write_text(src, encoding="utf-8")
        cg = build_call_graph(src_root)
        return AuditContext(
            repo_root=tmp_path, src_root=src_root, tests_root=tmp_path / "tests",
            config={}, plugin_modules=[],
            graph=AnalysisGraph(call_graph=cg),
        )

    def test_no_call_graph_returns_zero(self, tmp_path):
        ctx = AuditContext(repo_root=tmp_path, src_root=tmp_path/"src", tests_root=tmp_path/"tests",
                          config={}, plugin_modules=[], graph=AnalysisGraph(call_graph=None))
        assert detect_f3(ctx).count == 0

    def test_accessed_field_not_flagged(self, tmp_path):
        ctx = self._ctx("""
from pydantic import BaseModel
class Foo(BaseModel):
    name: str
def use(f: Foo):
    return f.name
""", tmp_path)
        assert detect_f3(ctx).count == 0

    def test_never_accessed_field_flagged(self, tmp_path):
        ctx = self._ctx("""
from pydantic import BaseModel
class Foo(BaseModel):
    name: str
    dead_field: int
def use(f: Foo):
    return f.name
""", tmp_path)
        result = detect_f3(ctx)
        assert result.count == 1
        assert "dead_field" in result.samples[0]

    def test_kwarg_set_not_flagged(self, tmp_path):
        # Setting via constructor kwarg counts as usage
        ctx = self._ctx("""
from pydantic import BaseModel
class Foo(BaseModel):
    name: str
f = Foo(name="hello")
""", tmp_path)
        assert detect_f3(ctx).count == 0

    def test_private_field_not_flagged(self, tmp_path):
        ctx = self._ctx("""
from pydantic import BaseModel
class Foo(BaseModel):
    _private: str
""", tmp_path)
        assert detect_f3(ctx).count == 0

    def test_non_basemodel_not_flagged(self, tmp_path):
        ctx = self._ctx("""
class Foo:
    dead_field: int
""", tmp_path)
        assert detect_f3(ctx).count == 0

    def test_dynamic_getattr_self_not_flagged(self, tmp_path):
        # getattr(self, key) where key is a variable — all fields implicitly live
        ctx = self._ctx("""
from pydantic import BaseModel
class Settings(BaseModel):
    policy_path: str
    timeout: int
    def resolve(self, attr: str):
        return getattr(self, attr)
""", tmp_path)
        assert detect_f3(ctx).count == 0

    def test_model_validate_class_not_flagged(self, tmp_path):
        # ClassName.model_validate(...) marks all fields as schema fields
        ctx = self._ctx("""
from pydantic import BaseModel
class RunStatus(BaseModel):
    current_phase: str
    version: int

status = RunStatus.model_validate({"current_phase": "done", "version": 1})
""", tmp_path)
        assert detect_f3(ctx).count == 0

    def test_nested_model_in_validated_class_not_flagged(self, tmp_path):
        # Fields in nested Pydantic models under a model_validate'd class are also schema fields
        ctx = self._ctx("""
from pydantic import BaseModel
class Step(BaseModel):
    field_name: str
    phase_required: str
class Config(BaseModel):
    step: Step

cfg = Config.model_validate({"step": {"field_name": "x"}})
""", tmp_path)
        assert detect_f3(ctx).count == 0
