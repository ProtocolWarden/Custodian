# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for U4 detector: Protocol implementation gaps."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.stubs import detect_u4
from custodian.audit_kit.passes.ast_forest import AstForest


def _forest_from_source(src: str, tmp_path: Path, name: str = "module.py") -> AstForest:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    path = src_root / name
    text = textwrap.dedent(src)
    path.write_text(text, encoding="utf-8")
    forest = AstForest()
    forest.trees[path] = ast.parse(text)
    forest.sources[path] = text
    return forest


def _ctx(tmp_path: Path, forest: AstForest) -> AuditContext:
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=forest),
    )


class TestU4:
    def test_no_forest_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path,
            src_root=tmp_path / "src",
            tests_root=tmp_path / "tests",
            config={},
            plugin_modules=[],
            graph=AnalysisGraph(ast_forest=None),
        )
        assert detect_u4(ctx).count == 0

    def test_complete_implementation_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            from typing import Protocol

            class Doer(Protocol):
                def do_it(self) -> None: ...
                def undo_it(self) -> None: ...

            class ConcreteDoer(Doer):
                def do_it(self) -> None:
                    pass
                def undo_it(self) -> None:
                    pass
        """, tmp_path)
        assert detect_u4(_ctx(tmp_path, forest)).count == 0

    def test_missing_method_flagged(self, tmp_path):
        forest = _forest_from_source("""
            from typing import Protocol

            class Doer(Protocol):
                def do_it(self) -> None: ...
                def undo_it(self) -> None: ...

            class PartialDoer(Doer):
                def do_it(self) -> None:
                    pass
        """, tmp_path)
        result = detect_u4(_ctx(tmp_path, forest))
        assert result.count == 1
        assert "undo_it" in result.samples[0]

    def test_dunder_methods_ignored(self, tmp_path):
        forest = _forest_from_source("""
            from typing import Protocol

            class Sized(Protocol):
                def __len__(self) -> int: ...

            class Bag(Sized):
                pass
        """, tmp_path)
        assert detect_u4(_ctx(tmp_path, forest)).count == 0

    def test_class_inheriting_non_protocol_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            class Base:
                def do_it(self) -> None: ...

            class Child(Base):
                pass
        """, tmp_path)
        assert detect_u4(_ctx(tmp_path, forest)).count == 0

    def test_protocol_class_itself_not_flagged(self, tmp_path):
        forest = _forest_from_source("""
            from typing import Protocol

            class MyProtocol(Protocol):
                def act(self) -> None: ...

            class ExtendedProtocol(MyProtocol, Protocol):
                def extra(self) -> None: ...
        """, tmp_path)
        assert detect_u4(_ctx(tmp_path, forest)).count == 0

    def test_multiple_missing_methods_counted_once_per_class(self, tmp_path):
        forest = _forest_from_source("""
            from typing import Protocol

            class Full(Protocol):
                def a(self) -> None: ...
                def b(self) -> None: ...
                def c(self) -> None: ...

            class Empty(Full):
                pass
        """, tmp_path)
        result = detect_u4(_ctx(tmp_path, forest))
        assert result.count == 1

    def test_overload_not_required(self, tmp_path):
        forest = _forest_from_source("""
            from typing import Protocol, overload

            class Converter(Protocol):
                @overload
                def convert(self, x: int) -> str: ...
                @overload
                def convert(self, x: str) -> int: ...
                def convert(self, x): ...

            class MyConverter(Converter):
                def convert(self, x):
                    return str(x)
        """, tmp_path)
        assert detect_u4(_ctx(tmp_path, forest)).count == 0
