# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for K4 — docstring/signature type drift."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.docs import (
    _normalise_type,
    _types_equivalent,
    detect_k4,
)


class TestNormaliseType:
    @pytest.mark.parametrize("raw,expected", [
        ("str", "str"),
        ("Optional[str]", "str | None"),
        ("Optional[ str ]", "str | None"),
        ("List[int]", "list[int]"),
        ("Dict[str, int]", "dict[str, int]"),
        ("str  |None", "str | None"),
        ("str|None", "str | None"),
        ("Tuple[int, str]", "tuple[int, str]"),
    ])
    def test_normalisation(self, raw, expected):
        assert _normalise_type(raw) == expected


class TestTypesEquivalent:
    @pytest.mark.parametrize("a,b", [
        ("str", "str"),
        ("Optional[int]", "int | None"),
        ("List[str]", "list[str]"),
        ("string", "str"),
        ("integer", "int"),
        ("Dict[str, int]", "dict[str, int]"),
        ("Optional[List[str]]", "list[str] | None"),
    ])
    def test_equivalent(self, a, b):
        assert _types_equivalent(a, b)
        assert _types_equivalent(b, a)

    @pytest.mark.parametrize("a,b", [
        ("str", "int"),
        ("list[str]", "list[int]"),
        ("Optional[str]", "Optional[int]"),
        ("dict[str, int]", "dict[str, str]"),
    ])
    def test_not_equivalent(self, a, b):
        assert not _types_equivalent(a, b)

    def test_either_missing_silent(self):
        # K4 only catches drift; missing types are E1/K3 territory.
        assert _types_equivalent("str", "")
        assert _types_equivalent("", "str")


def _ctx(tmp_path: Path, src: str) -> AuditContext:
    src_dir = tmp_path / "src"
    src_dir.mkdir()
    (src_dir / "module.py").write_text(textwrap.dedent(src))
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_dir,
        tests_root=tmp_path / "tests",
        config={},
        graph=None,
        plugin_modules=[],
    )


class TestDetectK4:
    def test_no_drift(self, tmp_path):
        ctx = _ctx(tmp_path, '''
            def f(count: int) -> None:
                """Do.

                Args:
                    count (int): how many.
                """
        ''')
        assert detect_k4(ctx).count == 0

    def test_type_drift_caught(self, tmp_path):
        ctx = _ctx(tmp_path, '''
            def f(count: int) -> None:
                """Do.

                Args:
                    count (str): how many.
                """
        ''')
        result = detect_k4(ctx)
        assert result.count == 1
        assert "count" in result.samples[0]
        assert "str" in result.samples[0]
        assert "int" in result.samples[0]

    def test_optional_alias_no_drift(self, tmp_path):
        ctx = _ctx(tmp_path, '''
            from typing import Optional
            def f(name: Optional[str]) -> None:
                """Do.

                Args:
                    name (str | None): the name.
                """
        ''')
        assert detect_k4(ctx).count == 0

    def test_doc_untyped_silent(self, tmp_path):
        # Param documented but with no type — K3 territory, not K4.
        ctx = _ctx(tmp_path, '''
            def f(count: int) -> None:
                """Do.

                Args:
                    count: how many.
                """
        ''')
        assert detect_k4(ctx).count == 0

    def test_sig_unannotated_silent(self, tmp_path):
        # Param not annotated in signature — E1 territory, not K4.
        ctx = _ctx(tmp_path, '''
            def f(count) -> None:
                """Do.

                Args:
                    count (int): how many.
                """
        ''')
        assert detect_k4(ctx).count == 0
