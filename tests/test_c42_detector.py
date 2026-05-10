# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for C42 detector — warnings.warn() without stacklevel=."""
from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.code_health import detect_c42
from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.passes.ast_forest import AstForest


def _write(tmp_path: Path, rel: str, src: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")


def _ctx(tmp_path: Path, config: dict | None = None) -> AuditContext:
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=None,
        config=config or {},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=AstForest()),
    )


def test_qualified_warn_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "src/a.py", "import warnings\nwarnings.warn('deprecated')\n")
    assert detect_c42(_ctx(tmp_path)).count == 1


def test_unqualified_warn_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "src/a.py", "from warnings import warn\nwarn('deprecated')\n")
    assert detect_c42(_ctx(tmp_path)).count == 1


def test_warn_with_stacklevel_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "src/a.py", "import warnings\nwarnings.warn('msg', stacklevel=2)\n")
    assert detect_c42(_ctx(tmp_path)).count == 0


def test_warn_with_stacklevel_1_explicit_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "src/a.py", "import warnings\nwarnings.warn('msg', stacklevel=1)\n")
    assert detect_c42(_ctx(tmp_path)).count == 0


def test_warn_with_category_and_stacklevel_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "src/a.py",
        "import warnings\nwarnings.warn('msg', DeprecationWarning, stacklevel=2)\n",
    )
    assert detect_c42(_ctx(tmp_path)).count == 0


def test_other_warn_methods_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "src/a.py", "logger.warn('not a warnings.warn call')\n")
    assert detect_c42(_ctx(tmp_path)).count == 0


def test_noqa_suppresses(tmp_path: Path) -> None:
    _write(tmp_path, "src/a.py", "import warnings\nwarnings.warn('msg')  # noqa: C42\n")
    assert detect_c42(_ctx(tmp_path)).count == 0


def test_multiple_violations(tmp_path: Path) -> None:
    src = (
        "import warnings\n"
        "warnings.warn('a')\n"
        "warnings.warn('b', DeprecationWarning)\n"
        "warnings.warn('c', stacklevel=2)\n"
    )
    _write(tmp_path, "src/a.py", src)
    result = detect_c42(_ctx(tmp_path))
    assert result.count == 2


def test_exclude_path_suppresses(tmp_path: Path) -> None:
    _write(tmp_path, "src/legacy.py", "import warnings\nwarnings.warn('old')\n")
    config = {"audit": {"exclude_paths": {"C42": ["src/legacy.py"]}}}
    assert detect_c42(_ctx(tmp_path, config)).count == 0


def test_sample_format(tmp_path: Path) -> None:
    _write(tmp_path, "src/a.py", "import warnings\nwarnings.warn('deprecated')\n")
    result = detect_c42(_ctx(tmp_path))
    assert result.count == 1
    assert "warnings.warn() without stacklevel=" in result.samples[0]
