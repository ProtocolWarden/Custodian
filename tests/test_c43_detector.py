# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for C43 detector — json.dump() without ensure_ascii=False."""
from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.code_health import detect_c43
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


def test_json_dump_without_ensure_ascii_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "src/a.py", "import json\njson.dump(data, fp)\n")
    assert detect_c43(_ctx(tmp_path)).count == 1


def test_json_dump_with_ensure_ascii_false_not_flagged(tmp_path: Path) -> None:
    _write(tmp_path, "src/a.py", "import json\njson.dump(data, fp, ensure_ascii=False)\n")
    assert detect_c43(_ctx(tmp_path)).count == 0


def test_json_dump_with_ensure_ascii_true_not_flagged(tmp_path: Path) -> None:
    # Explicit True is a deliberate choice — not flagged.
    _write(tmp_path, "src/a.py", "import json\njson.dump(data, fp, ensure_ascii=True)\n")
    assert detect_c43(_ctx(tmp_path)).count == 0


def test_json_dumps_not_flagged_by_c43(tmp_path: Path) -> None:
    # json.dumps() is covered by C41, not C43.
    _write(tmp_path, "src/a.py", "import json\njson.dumps(data)\n")
    assert detect_c43(_ctx(tmp_path)).count == 0


def test_noqa_suppresses(tmp_path: Path) -> None:
    _write(tmp_path, "src/a.py", "import json\njson.dump(data, fp)  # noqa: C43\n")
    assert detect_c43(_ctx(tmp_path)).count == 0


def test_multiple_violations(tmp_path: Path) -> None:
    src = (
        "import json\n"
        "json.dump(a, f1)\n"
        "json.dump(b, f2, indent=2)\n"
        "json.dump(c, f3, ensure_ascii=False)\n"
    )
    _write(tmp_path, "src/a.py", src)
    assert detect_c43(_ctx(tmp_path)).count == 2


def test_exclude_path_suppresses(tmp_path: Path) -> None:
    _write(tmp_path, "src/legacy.py", "import json\njson.dump(data, fp)\n")
    config = {"audit": {"exclude_paths": {"C43": ["src/legacy.py"]}}}
    assert detect_c43(_ctx(tmp_path, config)).count == 0


def test_sample_format(tmp_path: Path) -> None:
    _write(tmp_path, "src/a.py", "import json\njson.dump(data, fp)\n")
    result = detect_c43(_ctx(tmp_path))
    assert result.count == 1
    assert "json.dump() without ensure_ascii=False" in result.samples[0]


def test_other_dump_method_not_flagged(tmp_path: Path) -> None:
    # obj.dump() with a different object — not json.dump()
    _write(tmp_path, "src/a.py", "pickler.dump(data, fp)\n")
    assert detect_c43(_ctx(tmp_path)).count == 0
