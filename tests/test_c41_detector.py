# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for C41 detector — json.dumps() without ensure_ascii=False."""
from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.code_health import detect_c41
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


class TestC41Detector:
    def test_no_json_dumps_clean(self, tmp_path):
        _write(tmp_path, "src/mod.py", "x = 1\n")
        assert detect_c41(_ctx(tmp_path)).count == 0

    def test_json_dumps_without_ensure_ascii_flagged(self, tmp_path):
        _write(tmp_path, "src/mod.py", "import json\nout = json.dumps(data)\n")
        result = detect_c41(_ctx(tmp_path))
        assert result.count == 1

    def test_json_dumps_ensure_ascii_false_not_flagged(self, tmp_path):
        _write(tmp_path, "src/mod.py", "import json\nout = json.dumps(data, ensure_ascii=False)\n")
        assert detect_c41(_ctx(tmp_path)).count == 0

    def test_json_dumps_ensure_ascii_true_not_flagged(self, tmp_path):
        # Explicit ensure_ascii=True is a deliberate choice — not flagged
        _write(tmp_path, "src/mod.py", "import json\nout = json.dumps(data, ensure_ascii=True)\n")
        assert detect_c41(_ctx(tmp_path)).count == 0

    def test_json_dumps_sort_keys_no_ensure_ascii_flagged(self, tmp_path):
        _write(tmp_path, "src/mod.py", "import json\nout = json.dumps(data, sort_keys=True)\n")
        assert detect_c41(_ctx(tmp_path)).count == 1

    def test_json_dumps_with_ensure_ascii_variable_not_flagged(self, tmp_path):
        # ensure_ascii=some_variable — treated as potentially False, not flagged
        _write(tmp_path, "src/mod.py", "import json\nout = json.dumps(data, ensure_ascii=flag)\n")
        assert detect_c41(_ctx(tmp_path)).count == 0

    def test_from_json_import_dumps_flagged(self, tmp_path):
        _write(tmp_path, "src/mod.py", "from json import dumps\nout = dumps(data)\n")
        assert detect_c41(_ctx(tmp_path)).count == 1

    def test_from_json_import_dumps_with_ensure_ascii_false_not_flagged(self, tmp_path):
        _write(tmp_path, "src/mod.py", "from json import dumps\nout = dumps(data, ensure_ascii=False)\n")
        assert detect_c41(_ctx(tmp_path)).count == 0

    def test_multiple_dumps_counted(self, tmp_path):
        src = (
            "import json\n"
            "a = json.dumps(x)\n"
            "b = json.dumps(y)\n"
            "c = json.dumps(z, ensure_ascii=False)\n"
        )
        _write(tmp_path, "src/mod.py", src)
        assert detect_c41(_ctx(tmp_path)).count == 2

    def test_noqa_suppressed(self, tmp_path):
        _write(tmp_path, "src/mod.py", "import json\nout = json.dumps(data)  # noqa: C41\n")
        assert detect_c41(_ctx(tmp_path)).count == 0

    def test_sample_includes_file_and_line(self, tmp_path):
        _write(tmp_path, "src/mod.py", "import json\nout = json.dumps(data)\n")
        result = detect_c41(_ctx(tmp_path))
        assert result.count == 1
        assert "src/mod.py:2" in result.samples[0]
        assert "ensure_ascii" in result.samples[0]

    def test_unrelated_dumps_method_not_flagged(self, tmp_path):
        # obj.dumps() that is not json.dumps
        _write(tmp_path, "src/mod.py", "out = serializer.dumps(data)\n")
        assert detect_c41(_ctx(tmp_path)).count == 0

    def test_empty_file_clean(self, tmp_path):
        _write(tmp_path, "src/mod.py", "")
        assert detect_c41(_ctx(tmp_path)).count == 0
