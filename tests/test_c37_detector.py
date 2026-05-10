# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for C37 detector: stale audit config keys."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.code_health import detect_c37
from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.passes.ast_forest import AstForest


def _ctx(tmp_path: Path, yaml_text: str, src_files: dict[str, str] | None = None) -> AuditContext:
    (tmp_path / ".custodian.yaml").write_text(yaml_text, encoding="utf-8")
    forest = AstForest()
    if src_files:
        src_root = tmp_path / "src"
        src_root.mkdir(parents=True, exist_ok=True)
        for rel, content in src_files.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            text = textwrap.dedent(content)
            p.write_text(text, encoding="utf-8")
            forest.trees[p] = ast.parse(text)
            forest.sources[p] = text
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=forest),
    )


class TestC37:
    def test_no_custodian_yaml_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path,
            src_root=tmp_path / "src",
            tests_root=tmp_path / "tests",
            config={},
            plugin_modules=[],
            graph=AnalysisGraph(ast_forest=AstForest()),
        )
        assert detect_c37(ctx).count == 0

    def test_live_key_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, """
audit:
  t3_env_gate_hints:
    - "MY_HINT"
""", {
            "src/detector.py": """
                def check():
                    key = "t3_env_gate_hints"
            """
        })
        assert detect_c37(ctx).count == 0

    def test_stale_key_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, """
audit:
  removed_old_setting: true
""", {
            "src/detector.py": """
                def check():
                    pass
            """
        })
        result = detect_c37(ctx)
        assert result.count == 1
        assert "removed_old_setting" in result.samples[0]

    def test_exclude_paths_key_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, """
audit:
  exclude_paths:
    T1:
      - "src/legacy/**"
""", {
            "src/detector.py": """
                pass
            """
        })
        assert detect_c37(ctx).count == 0

    def test_no_audit_section_returns_zero(self, tmp_path):
        ctx = _ctx(tmp_path, """
tool:
  name: custodian
""")
        assert detect_c37(ctx).count == 0

    def test_multiple_live_keys_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, """
audit:
  t3_env_gate_hints:
    - hint
  t2_timeout: 30
""", {
            "src/checks.py": """
                T3_HINTS = "t3_env_gate_hints"
                T2_LIMIT = "t2_timeout"
            """
        })
        assert detect_c37(ctx).count == 0

    def test_mixed_live_and_stale(self, tmp_path):
        ctx = _ctx(tmp_path, """
audit:
  live_key: true
  ghost_key: false
""", {
            "src/checks.py": """
                KEY = "live_key"
            """
        })
        result = detect_c37(ctx)
        assert result.count == 1
        assert "ghost_key" in result.samples[0]
