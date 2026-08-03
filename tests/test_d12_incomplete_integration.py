# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for D12 — public src symbol tested but never wired into production."""
from __future__ import annotations

import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.dead_code import detect_d12
from custodian.audit_kit.passes.ast_forest import build_ast_forest
from custodian.audit_kit.passes.tests_forest import build_tests_forest


def _ctx(
    tmp_path: Path,
    src_files: dict[str, str],
    test_files: dict[str, str],
    *,
    config: dict | None = None,
) -> AuditContext:
    src_dir = tmp_path / "src"
    src_dir.mkdir(exist_ok=True)
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir(exist_ok=True)
    for name, body in src_files.items():
        (src_dir / name).write_text(textwrap.dedent(body), encoding="utf-8")
    for name, body in test_files.items():
        (tests_dir / name).write_text(textwrap.dedent(body), encoding="utf-8")

    class _Graph:
        def __init__(self, af, tf):
            self.ast_forest = af
            self.tests_forest = tf
            self.call_graph = None
            self.import_graph = None
            self.symbol_index = None

    return AuditContext(
        repo_root=tmp_path,
        src_root=src_dir,
        tests_root=tests_dir,
        config=config or {},
        graph=_Graph(build_ast_forest(src_dir), build_tests_forest(tests_dir)),
        plugin_modules=[],
    )


# The #313 shape: a public method defined + tested, but the production caller
# was never wired to call it.
_MIXIN = '''
    class FlakyQueryMixin:
        def get_extraction_health(self):
            return {"success_rate": 100.0}
'''
_TEST_CALLS_IT = '''
    from src.mixin import FlakyQueryMixin

    def test_extraction_health():
        assert FlakyQueryMixin().get_extraction_health()["success_rate"] == 100.0
'''


class TestD12:
    def test_tested_but_not_wired_is_flagged(self, tmp_path):
        # The smoking gun: referenced by a test, never by production.
        ctx = _ctx(tmp_path, {"mixin.py": _MIXIN}, {"test_mixin.py": _TEST_CALLS_IT})
        result = detect_d12(ctx)
        assert result.count == 1
        assert "get_extraction_health" in result.samples[0]
        assert "incomplete integration" in result.samples[0]

    def test_wired_into_production_is_not_flagged(self, tmp_path):
        # Same method, but a production module now calls it → cleared.
        collector = '''
            from src.mixin import FlakyQueryMixin

            def collect():
                return FlakyQueryMixin().get_extraction_health()
        '''
        ctx = _ctx(
            tmp_path,
            {"mixin.py": _MIXIN, "collector.py": collector},
            {"test_mixin.py": _TEST_CALLS_IT},
        )
        assert detect_d12(ctx).count == 0

    def test_referenced_nowhere_is_not_flagged(self, tmp_path):
        # No test reference either → dead code (D1/D5/Vulture), not an
        # integration gap. D12 deliberately stays quiet here.
        ctx = _ctx(tmp_path, {"mixin.py": _MIXIN}, {})
        assert detect_d12(ctx).count == 0

    def test_private_and_dunder_skipped(self, tmp_path):
        src = '''
            class A:
                def _helper(self):
                    return 1
                def __len__(self):
                    return 0
        '''
        tests = '''
            from src.mixin import A
            def test_a():
                a = A()
                assert a._helper() == 1
                assert len(a) == 0
        '''
        ctx = _ctx(tmp_path, {"mixin.py": src}, {"test_a.py": tests})
        assert detect_d12(ctx).count == 0

    def test_decorated_defs_skipped(self, tmp_path):
        # CLI commands / properties / fixtures are framework-invoked, not by an
        # in-repo caller — a decorator clears the def.
        src = '''
            import typer
            app = typer.Typer()

            @app.command("run")
            def run_it():
                return "ran"

            class C:
                @property
                def value(self):
                    return 42
        '''
        tests = '''
            from src.mixin import run_it, C
            def test_it():
                assert run_it() == "ran"
                assert C().value == 42
        '''
        ctx = _ctx(tmp_path, {"mixin.py": src}, {"test_it.py": tests})
        assert detect_d12(ctx).count == 0

    def test_all_export_skipped(self, tmp_path):
        # Exported public API may be consumed cross-repo — not an integration gap.
        src = '''
            __all__ = ["public_api"]

            def public_api():
                return "ok"
        '''
        tests = '''
            from src.mixin import public_api
            def test_api():
                assert public_api() == "ok"
        '''
        ctx = _ctx(tmp_path, {"mixin.py": src}, {"test_api.py": tests})
        assert detect_d12(ctx).count == 0

    def test_pytest_plugin_hooks_skipped(self, tmp_path):
        # pytest_addoption / pytest_configure are invoked by pytest by name —
        # no in-repo caller by design, not an integration gap.
        src = '''
            def pytest_addoption(parser):
                parser.addoption("--x")
            def pytest_configure(config):
                config.x = 1
        '''
        tests = '''
            from src.mixin import pytest_addoption, pytest_configure
            def test_hooks():
                pytest_addoption(object())
                pytest_configure(object())
        '''
        ctx = _ctx(tmp_path, {"mixin.py": src}, {"test_hooks.py": tests})
        assert detect_d12(ctx).count == 0

    def test_baseline_accepts_existing_only_new_fires(self, tmp_path):
        # The ratchet: a name in audit.d12_baseline is accepted; a NEW unwired
        # symbol (not baselined) still fires. This is how a repo enables D12 on
        # a large backlog without blocking — only regressions trip it.
        src = '''
            class Q:
                def get_extraction_health(self):  # pre-existing, baselined
                    return 1
                def newly_added_unwired(self):     # new, not baselined
                    return 2
        '''
        tests = '''
            from src.mixin import Q
            def test_q():
                assert Q().get_extraction_health() == 1
                assert Q().newly_added_unwired() == 2
        '''
        ctx = _ctx(
            tmp_path, {"mixin.py": src}, {"test_q.py": tests},
            config={"audit": {"d12_baseline": ["get_extraction_health"]}},
        )
        result = detect_d12(ctx)
        assert result.count == 1  # only the new one
        assert "newly_added_unwired" in result.samples[0]

    def test_exclude_path_config(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            {"mixin.py": _MIXIN},
            {"test_mixin.py": _TEST_CALLS_IT},
            config={"audit": {"exclude_paths": {"D12": ["src/mixin.py"]}}},
        )
        assert detect_d12(ctx).count == 0

    def test_reference_in_excluded_file_still_clears(self, tmp_path):
        # A production reference in an EXCLUDED file still means "wired" — only
        # definitions honor the exclude list, references are global.
        ctx = _ctx(
            tmp_path,
            {"mixin.py": _MIXIN, "wired.py": "from src.mixin import FlakyQueryMixin\ndef go():\n    return FlakyQueryMixin().get_extraction_health()\n"},
            {"test_mixin.py": _TEST_CALLS_IT},
            config={"audit": {"exclude_paths": {"D12": ["src/wired.py"]}}},
        )
        assert detect_d12(ctx).count == 0
