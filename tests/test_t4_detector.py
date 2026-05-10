# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for T4 detector: orphan pytest fixtures."""
from __future__ import annotations

import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.test_shape import detect_t4
from custodian.audit_kit.passes.ast_forest import AstForest


def _write(tmp_path: Path, rel: str, src: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(src), encoding="utf-8")


def _ctx(tmp_path: Path, config: dict | None = None) -> AuditContext:
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=AstForest()),
    )


class TestT4:
    def test_no_tests_root_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path,
            src_root=tmp_path / "src",
            tests_root=tmp_path / "nonexistent",
            config={},
            plugin_modules=[],
            graph=AnalysisGraph(ast_forest=AstForest()),
        )
        assert detect_t4(ctx).count == 0

    def test_requested_fixture_not_flagged(self, tmp_path):
        _write(tmp_path, "tests/test_foo.py", """
            import pytest

            @pytest.fixture
            def my_fixture():
                return 42

            def test_uses_it(my_fixture):
                assert my_fixture == 42
        """)
        assert detect_t4(_ctx(tmp_path)).count == 0

    def test_orphan_fixture_flagged(self, tmp_path):
        _write(tmp_path, "tests/test_foo.py", """
            import pytest

            @pytest.fixture
            def unused_fixture():
                return 42

            def test_nothing():
                assert True
        """)
        result = detect_t4(_ctx(tmp_path))
        assert result.count == 1
        assert "unused_fixture" in result.samples[0]

    def test_autouse_fixture_not_flagged(self, tmp_path):
        _write(tmp_path, "tests/test_foo.py", """
            import pytest

            @pytest.fixture(autouse=True)
            def auto_setup():
                pass

            def test_nothing():
                assert True
        """)
        assert detect_t4(_ctx(tmp_path)).count == 0

    def test_fixture_requested_by_other_fixture(self, tmp_path):
        _write(tmp_path, "tests/conftest.py", """
            import pytest

            @pytest.fixture
            def base_data():
                return {}

            @pytest.fixture
            def enriched_data(base_data):
                return {**base_data, "extra": 1}
        """)
        _write(tmp_path, "tests/test_foo.py", """
            def test_uses_enriched(enriched_data):
                assert enriched_data
        """)
        assert detect_t4(_ctx(tmp_path)).count == 0

    def test_plugin_override_fixtures_not_flagged(self, tmp_path):
        _write(tmp_path, "tests/conftest.py", """
            import pytest

            @pytest.fixture
            def anyio_backend():
                return "asyncio"

            @pytest.fixture
            def event_loop():
                import asyncio
                return asyncio.new_event_loop()
        """)
        _write(tmp_path, "tests/test_foo.py", """
            def test_nothing():
                assert True
        """)
        assert detect_t4(_ctx(tmp_path)).count == 0

    def test_conftest_fixture_used_in_sibling_test(self, tmp_path):
        _write(tmp_path, "tests/conftest.py", """
            import pytest

            @pytest.fixture
            def shared():
                return "ok"
        """)
        _write(tmp_path, "tests/test_bar.py", """
            def test_uses_shared(shared):
                assert shared == "ok"
        """)
        assert detect_t4(_ctx(tmp_path)).count == 0

    def test_exclude_paths_respected(self, tmp_path):
        _write(tmp_path, "tests/legacy/conftest.py", """
            import pytest

            @pytest.fixture
            def old_fixture():
                return None
        """)
        _write(tmp_path, "tests/test_foo.py", """
            def test_nothing():
                assert True
        """)
        config = {"audit": {"exclude_paths": {"T4": ["tests/legacy/**"]}}}
        assert detect_t4(_ctx(tmp_path, config)).count == 0

    def test_multiple_orphans_counted(self, tmp_path):
        _write(tmp_path, "tests/test_foo.py", """
            import pytest

            @pytest.fixture
            def orphan_a():
                return 1

            @pytest.fixture
            def orphan_b():
                return 2

            def test_nothing():
                assert True
        """)
        assert detect_t4(_ctx(tmp_path)).count == 2
