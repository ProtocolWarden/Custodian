# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for N2 (invisible test functions — not prefixed test_)."""
from __future__ import annotations

import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.naming import detect_n2


def _ctx(tmp_path: Path, test_files: dict[str, str], config: dict | None = None) -> AuditContext:
    tests_root = tmp_path / "tests"
    for rel, content in test_files.items():
        p = tests_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(content), encoding="utf-8")
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tests_root,
        config=config or {},
        plugin_modules=[],
    )


class TestN2:
    def test_unprefixed_helper_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"test_foo.py": """
            def helper_build():
                return {}
            def test_real():
                assert helper_build()
        """})
        result = detect_n2(ctx)
        assert result.count == 1
        assert "helper_build" in result.samples[0]

    def test_test_prefixed_function_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"test_foo.py": """
            def test_something():
                assert True
        """})
        assert detect_n2(ctx).count == 0

    def test_private_helper_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"test_foo.py": """
            def _make_thing():
                return {}
            def test_real():
                assert _make_thing()
        """})
        assert detect_n2(ctx).count == 0

    def test_pytest_fixture_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"test_foo.py": """
            import pytest

            @pytest.fixture
            def my_thing():
                return {}

            def test_uses_fixture(my_thing):
                assert my_thing
        """})
        assert detect_n2(ctx).count == 0

    def test_pytest_fixture_with_scope_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"test_foo.py": """
            import pytest

            @pytest.fixture(scope="module")
            def expensive_thing():
                return {}
        """})
        assert detect_n2(ctx).count == 0

    def test_conftest_not_scanned(self, tmp_path):
        """conftest.py is support infrastructure, not a test file."""
        ctx = _ctx(tmp_path, {"conftest.py": """
            def some_helper():
                return {}
        """})
        assert detect_n2(ctx).count == 0

    def test_non_test_file_not_scanned(self, tmp_path):
        """Files not named test_*.py should not be scanned."""
        ctx = _ctx(tmp_path, {"helpers.py": """
            def some_helper():
                return {}
        """})
        assert detect_n2(ctx).count == 0

    def test_setup_teardown_hooks_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"test_foo.py": """
            def setup_module():
                pass
            def teardown_module():
                pass
            def setup_function():
                pass
            def test_real():
                assert True
        """})
        assert detect_n2(ctx).count == 0

    def test_pytest_hook_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"test_foo.py": """
            def pytest_configure(config):
                pass
            def test_real():
                assert True
        """})
        assert detect_n2(ctx).count == 0

    def test_exclude_paths(self, tmp_path):
        ctx = _ctx(tmp_path, {"legacy/test_old.py": """
            def helper():
                return {}
        """}, config={"audit": {"exclude_paths": {"N2": ["tests/legacy/**"]}}})
        assert detect_n2(ctx).count == 0
