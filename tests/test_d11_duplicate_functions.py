# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for D11 — duplicate function bodies."""
from __future__ import annotations

import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.dead_code import detect_d11
from custodian.audit_kit.passes.ast_forest import build_ast_forest


def _ctx(tmp_path: Path, src: str, *, config: dict | None = None) -> AuditContext:
    src_dir = tmp_path / "src"
    src_dir.mkdir(exist_ok=True)
    # encoding= is not optional: the fixtures carry non-ASCII (em dashes in
    # docstrings), and without it Windows writes cp1252 while build_ast_forest
    # reads utf-8 — the file then fails to decode, is skipped, and the detector
    # reports zero findings instead of failing loudly.
    (src_dir / "module.py").write_text(textwrap.dedent(src), encoding="utf-8")

    class _Graph:
        def __init__(self, forest):
            self.ast_forest = forest
            self.call_graph = None
            self.import_graph = None
            self.symbol_index = None
            self.tests_forest = None

    forest = build_ast_forest(src_dir)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_dir,
        tests_root=tmp_path / "tests",
        config=config or {},
        graph=_Graph(forest),
        plugin_modules=[],
    )


class TestD11:
    def test_no_clones_returns_zero(self, tmp_path):
        ctx = _ctx(tmp_path, '''
            def fetch(url: str) -> str:
                """Fetch a URL."""
                response = http_get(url)
                if response.status != 200:
                    raise RuntimeError("bad status")
                return response.body

            def parse(text: str) -> dict:
                """Parse JSON text."""
                if not text:
                    return {}
                obj = json_loads(text)
                obj["parsed_at"] = now()
                return obj
        ''')
        assert detect_d11(ctx).count == 0

    def test_renamed_clone_caught(self, tmp_path):
        ctx = _ctx(tmp_path, '''
            def fetch_data_alpha(url: str, headers: dict) -> dict:
                """Fetch via alpha."""
                req = build_request(url, headers)
                response = client.send(req)
                if response.status != 200:
                    raise RuntimeError("bad")
                payload = json.loads(response.body)
                payload["fetched"] = True
                return payload

            def fetch_data_beta(endpoint: str, hdrs: dict) -> dict:
                """Fetch via beta — same shape, different names."""
                rq = build_request(endpoint, hdrs)
                resp = client.send(rq)
                if resp.status != 200:
                    raise RuntimeError("bad")
                data = json.loads(resp.body)
                data["fetched"] = True
                return data
        ''')
        result = detect_d11(ctx)
        assert result.count == 1
        assert "fetch_data_alpha" in result.samples[0]
        assert "fetch_data_beta" in result.samples[0]

    def test_dunders_skipped(self, tmp_path):
        ctx = _ctx(tmp_path, '''
            class A:
                def __init__(self, x: int) -> None:
                    self.x = x
                    self.y = x * 2
                    self.z = x * 3
                    if x > 0:
                        self.positive = True

            class B:
                def __init__(self, n: int) -> None:
                    self.x = n
                    self.y = n * 2
                    self.z = n * 3
                    if n > 0:
                        self.positive = True
        ''')
        # __init__ is in _D11_SKIP_NAMES
        assert detect_d11(ctx).count == 0

    def test_test_functions_skipped(self, tmp_path):
        ctx = _ctx(tmp_path, '''
            import pytest

            @pytest.mark.parametrize("x", [1, 2, 3])
            def test_alpha(x):
                value = compute(x)
                if value > 0:
                    assert value < 100
                    assert value != x
                else:
                    assert value == 0

            @pytest.mark.parametrize("x", [4, 5, 6])
            def test_beta(x):
                value = compute(x)
                if value > 0:
                    assert value < 100
                    assert value != x
                else:
                    assert value == 0
        ''')
        # test_* are excluded
        assert detect_d11(ctx).count == 0

    def test_short_functions_skipped(self, tmp_path):
        ctx = _ctx(tmp_path, '''
            def a(): return 1

            def b(): return 1

            def c(): return 1
        ''')
        # Below min_lines threshold
        assert detect_d11(ctx).count == 0

    def test_threshold_configurable(self, tmp_path):
        # Two trivial 5-line functions with identical shape — by default
        # below the min_statements floor (25).
        src = '''
            def alpha(x: int) -> int:
                if x > 0:
                    y = x * 2
                else:
                    y = -x
                return y

            def beta(n: int) -> int:
                if n > 0:
                    y = n * 2
                else:
                    y = -n
                return y
        '''
        # Default thresholds → no clones (too small)
        ctx = _ctx(tmp_path, src)
        assert detect_d11(ctx).count == 0
        # Lower the thresholds → caught
        ctx = _ctx(tmp_path, src, config={
            "audit": {"d11_min_statements": 5, "d11_min_lines": 3},
        })
        assert detect_d11(ctx).count == 1
