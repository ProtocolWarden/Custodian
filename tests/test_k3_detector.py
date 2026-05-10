# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for K3 (docstring Args section parameter drift)."""
from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.docs import detect_k3


def _ctx(tmp_path: Path, src_files: dict[str, str], config: dict | None = None) -> AuditContext:
    src_root = tmp_path / "src"
    for rel, content in src_files.items():
        p = src_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
    )


class TestK3:
    def test_stale_param_in_docstring_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": '''
def fn(x, y):
    """Compute something.

    Args:
        x: First value.
        old_param: This param was removed.
    """
    return x + y
'''})
        result = detect_k3(ctx)
        assert result.count == 1
        assert "old_param" in result.samples[0]

    def test_matching_params_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": '''
def fn(x, y):
    """Compute.

    Args:
        x: First.
        y: Second.
    """
    return x + y
'''})
        assert detect_k3(ctx).count == 0

    def test_no_docstring_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": "def fn(x, y): return x + y\n"})
        assert detect_k3(ctx).count == 0

    def test_no_args_section_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": '''
def fn(x):
    """Compute.

    Returns:
        The result.
    """
    return x
'''})
        assert detect_k3(ctx).count == 0

    def test_returns_section_not_treated_as_param(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": '''
def fn(x):
    """Compute.

    Args:
        x: Input.

    Returns:
        The result.
    """
    return x
'''})
        assert detect_k3(ctx).count == 0

    def test_raises_section_not_treated_as_param(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": '''
def fn(x):
    """Compute.

    Args:
        x: Input.

    Raises:
        ValueError: When x is negative.
    """
    if x < 0:
        raise ValueError
    return x
'''})
        assert detect_k3(ctx).count == 0

    def test_kwargs_section_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": '''
def fn(x, **kwargs):
    """Compute.

    Args:
        x: Input.

    Kwargs:
        extra: Extra param.
    """
    return x
'''})
        assert detect_k3(ctx).count == 0

    def test_self_and_cls_not_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": '''
class Foo:
    def bar(self, x):
        """Do something.

        Args:
            x: Input value.
        """
        return x
'''})
        assert detect_k3(ctx).count == 0

    def test_underscore_prefix_param_flagged(self, tmp_path):
        ctx = _ctx(tmp_path, {"m.py": '''
def fn(x, _internal):
    """Compute.

    Args:
        x: Input.
        internal: Was renamed to _internal.
    """
    return x
'''})
        result = detect_k3(ctx)
        assert result.count == 1
        assert "internal" in result.samples[0]

    def test_exclude_paths(self, tmp_path):
        ctx = _ctx(tmp_path, {"legacy/m.py": '''
def fn(x):
    """Do.

    Args:
        old_param: Gone.
    """
    return x
'''}, config={"audit": {"exclude_paths": {"K3": ["src/legacy/**"]}}})
        assert detect_k3(ctx).count == 0
