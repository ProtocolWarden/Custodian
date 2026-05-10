# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for X1 — PlatformManifest legacy-name drift."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.cross_repo import detect_x1


_PM_YAML = textwrap.dedent("""\
    manifest_kind: platform
    manifest_version: "1.0.0"
    repos:
      operations_center:
        canonical_name: OperationsCenter
        legacy_names: [ControlPlane]
      operator_console:
        canonical_name: OperatorConsole
        legacy_names: [FOB]
""")


def _ctx(tmp_path: Path, src_files: dict[str, str], *, config: dict | None = None) -> AuditContext:
    src_dir = tmp_path / "src"
    src_dir.mkdir(exist_ok=True)
    for relpath, body in src_files.items():
        p = src_dir / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_dir,
        tests_root=tmp_path / "tests",
        config=config or {},
        graph=None,
        plugin_modules=[],
    )


def _write_pm(tmp_path: Path) -> Path:
    pm_dir = tmp_path / "PlatformManifest" / "src" / "platform_manifest" / "data"
    pm_dir.mkdir(parents=True)
    pm_path = pm_dir / "platform_manifest.yaml"
    pm_path.write_text(_PM_YAML)
    return pm_path


class TestX1:
    def test_silent_when_no_manifest_configured(self, tmp_path):
        ctx = _ctx(tmp_path, {"a.py": "x = 1"})
        assert detect_x1(ctx).count == 0

    def test_silent_when_manifest_path_missing(self, tmp_path):
        ctx = _ctx(tmp_path, {"a.py": "x = 1"}, config={
            "audit": {"cross_repo": {
                "platform_manifest_path": "missing.yaml",
            }},
        })
        assert detect_x1(ctx).count == 0

    def test_legacy_name_in_python_caught(self, tmp_path):
        _write_pm(tmp_path)
        ctx = _ctx(
            tmp_path,
            {"a.py": "ControlPlane = 'still using the old name'\n"},
            config={"audit": {"cross_repo": {
                "platform_manifest_repo": "PlatformManifest",
            }}},
        )
        result = detect_x1(ctx)
        assert result.count == 1
        assert "ControlPlane" in result.samples[0]
        assert "OperationsCenter" in result.samples[0]

    def test_legacy_name_in_markdown_caught(self, tmp_path):
        _write_pm(tmp_path)
        (tmp_path / "README.md").write_text("FOB launches the watcher.\n")
        ctx = _ctx(
            tmp_path,
            {},
            config={"audit": {"cross_repo": {
                "platform_manifest_repo": "PlatformManifest",
            }}},
        )
        result = detect_x1(ctx)
        assert result.count == 1
        assert "FOB" in result.samples[0]
        assert "OperatorConsole" in result.samples[0]

    def test_canonical_name_not_flagged(self, tmp_path):
        _write_pm(tmp_path)
        ctx = _ctx(
            tmp_path,
            {"a.py": "import OperationsCenter\n"},
            config={"audit": {"cross_repo": {
                "platform_manifest_repo": "PlatformManifest",
            }}},
        )
        assert detect_x1(ctx).count == 0

    def test_history_paths_skipped(self, tmp_path):
        _write_pm(tmp_path)
        history_dir = tmp_path / "docs" / "history"
        history_dir.mkdir(parents=True)
        (history_dir / "rename.md").write_text("FOB → OperatorConsole rename\n")
        ctx = _ctx(
            tmp_path,
            {},
            config={"audit": {"cross_repo": {
                "platform_manifest_repo": "PlatformManifest",
            }}},
        )
        # docs/history is in skip_parts
        assert detect_x1(ctx).count == 0

    def test_exclude_paths_honoured(self, tmp_path):
        _write_pm(tmp_path)
        ctx = _ctx(
            tmp_path,
            {"a.py": "ControlPlane = 1\n"},
            config={
                "audit": {
                    "cross_repo": {"platform_manifest_repo": "PlatformManifest"},
                    "exclude_paths": {"X1": ["src/a.py"]},
                },
            },
        )
        assert detect_x1(ctx).count == 0
