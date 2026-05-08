# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""M-class detector tests — repo-meta file presence."""
from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.repo_meta import (
    build_repo_meta_detectors,
    detect_m1, detect_m2, detect_m3, detect_m4,
)


def _ctx(repo_root: Path, config: dict | None = None) -> AuditContext:
    src_root = repo_root / "src"
    tests_root = repo_root / "tests"
    src_root.mkdir(parents=True, exist_ok=True)
    tests_root.mkdir(parents=True, exist_ok=True)
    return AuditContext(
        repo_root=repo_root,
        src_root=src_root,
        tests_root=tests_root,
        config=config or {},
        plugin_modules=[],
        graph=None,
    )


class TestM1Changelog:
    def test_missing_flagged(self, tmp_path: Path):
        assert detect_m1(_ctx(tmp_path)).count == 1

    def test_present_passes(self, tmp_path: Path):
        (tmp_path / "CHANGELOG.md").write_text("# Changelog")
        assert detect_m1(_ctx(tmp_path)).count == 0

    def test_skip_via_config(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"repo_meta": {"skip": ["M1"]}})
        assert detect_m1(ctx).count == 0


class TestM2Contributing:
    def test_missing_flagged(self, tmp_path: Path):
        assert detect_m2(_ctx(tmp_path)).count == 1

    def test_present_passes(self, tmp_path: Path):
        (tmp_path / "CONTRIBUTING.md").write_text("# Contributing")
        assert detect_m2(_ctx(tmp_path)).count == 0

    def test_skip_via_config(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"repo_meta": {"skip": ["M2"]}})
        assert detect_m2(ctx).count == 0


class TestM3Security:
    def test_missing_flagged(self, tmp_path: Path):
        assert detect_m3(_ctx(tmp_path)).count == 1

    def test_present_passes(self, tmp_path: Path):
        (tmp_path / "SECURITY.md").write_text("# Security")
        assert detect_m3(_ctx(tmp_path)).count == 0


class TestM4License:
    def test_missing_flagged(self, tmp_path: Path):
        assert detect_m4(_ctx(tmp_path)).count == 1

    def test_uppercase_LICENSE_passes(self, tmp_path: Path):
        (tmp_path / "LICENSE").write_text("MIT")
        assert detect_m4(_ctx(tmp_path)).count == 0

    def test_LICENSE_md_passes(self, tmp_path: Path):
        (tmp_path / "LICENSE.md").write_text("MIT")
        assert detect_m4(_ctx(tmp_path)).count == 0

    def test_LICENSE_txt_passes(self, tmp_path: Path):
        (tmp_path / "LICENSE.txt").write_text("MIT")
        assert detect_m4(_ctx(tmp_path)).count == 0

    def test_LICENCE_british_spelling_passes(self, tmp_path: Path):
        (tmp_path / "LICENCE").write_text("MIT")
        assert detect_m4(_ctx(tmp_path)).count == 0

    def test_skip_via_config(self, tmp_path: Path):
        ctx = _ctx(tmp_path, {"repo_meta": {"skip": ["M4"]}})
        assert detect_m4(ctx).count == 0


class TestBuilder:
    def test_returns_all_four(self):
        ds = build_repo_meta_detectors()
        ids = {d.id for d in ds}
        assert ids == {"M1", "M2", "M3", "M4"}

    def test_all_low_severity(self):
        for d in build_repo_meta_detectors():
            assert d.severity == "low"
