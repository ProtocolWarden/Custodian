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


class TestBuilderLegacy:
    def test_returns_all_legacy_four(self):
        ds = build_repo_meta_detectors()
        ids = {d.id for d in ds}
        assert {"M1", "M2", "M3", "M4"}.issubset(ids)

    def test_all_low_severity(self):
        for d in build_repo_meta_detectors():
            assert d.severity == "low"


class TestM5ChangelogFormat:
    def test_silent_when_changelog_absent(self, tmp_path: Path):
        from custodian.audit_kit.detectors.repo_meta import detect_m5
        assert detect_m5(_ctx(tmp_path)).count == 0

    def test_compliant_changelog_passes(self, tmp_path: Path):
        from custodian.audit_kit.detectors.repo_meta import detect_m5
        (tmp_path / "CHANGELOG.md").write_text(
            "# Changelog\n\n"
            "## [Unreleased]\n- foo\n\n"
            "## [1.0.0] - 2026-05-08\n- initial\n",
        )
        assert detect_m5(_ctx(tmp_path)).count == 0

    def test_missing_h1_flagged(self, tmp_path: Path):
        from custodian.audit_kit.detectors.repo_meta import detect_m5
        (tmp_path / "CHANGELOG.md").write_text(
            "## [1.0.0]\n- thing\n",
        )
        result = detect_m5(_ctx(tmp_path))
        assert result.count == 1
        assert "missing `# Changelog` H1" in result.samples[0]

    def test_no_release_sections_flagged(self, tmp_path: Path):
        from custodian.audit_kit.detectors.repo_meta import detect_m5
        (tmp_path / "CHANGELOG.md").write_text(
            "# Changelog\n\nFreeform notes with no release headings.\n",
        )
        result = detect_m5(_ctx(tmp_path))
        assert result.count == 1
        assert "no release sections" in result.samples[0]

    def test_unreleased_alone_passes(self, tmp_path: Path):
        from custodian.audit_kit.detectors.repo_meta import detect_m5
        (tmp_path / "CHANGELOG.md").write_text(
            "# Changelog\n\n## [Unreleased]\n- pending\n",
        )
        assert detect_m5(_ctx(tmp_path)).count == 0

    def test_skip_via_config(self, tmp_path: Path):
        from custodian.audit_kit.detectors.repo_meta import detect_m5
        (tmp_path / "CHANGELOG.md").write_text("garbage\n")
        ctx = _ctx(tmp_path, {"repo_meta": {"skip": ["M5"]}})
        assert detect_m5(ctx).count == 0


class TestBuilderM5:
    def test_returns_all_five(self):
        from custodian.audit_kit.detectors.repo_meta import build_repo_meta_detectors
        ds = build_repo_meta_detectors()
        ids = {d.id for d in ds}
        assert ids == {"M1", "M2", "M3", "M4", "M5"}
