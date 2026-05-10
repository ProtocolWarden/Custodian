# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


_SRC_ROOT = str(Path(__file__).parent.parent / "src")


def _run_doctor(repo: Path, *extra_args) -> subprocess.CompletedProcess:
    env = {**os.environ, "PYTHONPATH": _SRC_ROOT}
    return subprocess.run(
        [sys.executable, "-m", "custodian.cli.doctor", "--repo", str(repo), *extra_args],
        capture_output=True, text=True, env=env,
    )


def _make_minimal_repo(tmp_path: Path) -> Path:
    """Create a minimal valid .custodian.yaml setup."""
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / ".custodian.yaml").write_text(
        "repo_key: TestRepo\nsrc_root: src\ntests_root: tests\n", encoding="utf-8"
    )
    return tmp_path


class TestDoctorOK:
    def test_clean_repo_prints_ok(self, tmp_path):
        _make_minimal_repo(tmp_path)
        result = _run_doctor(tmp_path)
        assert result.returncode == 0
        assert "OK" in result.stdout

    def test_no_color_flag(self, tmp_path):
        _make_minimal_repo(tmp_path)
        result = _run_doctor(tmp_path, "--no-color")
        assert result.returncode == 0
        assert "\033[" not in result.stdout


class TestDoctorMissingKeys:
    def test_warns_missing_repo_key(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "tests").mkdir()
        (tmp_path / ".custodian.yaml").write_text(
            "src_root: src\ntests_root: tests\n", encoding="utf-8"
        )
        result = _run_doctor(tmp_path)
        assert "repo_key" in result.stdout

    def test_warns_missing_src_root_key(self, tmp_path):
        (tmp_path / ".custodian.yaml").write_text(
            "repo_key: X\ntests_root: tests\n", encoding="utf-8"
        )
        result = _run_doctor(tmp_path)
        assert "src_root" in result.stdout

    def test_warns_missing_directory(self, tmp_path):
        (tmp_path / ".custodian.yaml").write_text(
            "repo_key: X\nsrc_root: nonexistent\ntests_root: tests\n", encoding="utf-8"
        )
        result = _run_doctor(tmp_path)
        assert "nonexistent" in result.stdout


class TestDoctorUnknownKeys:
    def test_warns_unknown_top_level_key(self, tmp_path):
        _make_minimal_repo(tmp_path)
        (tmp_path / ".custodian.yaml").write_text(
            "repo_key: X\nsrc_root: src\ntests_root: tests\ntypo_key: bad\n",
            encoding="utf-8",
        )
        result = _run_doctor(tmp_path)
        assert "typo_key" in result.stdout

    def test_warns_unknown_audit_key(self, tmp_path):
        _make_minimal_repo(tmp_path)
        (tmp_path / ".custodian.yaml").write_text(
            "repo_key: X\nsrc_root: src\ntests_root: tests\naudit:\n  typo: true\n",
            encoding="utf-8",
        )
        result = _run_doctor(tmp_path)
        assert "typo" in result.stdout


class TestDoctorExcludePaths:
    def test_warns_unknown_detector_in_exclude_paths(self, tmp_path):
        _make_minimal_repo(tmp_path)
        (tmp_path / ".custodian.yaml").write_text(
            "repo_key: X\nsrc_root: src\ntests_root: tests\n"
            "audit:\n  exclude_paths:\n    ZZZZ:\n      - src/foo.py\n",
            encoding="utf-8",
        )
        result = _run_doctor(tmp_path)
        assert "ZZZZ" in result.stdout

    def test_warns_exclude_paths_value_not_list(self, tmp_path):
        _make_minimal_repo(tmp_path)
        (tmp_path / ".custodian.yaml").write_text(
            "repo_key: X\nsrc_root: src\ntests_root: tests\n"
            "audit:\n  exclude_paths:\n    C1: src/foo.py\n",
            encoding="utf-8",
        )
        result = _run_doctor(tmp_path)
        assert "list" in result.stdout


class TestDoctorStrict:
    def test_strict_exits_nonzero_on_warning(self, tmp_path):
        (tmp_path / ".custodian.yaml").write_text(
            "repo_key: X\nsrc_root: bad\ntests_root: bad\n", encoding="utf-8"
        )
        result = _run_doctor(tmp_path, "--strict")
        assert result.returncode != 0

    def test_strict_exits_zero_when_clean(self, tmp_path):
        _make_minimal_repo(tmp_path)
        result = _run_doctor(tmp_path, "--strict")
        assert result.returncode == 0
