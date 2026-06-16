# SPDX-License-Identifier: AGPL-3.0-or-later
"""Config-integrity doctor checks: duplicate-key detection (an `enforce:true` or
suppression silently dropped by YAML last-key-wins) and capabilities.enforce with
no registry locator (enforce-theater). Both catch ways a gate looks enforced but
isn't — without touching the audit/CI-red path."""

from __future__ import annotations

from pathlib import Path

from custodian.cli.doctor import _check_config
from custodian.cli.runner import load_config
from custodian.config.loader import find_duplicate_keys


# --- find_duplicate_keys (unit) ----------------------------------------------

def test_no_duplicates_clean():
    assert find_duplicate_keys("audit:\n  reconcile_enforce: true\n") == []


def test_duplicate_top_level_key():
    text = "audit:\n  reconcile_enforce: true\naudit:\n  capabilities:\n    enforce: true\n"
    assert find_duplicate_keys(text) == ["audit"]


def test_duplicate_nested_key():
    text = "audit:\n  capabilities:\n    enforce: true\n  capabilities:\n    enforce: false\n"
    assert find_duplicate_keys(text) == ["audit.capabilities"]


def test_malformed_yaml_returns_empty():
    assert find_duplicate_keys("audit: [unclosed\n  - : :") == []


def test_empty_text_returns_empty():
    assert find_duplicate_keys("") == []


# --- doctor integration ------------------------------------------------------

def _repo(tmp_path: Path, config_text: str) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    cfg_dir = tmp_path / ".custodian"
    cfg_dir.mkdir()
    (cfg_dir / "config.yaml").write_text(config_text, encoding="utf-8")
    return tmp_path


_BASE = "repo_key: Demo\nsrc_root: src\ntests_root: tests\n"


def _warnings(repo: Path) -> list[str]:
    w: list[str] = []
    _check_config(load_config(repo), repo, w)
    return w


def test_doctor_flags_duplicate_audit_key(tmp_path):
    # Two `audit:` blocks — YAML keeps the last, silently dropping enforce in the first.
    repo = _repo(tmp_path, _BASE + "audit:\n  reconcile_enforce: true\naudit:\n  src_root: src\n")
    assert any("duplicate key 'audit'" in m for m in _warnings(repo))


def test_doctor_clean_config_no_duplicate_warning(tmp_path):
    repo = _repo(tmp_path, _BASE + "audit:\n  reconcile_enforce: true\n")
    assert not any("duplicate key" in m for m in _warnings(repo))


def test_doctor_flags_enforce_without_locator(tmp_path):
    repo = _repo(tmp_path, _BASE + "audit:\n  capabilities:\n    enforce: true\n")
    assert any("no registry locator" in m for m in _warnings(repo))


def test_doctor_enforce_with_registry_path_ok(tmp_path):
    repo = _repo(
        tmp_path,
        _BASE + "audit:\n  capabilities:\n    enforce: true\n    registry_path: x/caps.yaml\n",
    )
    assert not any("no registry locator" in m for m in _warnings(repo))


def test_doctor_enforce_with_cross_repo_ok(tmp_path):
    repo = _repo(
        tmp_path,
        _BASE
        + "audit:\n  capabilities:\n    enforce: true\n"
        + "  cross_repo:\n    platform_manifest_repo: ../PlatformManifest\n",
    )
    assert not any("no registry locator" in m for m in _warnings(repo))


def test_doctor_enforce_false_not_flagged(tmp_path):
    # Dormant (enforce not set / false) needs no locator — must not warn.
    repo = _repo(tmp_path, _BASE + "audit:\n  capabilities:\n    enforce: false\n")
    assert not any("no registry locator" in m for m in _warnings(repo))
