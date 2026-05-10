# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import warnings
from pathlib import Path

import pytest
import yaml

from custodian.config.loader import (
    config_summary, load_config, migrate_v0_to_v1, _normalize_v0,
)


def _write_config(tmp_path: Path, content: dict) -> Path:
    path = tmp_path / ".custodian.yaml"
    path.write_text(yaml.dump(content), encoding="utf-8")
    return path


class TestLoadConfig:
    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path)

    def test_v0_emits_deprecation_warning(self, tmp_path):
        _write_config(tmp_path, {"repo_key": "test"})
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            load_config(tmp_path)
        assert any(issubclass(x.category, DeprecationWarning) for x in w)

    def test_v1_no_warning(self, tmp_path):
        _write_config(tmp_path, {"version": 1, "repo": {"key": "test"}})
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            load_config(tmp_path)
        assert not any(issubclass(x.category, DeprecationWarning) for x in w)

    def test_v0_normalized_has_repo_key(self, tmp_path):
        _write_config(tmp_path, {"repo_key": "myrepo", "src_root": "src"})
        with warnings.catch_warnings(record=True):
            warnings.simplefilter("always")
            cfg = load_config(tmp_path)
        assert cfg["repo"]["key"] == "myrepo"
        assert cfg["repo"]["src_root"] == "src"


class TestNormalizeV0:
    def test_maps_repo_key(self):
        raw = {"repo_key": "r1", "src_root": "src", "tests_root": "tests"}
        n = _normalize_v0(raw)
        assert n["repo"]["key"] == "r1"
        assert n["repo"]["src_root"] == "src"

    def test_maps_audit_policy(self):
        raw = {"audit": {"min_severity": "high", "ignore_rules": ["F401"]}}
        n = _normalize_v0(raw)
        assert n["policy"]["min_severity"] == "high"
        assert n["policy"]["ignore_rules"] == ["F401"]

    def test_preserves_original_keys(self):
        raw = {"repo_key": "r", "custom_key": "value"}
        n = _normalize_v0(raw)
        assert n["custom_key"] == "value"

    def test_tools_defaults(self):
        n = _normalize_v0({})
        assert n["tools"]["ruff"]["enabled"] is True
        # Vulture soft-flipped ON 2026-05-04 with min_confidence=80
        # (high-confidence dead code only). Repos can opt out via .custodian.yaml.
        assert n["tools"]["vulture"]["enabled"] is True
        assert n["tools"]["vulture"]["min_confidence"] == 80


class TestMigrateV0ToV1:
    def test_version_becomes_1(self):
        result = migrate_v0_to_v1({})
        assert result["version"] == 1

    def test_repo_mapped(self):
        raw = {"repo_key": "mrepo", "src_root": "code", "tests_root": "spec"}
        result = migrate_v0_to_v1(raw)
        assert result["repo"]["key"] == "mrepo"
        assert result["repo"]["src_root"] == "code"
        assert result["repo"]["tests_root"] == "spec"

    def test_policy_mapped(self):
        raw = {"audit": {"min_severity": "medium", "ignore_rules": ["ANN001"]}}
        result = migrate_v0_to_v1(raw)
        assert result["policy"]["min_severity"] == "medium"
        assert result["policy"]["ignore_rules"] == ["ANN001"]

    def test_architecture_layers_migrated(self):
        raw = {"architecture": {"layers": [{"name": "domain", "glob": "src/domain/**"}]}}
        result = migrate_v0_to_v1(raw)
        assert "architecture" in result["policy"]
        assert result["policy"]["architecture"]["rules"][0]["name"] == "domain"

    def test_tools_present(self):
        result = migrate_v0_to_v1({})
        assert "ruff" in result["tools"]
        assert "ty" in result["tools"]
        assert "semgrep" in result["tools"]
        assert "vulture" in result["tools"]


class TestConfigSummary:
    def test_shows_version(self):
        lines = config_summary({"version": 1})
        assert any("1" in ln for ln in lines)

    def test_shows_repo_key(self):
        cfg = {"repo": {"key": "myrepo"}}
        lines = config_summary(cfg)
        assert any("myrepo" in ln for ln in lines)

    def test_shows_tools(self):
        cfg = {"tools": {"ruff": {"enabled": True}, "vulture": {"enabled": False}}}
        lines = config_summary(cfg)
        assert any("ruff" in ln for ln in lines)
        assert any("vulture" in ln for ln in lines)
