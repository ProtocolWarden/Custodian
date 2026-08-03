# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import warnings
from pathlib import Path

import pytest
import yaml

from custodian.config.loader import (
    config_summary, has_ignore_paths, load_config, migrate_v0_to_v1, _normalize_v0,
)


# The retired `ignore_paths` key in both spellings it ever had: under `audit`
# in a raw v0 file, and under `policy` once normalized. See TestIgnorePathsRemoved.
_IGNORE_PATHS_V0 = {"audit": {"ignore_paths": ["src/legacy/**"]}}
_IGNORE_PATHS_V1 = {"version": 1, "policy": {"ignore_paths": ["src/legacy/**"]}}


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


class TestIgnorePathsRemoved:
    """``audit.ignore_paths`` is NOT a supported key, and must not creep back.

    It was parsed into ``policy["ignore_paths"]`` by both config-shape branches
    and echoed by ``config_summary``, but no code path ever read it to filter a
    finding. A repo writing ``audit: {ignore_paths: ["src/legacy/**"]}`` got the
    globs listed back in the config summary — which reads as confirmation the
    exemption landed — while every finding under that path kept reporting.

    Implementing it was rejected rather than deferred: detector findings carry
    no structured path. ``DetectorResult`` is ``(count, samples)`` where samples
    are free-form strings capped at 8 (``_MAX_SAMPLES``) with inconsistent
    shapes — absolute paths, repo-relative paths, and non-path prefixes like
    ``"docs: ..."``. A path filter could drop matching samples but could never
    correct ``count``, so a detector with 500 findings all under an ignored path
    would report ``count=500, samples=[]``: a worse failure than the no-op.
    ``audit.exclude_paths`` is the real, per-detector mechanism.
    """

    def test_normalize_v0_does_not_lift_it_into_policy(self):
        n = _normalize_v0(_IGNORE_PATHS_V0)
        assert "ignore_paths" not in n["policy"]

    def test_normalize_v0_still_preserves_the_raw_audit_block(self):
        # Removal stops the key being treated as policy; it does not rewrite
        # the operator's file. `_normalize_v0` re-exports the original keys.
        n = _normalize_v0(_IGNORE_PATHS_V0)
        assert n["audit"]["ignore_paths"] == ["src/legacy/**"]

    def test_migrate_does_not_carry_it_into_v1(self):
        result = migrate_v0_to_v1(_IGNORE_PATHS_V0)
        assert "ignore_paths" not in result["policy"]

    @pytest.mark.parametrize("cfg", [_IGNORE_PATHS_V0, _IGNORE_PATHS_V1])
    def test_summary_warns_instead_of_echoing_the_globs(self, cfg):
        lines = config_summary(cfg)
        assert not any("src/legacy/**" in ln for ln in lines), (
            "echoing the globs reads as confirmation the exemption took effect"
        )
        assert any("exclude_paths" in ln for ln in lines), (
            "the warning must name the mechanism that actually works"
        )

    def test_summary_stays_quiet_when_the_key_is_absent(self):
        lines = config_summary({"version": 1, "policy": {"ignore_rules": ["C1"]}})
        assert not any("ignore_paths" in ln for ln in lines)

    def test_has_ignore_paths_tolerates_a_non_mapping_section(self):
        # config_summary runs against a raw, unvalidated file via
        # `custodian-config show`; a scalar `audit:` must not raise.
        assert has_ignore_paths({"audit": "not-a-mapping"}) is False


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
