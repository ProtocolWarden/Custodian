# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Semgrep docker mode.

Native semgrep does not run on every host. On Windows ``semgrep-core`` fails
rule validation (``RPC subprocess exited with code 1``) *and* semgrep still
exits 0 — so an authored rule set silently never executes while the config
keeps asserting it does. ``docker: true`` runs the official image instead.

Paths are passed relative to the mount, which also normalises result paths:
semgrep echoes back the form it was given.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from custodian.adapters.registry import get_enabled_adapters
from custodian.adapters.semgrep import SemgrepAdapter


class TestAvailability:
    def test_docker_mode_needs_docker_not_semgrep(self):
        def only_docker(name):
            return "/usr/bin/docker" if name == "docker" else None

        with patch("custodian.adapters.semgrep.find_tool", side_effect=only_docker):
            assert SemgrepAdapter(docker=True).is_available() is True
            assert SemgrepAdapter().is_available() is False

    def test_docker_mode_unavailable_without_docker(self):
        with patch("custodian.adapters.semgrep.find_tool", return_value=None):
            assert SemgrepAdapter(docker=True).is_available() is False


class TestDockerCommand:
    def _cmd(self, tmp_path, configs=None):
        (tmp_path / "src").mkdir(exist_ok=True)
        rules = tmp_path / ".custodian" / "rules" / "semgrep"
        rules.mkdir(parents=True, exist_ok=True)
        adapter = SemgrepAdapter(docker=True)
        with patch("custodian.adapters.semgrep.find_tool", return_value="docker"):
            return adapter._docker_cmd(
                tmp_path, configs or [str(rules)], tmp_path / "src"
            )

    def test_mounts_the_repo_and_works_from_the_mount(self, tmp_path):
        cmd = self._cmd(tmp_path)
        assert cmd[:3] == ["docker", "run", "--rm"]
        assert f"{tmp_path.resolve().as_posix()}:/src" in cmd
        assert cmd[cmd.index("-w") + 1] == "/src"

    def test_paths_are_relative_to_the_mount(self, tmp_path):
        """Absolute host paths would not exist inside the container."""
        cmd = self._cmd(tmp_path)
        assert cmd[cmd.index("--config") + 1] == ".custodian/rules/semgrep"
        assert cmd[-1] == "src"
        assert not any(str(tmp_path) in part for part in cmd[cmd.index("--config"):])

    def test_emits_json_quietly_without_metrics(self, tmp_path):
        cmd = self._cmd(tmp_path)
        for flag in ("--json", "--quiet", "--metrics=off"):
            assert flag in cmd

    def test_path_outside_the_repo_is_refused(self, tmp_path):
        """Only the repo is mounted, so an outside rules dir cannot be reached."""
        outside = tmp_path.parent / "elsewhere"
        outside.mkdir(exist_ok=True)
        with pytest.raises(ValueError, match="outside the repo"):
            self._cmd(tmp_path, configs=[str(outside)])


class TestRegistryWiring:
    def test_docker_flag_and_image_are_read_from_config(self):
        adapters = get_enabled_adapters({
            "tools": {"semgrep": {
                "configs": [".custodian/rules/semgrep"],
                "docker": True,
                "image": "semgrep/semgrep:1.2.3",
                "timeout": 300,
            }}
        })
        adapter = next(a for a in adapters if a.name == "semgrep")
        assert adapter._docker is True
        assert adapter._image == "semgrep/semgrep:1.2.3"
        assert adapter._timeout == 300

    def test_defaults_to_native_with_a_bare_dict(self):
        adapters = get_enabled_adapters({"tools": {"semgrep": {"configs": ["r"]}}})
        adapter = next(a for a in adapters if a.name == "semgrep")
        assert adapter._docker is False
        assert adapter._image == "semgrep/semgrep:latest"


class TestResultsStillParse:
    def test_relative_container_paths_survive(self, tmp_path):
        """The container reports repo-relative paths; they must pass through."""
        (tmp_path / "src").mkdir(exist_ok=True)
        output = json.dumps({"results": [{
            "check_id": "rules.vf3-no-raw-os-environ",
            "extra": {"message": "raw env", "severity": "WARNING"},
            "path": "src/config/thing.py",
            "start": {"line": 12, "col": 1},
        }]})
        adapter = SemgrepAdapter(configs=[str(tmp_path / "r")], docker=True)
        (tmp_path / "r").mkdir(exist_ok=True)
        proc = MagicMock(stdout=output, stderr="", returncode=0)
        with patch("custodian.adapters.semgrep.find_tool", return_value="docker"), \
             patch("custodian.adapters.semgrep.subprocess.run", return_value=proc):
            findings = adapter.run(tmp_path, {"src_root": "src"})
        assert len(findings) == 1
        assert findings[0].path == "src/config/thing.py"
        assert findings[0].line == 12
        assert findings[0].rule == "vf3-no-raw-os-environ"


class TestTimeout:
    def test_timeout_reports_a_tool_error_rather_than_crashing(self, tmp_path):
        import subprocess as sp
        (tmp_path / "src").mkdir(exist_ok=True)
        (tmp_path / "r").mkdir(exist_ok=True)
        adapter = SemgrepAdapter(configs=[str(tmp_path / "r")], docker=True, timeout=7)
        with patch("custodian.adapters.semgrep.find_tool", return_value="docker"), \
             patch("custodian.adapters.semgrep.subprocess.run",
                   side_effect=sp.TimeoutExpired(cmd="semgrep", timeout=7)):
            findings = adapter.run(tmp_path, {"src_root": "src"})
        assert len(findings) == 1
        assert findings[0].rule == "TOOL_ERROR"
        assert "timed out after 7s" in findings[0].message
