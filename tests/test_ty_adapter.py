# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from custodian.adapters.registry import get_enabled_adapters
from custodian.adapters.ty import TyAdapter, _ty_severity
from custodian.core.finding import HIGH, MEDIUM, LOW


class TestTySeverityMapping:
    def test_error_is_high(self):    assert _ty_severity("error") == HIGH
    def test_warning_is_medium(self): assert _ty_severity("warning") == MEDIUM
    def test_info_is_low(self):      assert _ty_severity("info") == LOW
    def test_case_insensitive(self): assert _ty_severity("ERROR") == HIGH
    def test_unknown_is_medium(self): assert _ty_severity("unknown") == MEDIUM


class TestTyAdapterAvailability:
    def test_available_when_ty_found(self):
        with patch("custodian.adapters.ty.find_tool", return_value="/usr/bin/ty"):
            assert TyAdapter().is_available() is True

    def test_unavailable_when_ty_missing(self):
        with patch("custodian.adapters.ty.find_tool", return_value=None):
            assert TyAdapter().is_available() is False


class TestTyAdapterRun:
    def _run_with_stderr(self, tmp_path, stderr_lines, returncode=1):
        (tmp_path / "src").mkdir(exist_ok=True)
        adapter = TyAdapter()
        proc = MagicMock()
        proc.stderr = "\n".join(stderr_lines)
        proc.stdout = ""
        proc.returncode = returncode
        with patch("subprocess.run", return_value=proc):
            return adapter.run(tmp_path, {})

    def test_binary_not_found(self, tmp_path):
        (tmp_path / "src").mkdir()
        with patch("subprocess.run", side_effect=FileNotFoundError):
            findings = TyAdapter().run(tmp_path, {})
        assert len(findings) == 1
        assert findings[0].rule == "TOOL_UNAVAILABLE"

    def test_no_diagnostics(self, tmp_path):
        findings = self._run_with_stderr(tmp_path, ["Found 0 diagnostics"], returncode=0)
        assert findings == []

    def test_parses_error_line(self, tmp_path):
        path = str(tmp_path / "src" / "foo.py")
        stderr = [f"{path}:10:5: error[invalid-assignment] Object of type `Literal[1]` is not assignable to `str`"]
        findings = self._run_with_stderr(tmp_path, stderr)
        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "ty"
        assert f.rule == "invalid-assignment"
        assert f.severity == HIGH
        assert f.line == 10
        assert "not assignable" in f.message

    def test_path_relativized(self, tmp_path):
        path = str(tmp_path / "src" / "sub" / "bar.py")
        stderr = [f"{path}:5:1: error[missing-return] Missing return statement"]
        findings = self._run_with_stderr(tmp_path, stderr)
        assert findings[0].path == "src/sub/bar.py"

    def test_warning_severity(self, tmp_path):
        path = str(tmp_path / "src" / "x.py")
        stderr = [f"{path}:1:1: warning[possibly-unbound] Variable may be unbound"]
        findings = self._run_with_stderr(tmp_path, stderr)
        assert findings[0].severity == MEDIUM

    def test_non_matching_lines_skipped(self, tmp_path):
        findings = self._run_with_stderr(tmp_path, [
            "Found 2 diagnostics",
            "",
            "Some other output",
        ])
        assert findings == []

    def test_multiple_diagnostics(self, tmp_path):
        p = str(tmp_path / "src" / "a.py")
        stderr = [
            f"{p}:1:1: error[invalid-assignment] Bad assignment",
            f"{p}:2:1: warning[possibly-unbound] Unbound var",
            f"{p}:3:1: info[some-info] Info message",
        ]
        findings = self._run_with_stderr(tmp_path, stderr)
        assert len(findings) == 3
        assert [f.severity for f in findings] == [HIGH, MEDIUM, LOW]

    def test_uses_custom_src_root(self, tmp_path):
        custom = tmp_path / "mycode"
        custom.mkdir()
        proc = MagicMock()
        proc.stderr = ""
        proc.stdout = ""
        with patch("subprocess.run", return_value=proc) as mock_run:
            TyAdapter().run(tmp_path, {"src_root": "mycode"})
        cmd = mock_run.call_args[0][0]
        assert str(custom) in cmd

    def test_timeout_reports_one_dead_tool_not_a_crash(self, tmp_path):
        """A timeout used to propagate and take the whole audit down."""
        (tmp_path / "src").mkdir()
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="ty", timeout=120),
        ):
            findings = TyAdapter().run(tmp_path, {})
        assert len(findings) == 1
        assert findings[0].rule == "TOOL_ERROR"
        assert "timed out" in findings[0].message


class TestTyAdapterDockerMode:
    """Docker mode exists because a host run is unsound, not just noisy.

    The dependencies ty resolves imports against live inside the image for a
    containerized repo. Unresolved imports infer as Unknown, which both
    invents attribute errors and suppresses real ones.
    """

    def _cmd_for(self, tmp_path, **kwargs):
        (tmp_path / "src").mkdir(exist_ok=True)
        proc = MagicMock()
        proc.stderr = ""
        proc.stdout = ""
        with patch("custodian.adapters.ty.find_tool", return_value="docker"), \
             patch("subprocess.run", return_value=proc) as mock_run:
            TyAdapter(docker=True, **kwargs).run(tmp_path, {})
        return mock_run.call_args[0][0]

    def test_available_when_docker_present_even_without_ty(self, tmp_path):
        with patch("custodian.adapters.ty.find_tool", return_value="docker"):
            assert TyAdapter(docker=True).is_available() is True

    def test_unavailable_when_docker_missing(self):
        with patch("custodian.adapters.ty.find_tool", return_value=None):
            assert TyAdapter(docker=True).is_available() is False

    def test_builds_docker_run(self, tmp_path):
        cmd = self._cmd_for(tmp_path, image="docker-worker:latest")
        assert cmd[:3] == ["docker", "run", "--rm"]
        assert "docker-worker:latest" in cmd
        assert cmd[-3:] == ["--output-format", "concise", "src"]

    def test_target_is_relative_so_paths_come_back_repo_relative(self, tmp_path):
        """ty echoes the target form it was given; relative in, relative out."""
        cmd = self._cmd_for(tmp_path)
        assert "src" in cmd
        assert str(tmp_path) not in " ".join(cmd[cmd.index("-w"):])

    def test_mount_and_entrypoint_are_configurable(self, tmp_path):
        """A venv with a hardcoded prefix only works at its own mount point."""
        cmd = self._cmd_for(
            tmp_path, mount="/work", command="/work/.venv/bin/ty",
        )
        assert f"{tmp_path.resolve().as_posix()}:/work" in cmd
        assert cmd[cmd.index("-w") + 1] == "/work"
        assert cmd[cmd.index("--entrypoint") + 1] == "/work/.venv/bin/ty"

    def test_src_root_outside_repo_is_reported_not_silently_wrong(self, tmp_path):
        adapter = TyAdapter(docker=True)
        outside = tmp_path.parent / "elsewhere"
        outside.mkdir(exist_ok=True)
        with patch("custodian.adapters.ty.find_tool", return_value="docker"):
            findings = adapter.run(tmp_path, {"src_root": "../elsewhere"})
        assert len(findings) == 1
        assert findings[0].rule == "TOOL_ERROR"
        assert "outside the repo" in findings[0].message

    def test_relative_paths_from_container_survive_parsing(self, tmp_path):
        """Container paths are already repo-relative and must not be mangled."""
        (tmp_path / "src").mkdir(exist_ok=True)
        proc = MagicMock()
        proc.stderr = "src/foo/bar.py:12:3: error[unresolved-attribute] No attr `x`"
        proc.stdout = ""
        with patch("custodian.adapters.ty.find_tool", return_value="docker"), \
             patch("subprocess.run", return_value=proc):
            findings = TyAdapter(docker=True).run(tmp_path, {})
        assert len(findings) == 1
        assert findings[0].path == "src/foo/bar.py"
        assert findings[0].line == 12


class TestTyRegistryWiring:
    def test_bare_true_gives_a_native_adapter(self):
        adapters = get_enabled_adapters({"tools": {"ty": True}})
        adapter = next(a for a in adapters if a.name == "ty")
        assert adapter._docker is False

    def test_dict_form_passes_docker_settings_through(self):
        adapters = get_enabled_adapters({
            "tools": {"ty": {
                "docker": True,
                "image": "docker-worker:latest",
                "mount": "/work",
                "command": "/work/.venv/bin/ty",
                "timeout": 300,
            }}
        })
        adapter = next(a for a in adapters if a.name == "ty")
        assert adapter._docker is True
        assert adapter._image == "docker-worker:latest"
        assert adapter._mount == "/work"
        assert adapter._command == "/work/.venv/bin/ty"
        assert adapter._timeout == 300

    def test_enabled_false_disables_it(self):
        """`{"enabled": False}` is a truthy dict — the v1 schema spells every
        tool that way, so a bare truthiness test enables a disabled tool."""
        adapters = get_enabled_adapters({"tools": {"ty": {"enabled": False}}})
        assert not [a for a in adapters if a.name == "ty"]

    def test_enabled_true_still_enables_it(self):
        adapters = get_enabled_adapters({"tools": {"ty": {"enabled": True}}})
        assert [a for a in adapters if a.name == "ty"]
