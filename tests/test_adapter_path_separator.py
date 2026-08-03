# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Adapter finding paths must be posix on every platform.

Every adapter relativises the absolute path its tool reports against the repo
root. Doing that with ``str(Path(...).relative_to(...))`` yields OS-native
separators, so on Windows the same file is reported as ``src\\foo\\bar.py``
instead of ``src/foo/bar.py``. Config globs (``exclude_paths``,
``tools.coverage.exclude_paths``) are always authored with forward slashes, and
so is the SARIF ``artifactLocation.uri`` these paths become — a backslash path
silently matches nothing and denotes nothing. See PR #55, which fixed the same
class of bug in the detector-side glob matcher.

Each test forces the path flavour to ``PureWindowsPath`` for the duration of
the adapter call, so ``str()`` produces backslashes on POSIX too. Without that,
these would be platform-conditional: green on Linux CI whether or not the
normalisation is present, and only ever red on a Windows workstation — which is
exactly how the bug survived.
"""
from __future__ import annotations

import json
from pathlib import Path, PureWindowsPath
from unittest.mock import MagicMock, patch

import pytest

from custodian.adapters import coverage as coverage_mod
from custodian.adapters import mypy as mypy_mod
from custodian.adapters import ruff as ruff_mod
from custodian.adapters import semgrep as semgrep_mod
from custodian.adapters import vulture as vulture_mod
from custodian.adapters.coverage import CoverageAdapter
from custodian.adapters.mypy import MypyAdapter
from custodian.adapters.ruff import RuffAdapter
from custodian.adapters.semgrep import SemgrepAdapter
from custodian.adapters.vulture import VultureAdapter


def _reported_path(tmp_path: Path) -> str:
    """The absolute path the tool under test will echo back for our fixture file."""
    return str(tmp_path / "src" / "sub" / "bar.py")


def _proc(stdout: str, returncode: int = 1) -> MagicMock:
    proc = MagicMock()
    proc.stdout = stdout
    proc.stderr = ""
    proc.returncode = returncode
    return proc


def _run_adapter(monkeypatch, module, adapter, tmp_path: Path, stdout: str, returncode: int = 1):
    """Run ``adapter`` with Windows path semantics forced, whatever the host is."""
    (tmp_path / "src").mkdir(exist_ok=True)
    monkeypatch.setattr(module, "Path", PureWindowsPath)
    with patch("subprocess.run", return_value=_proc(stdout, returncode)):
        return adapter.run(tmp_path, {})


def test_ruff_path_is_posix(monkeypatch, tmp_path):
    payload = json.dumps([{
        "code": "E722",
        "message": "Do not use bare `except`",
        "filename": _reported_path(tmp_path),
        "location": {"row": 5, "column": 4},
    }])
    findings = _run_adapter(monkeypatch, ruff_mod, RuffAdapter(), tmp_path, payload)
    assert findings[0].path == "src/sub/bar.py"


def test_mypy_path_is_posix(monkeypatch, tmp_path):
    stdout = f"{_reported_path(tmp_path)}:10:5: error: Incompatible types  [assignment]"
    findings = _run_adapter(monkeypatch, mypy_mod, MypyAdapter(), tmp_path, stdout)
    assert findings[0].path == "src/sub/bar.py"


def test_semgrep_path_is_posix(monkeypatch, tmp_path):
    payload = json.dumps({"results": [{
        "check_id": "rules.sql-injection",
        "extra": {"message": "SQL injection risk", "severity": "ERROR"},
        "path": _reported_path(tmp_path),
        "start": {"line": 42, "col": 1},
    }]})
    adapter = SemgrepAdapter(configs=[str(tmp_path / "rules" / "semgrep")])
    findings = _run_adapter(monkeypatch, semgrep_mod, adapter, tmp_path, payload, returncode=0)
    assert findings[0].path == "src/sub/bar.py"


def test_vulture_path_is_posix(monkeypatch, tmp_path):
    stdout = f"{_reported_path(tmp_path)}:5: unused variable 'x' (80% confidence)"
    findings = _run_adapter(monkeypatch, vulture_mod, VultureAdapter(), tmp_path, stdout, returncode=3)
    assert findings[0].path == "src/sub/bar.py"


class _WinPath(PureWindowsPath):
    """``PureWindowsPath`` with the ``resolve()`` the coverage adapter calls.

    Pure paths have no filesystem access, so ``resolve()`` is absent. The
    adapter only needs it to canonicalise before ``relative_to``; the fixture
    path is already absolute, so returning self is faithful.
    """

    def resolve(self):
        return self


def _coverage_findings(monkeypatch, tmp_path: Path, exclude_paths=None):
    """Run the coverage adapter over one absolute-path entry, Windows flavour."""
    payload = {"meta": {"version": "7.6.1"}, "files": {
        _reported_path(tmp_path): {
            "summary": {"num_statements": 10, "covered_lines": 0, "percent_covered": 0.0},
        },
    }}
    (tmp_path / "coverage.json").write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setattr(coverage_mod, "Path", _WinPath)
    # Default (relative) json_path on purpose: the adapter joins it onto the
    # real ``repo_path``, so reading the file stays on real Path objects and
    # only the relativisation under test sees the forced flavour.
    adapter = CoverageAdapter(exclude_paths=exclude_paths)
    return adapter.run(tmp_path, {})


def test_coverage_path_is_posix(monkeypatch, tmp_path):
    findings = _coverage_findings(monkeypatch, tmp_path)
    assert [f.path for f in findings] == ["src/sub/bar.py"]


def test_coverage_exclude_paths_suppresses_on_windows(monkeypatch, tmp_path):
    """The operator-visible symptom: an exclusion that reads as a no-op.

    ``tools.coverage.exclude_paths`` is the one adapter-side config that is
    glob-matched against an adapter-produced path, so a native-separator path
    silently matched nothing and the excluded module kept reporting.
    """
    findings = _coverage_findings(monkeypatch, tmp_path, exclude_paths=["src/sub/**"])
    assert findings == []


@pytest.mark.parametrize("posix_path", ["src/sub/bar.py", "src/a/b/c.py"])
def test_posix_hosts_are_unaffected(posix_path, tmp_path):
    """The normalisation is a no-op when the tool already reports posix.

    Guards against 'fixing' this by rewriting separators in the message or the
    out-of-repo fallback rather than at the relativisation itself.
    """
    (tmp_path / "src").mkdir(exist_ok=True)
    payload = json.dumps([{
        "code": "F401",
        "message": "unused import",
        "filename": str(tmp_path / posix_path),
        "location": {"row": 1, "column": 1},
    }])
    with patch("subprocess.run", return_value=_proc(payload)):
        findings = RuffAdapter().run(tmp_path, {})
    assert findings[0].path == posix_path
