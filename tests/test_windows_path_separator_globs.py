# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Glob matching must be path-separator agnostic.

Config globs are always authored with forward slashes (``src/config/**``),
but on Windows ``Path.relative_to()`` stringifies with backslashes
(``src\\config\\api_toggles.py``). Matching one against the other fails
silently, which made every ``exclude_paths`` and ``c13_allowed_paths`` entry
a no-op on Windows: adjudicated exemptions re-reported as findings, and one
consumer repo's audit was inflated by roughly 465 of 525 findings before the
cause was identified.

These assertions are written against literal backslash strings rather than
real paths, so they fail on POSIX CI too if the normalisation is removed —
a platform-conditional regression test would not have caught the original bug.
"""
from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath

import pytest

from custodian.audit_kit.code_health import _matches_any, _norm_rel, detect_c13
from custodian.audit_kit.detector import AuditContext


@pytest.mark.parametrize(
    "raw, expected",
    [
        (r"src\config\api_toggles.py", "src/config/api_toggles.py"),
        ("src/config/api_toggles.py", "src/config/api_toggles.py"),
        (r"src\a\b\c.py", "src/a/b/c.py"),
        ("", ""),
        (PureWindowsPath(r"src\config\api_toggles.py"), "src/config/api_toggles.py"),
        (PurePosixPath("src/config/api_toggles.py"), "src/config/api_toggles.py"),
    ],
)
def test_norm_rel_yields_posix_form(raw, expected):
    assert _norm_rel(raw) == expected


def test_backslash_path_matches_forward_slash_glob():
    """The regression: this returned False and voided every exclusion."""
    assert _matches_any(r"src\config\api_toggles.py", ["src/config/**"])


def test_forward_slash_path_still_matches():
    assert _matches_any("src/config/api_toggles.py", ["src/config/**"])


def test_path_objects_are_accepted_and_normalised():
    assert _matches_any(PureWindowsPath(r"src\config\x.py"), ["src/config/**"])
    assert _matches_any(PurePosixPath("src/config/x.py"), ["src/config/**"])


def test_normalisation_does_not_make_everything_match():
    """Guard against 'fixing' the bug by loosening the matcher."""
    assert not _matches_any(r"src\workflow\stage.py", ["src/config/**"])
    assert not _matches_any("src/workflow/stage.py", ["src/config/**"])


def test_c13_allowed_paths_actually_exempts(tmp_path):
    """End-to-end: the config key a consumer repo writes must take effect."""
    src = tmp_path / "src"
    (src / "config").mkdir(parents=True)
    (src / "workflow").mkdir(parents=True)
    body = "import os\nX = os.environ.get('A')\n"
    (src / "config" / "settings.py").write_text(body, encoding="utf-8")
    (src / "workflow" / "stage.py").write_text(body, encoding="utf-8")

    context = AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path / "tests",
        config={"audit": {"c13_allowed_paths": ["src/config/**"]}},
        plugin_modules=[],
    )

    result = detect_c13(context)
    joined = " ".join(result.samples)
    assert "settings.py" not in joined, "allowed path was not exempted"
    assert result.count == 1, f"expected only the workflow hit, got {result.count}"
