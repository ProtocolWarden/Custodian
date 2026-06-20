# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for the INJ1 prompt-injection signature detector."""

from __future__ import annotations

import subprocess
from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.injection import (
    build_injection_detectors,
    detect_inj1,
)

# Build the invisible chars from codepoints so THIS test file contains none
# (it would otherwise trip the very rule it tests).
_ZWSP = chr(0x200B)
_RLO = chr(0x202E)
_BOM = chr(0xFEFF)
_EXEMPT = "custodian:allow-invisible-chars"


def _ctx(repo_root: Path) -> AuditContext:
    src_root = repo_root / "src"
    tests_root = repo_root / "tests"
    src_root.mkdir(parents=True, exist_ok=True)
    tests_root.mkdir(parents=True, exist_ok=True)
    return AuditContext(
        repo_root=repo_root,
        src_root=src_root,
        tests_root=tests_root,
        config={},
        plugin_modules=[],
        graph=None,
    )


def _git_init(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)


class TestInj1:
    def test_flags_zero_width_space(self, tmp_path: Path) -> None:
        (tmp_path / "evil.py").write_text(f"x = 1{_ZWSP}  # hidden\n", encoding="utf-8")
        _git_init(tmp_path)
        result = detect_inj1(_ctx(tmp_path))
        assert result.count == 1
        assert "U+200B" in result.samples[0]
        assert "evil.py" in result.samples[0]

    def test_flags_bidi_override(self, tmp_path: Path) -> None:
        (tmp_path / "readme.md").write_text(f"approve{_RLO}reject\n", encoding="utf-8")
        _git_init(tmp_path)
        assert detect_inj1(_ctx(tmp_path)).count == 1

    def test_flags_mid_file_bom(self, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_text(f"line1\npre{_BOM}post\n", encoding="utf-8")
        _git_init(tmp_path)
        assert detect_inj1(_ctx(tmp_path)).count == 1

    def test_clean_repo_no_findings(self, tmp_path: Path) -> None:
        (tmp_path / "ok.py").write_text("def f():\n    return 42\n", encoding="utf-8")
        (tmp_path / "doc.md").write_text("# Title\n\nNormal prose.\n", encoding="utf-8")
        _git_init(tmp_path)
        assert detect_inj1(_ctx(tmp_path)).count == 0

    def test_exempt_marker_skips_file(self, tmp_path: Path) -> None:
        # A legitimate handler / fixture that opts out by carrying the marker.
        (tmp_path / "sanitizer.py").write_text(
            f"# {_EXEMPT}\nPATTERN = '{_ZWSP}'\n", encoding="utf-8"
        )
        _git_init(tmp_path)
        assert detect_inj1(_ctx(tmp_path)).count == 0

    def test_reports_codepoint_not_surrounding_text(self, tmp_path: Path) -> None:
        # D-INJ-3: never re-launder attacker content; only the codepoint+position.
        secret = "ATTACKER-PAYLOAD-DO-NOT-LEAK"
        (tmp_path / "x.py").write_text(f"# {secret}{_ZWSP}\n", encoding="utf-8")
        _git_init(tmp_path)
        sample = detect_inj1(_ctx(tmp_path)).samples[0]
        assert secret not in sample
        assert "U+200B" in sample

    def test_detector_is_deprecated_non_gating(self) -> None:
        # Outer defense: must be skipped by the default gate (opt-in only) so a
        # repo's own injection-handling code can't red the fleet-wide audit.
        dets = build_injection_detectors()
        assert len(dets) == 1
        assert dets[0].id == "INJ1"
        assert dets[0].deprecated is True
