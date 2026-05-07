# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for R-class detectors — README structural conventions."""
from __future__ import annotations

import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.readme import (
    build_readme_detectors,
    detect_r1, detect_r2, detect_r3, detect_r4, detect_r5,
)


def _ctx(tmp_path: Path, content: str | None, repo_key: str = "MyRepo") -> AuditContext:
    if content is not None:
        (tmp_path / "README.md").write_text(textwrap.dedent(content), encoding="utf-8")
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config={"repo_key": repo_key},
        plugin_modules=[],
    )


GOOD = """\
# MyRepo

MyRepo is a thing that does stuff. This is a real intro sentence.

## What this repo is

- a short description
- another bullet

## What this repo is not

- not a sister repo
- not a package manager

## Other content

stuff.
"""


class TestRegistration:
    def test_build_returns_five(self):
        ds = build_readme_detectors()
        assert [d.id for d in ds] == ["R1", "R2", "R3", "R4", "R5"]
        for d in ds:
            assert d.severity == "low"
            assert d.needs == frozenset()


class TestR1:
    def test_present(self, tmp_path):
        assert detect_r1(_ctx(tmp_path, GOOD)).count == 0

    def test_missing(self, tmp_path):
        assert detect_r1(_ctx(tmp_path, None)).count == 1


class TestR2:
    def test_h1_matches(self, tmp_path):
        assert detect_r2(_ctx(tmp_path, GOOD, repo_key="MyRepo")).count == 0

    def test_h1_humanised_match(self, tmp_path):
        c = "# Operations Center\n\nIntro.\n\n## What this repo is\n\n- x\n\n## What this repo is not\n\n- y\n"
        assert detect_r2(_ctx(tmp_path, c, repo_key="OperationsCenter")).count == 0

    def test_h1_with_tagline(self, tmp_path):
        c = "# CxRP — Contract eXecution Routing Protocol\n\nIntro.\n"
        assert detect_r2(_ctx(tmp_path, c, repo_key="CxRP")).count == 0

    def test_h1_with_colon_tagline(self, tmp_path):
        c = "# MyRepo: a thing that does stuff\n\nIntro.\n"
        assert detect_r2(_ctx(tmp_path, c, repo_key="MyRepo")).count == 0

    def test_h1_mismatch(self, tmp_path):
        c = "# WrongName\n\nIntro.\n"
        assert detect_r2(_ctx(tmp_path, c, repo_key="MyRepo")).count == 1

    def test_no_h1(self, tmp_path):
        c = "no h1 here, just text"
        assert detect_r2(_ctx(tmp_path, c)).count == 1

    def test_no_readme_silent(self, tmp_path):
        assert detect_r2(_ctx(tmp_path, None)).count == 0


class TestR3:
    def test_present(self, tmp_path):
        assert detect_r3(_ctx(tmp_path, GOOD)).count == 0

    def test_named_variant(self, tmp_path):
        c = "# X\n\nIntro.\n\n## What X is\n\n- a\n\n## What X is not\n\n- b\n"
        assert detect_r3(_ctx(tmp_path, c, repo_key="X")).count == 0

    def test_includes_variant(self, tmp_path):
        c = "# X\n\nIntro.\n\n## What This Includes\n\n- a\n\n## What X is not\n\n- b\n"
        assert detect_r3(_ctx(tmp_path, c, repo_key="X")).count == 0

    def test_missing(self, tmp_path):
        c = "# X\n\nIntro.\n\n## Some Other Heading\n\nstuff\n"
        assert detect_r3(_ctx(tmp_path, c, repo_key="X")).count == 1


class TestR4:
    def test_present(self, tmp_path):
        assert detect_r4(_ctx(tmp_path, GOOD)).count == 0

    def test_named_variant(self, tmp_path):
        c = "# X\n\nIntro.\n\n## What X is\n\n- a\n\n## What X is not\n\n- b\n"
        assert detect_r4(_ctx(tmp_path, c, repo_key="X")).count == 0

    def test_missing(self, tmp_path):
        c = "# X\n\nIntro.\n\n## What this repo is\n\n- a\n"
        assert detect_r4(_ctx(tmp_path, c, repo_key="X")).count == 1


class TestR5:
    def test_present(self, tmp_path):
        assert detect_r5(_ctx(tmp_path, GOOD)).count == 0

    def test_intro_empty(self, tmp_path):
        c = "# X\n\n\n## What this repo is\n\n- a\n"
        assert detect_r5(_ctx(tmp_path, c, repo_key="X")).count == 1

    def test_intro_only_badges(self, tmp_path):
        c = "# X\n\n![Status](https://img.shields.io/x.svg)\n\n## What this repo is\n\n- a\n"
        assert detect_r5(_ctx(tmp_path, c, repo_key="X")).count == 1

    def test_intro_with_hr_only(self, tmp_path):
        c = "# X\n\n---\n\n## What this repo is\n\n- a\n"
        assert detect_r5(_ctx(tmp_path, c, repo_key="X")).count == 1

    def test_intro_real_prose(self, tmp_path):
        c = "# X\n\n![badge](http://x)\n\nReal sentence here.\n\n## What this repo is\n\n- a\n"
        assert detect_r5(_ctx(tmp_path, c, repo_key="X")).count == 0
