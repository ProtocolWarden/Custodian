# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for recursive-glob path matcher."""
from __future__ import annotations

import pytest

from custodian.audit_kit.glob_match import glob_match


class TestSingleStar:
    def test_matches_within_segment(self):
        assert glob_match("foo.py", "*.py")

    def test_does_not_cross_slash(self):
        assert not glob_match("a/foo.py", "*.py")

    def test_anchored_to_segment(self):
        assert glob_match("src/foo.py", "src/*.py")
        assert not glob_match("src/foo/bar.py", "src/*.py")


class TestDoubleStar:
    def test_matches_zero_segments(self):
        # `src/**/foo.py` should match `src/foo.py` (empty middle).
        assert glob_match("src/foo.py", "src/**/foo.py")

    def test_matches_one_segment(self):
        assert glob_match("src/a/foo.py", "src/**/foo.py")

    def test_matches_many_segments(self):
        assert glob_match("src/a/b/c/foo.py", "src/**/foo.py")

    def test_trailing_double_star(self):
        # `src/**` should match anything under src/.
        assert glob_match("src/foo.py", "src/**")
        assert glob_match("src/a/b.py", "src/**")
        assert glob_match("src", "src/**")  # `**` matches empty too

    def test_double_star_with_extension(self):
        # The case that motivated this module: `**/*.py` recursive.
        assert glob_match("src/foo/bar.py", "src/foo/**/*.py")
        assert glob_match("src/foo/bar.py", "src/**/*.py")
        assert glob_match("src/a/b/c.py", "src/**/*.py")
        # Should also match the "no middle segments" case.
        assert glob_match("src/foo.py", "src/**/*.py")

    def test_leading_double_star(self):
        assert glob_match("foo/bar.py", "**/bar.py")
        assert glob_match("a/b/c/bar.py", "**/bar.py")
        # `**` matches empty, so a top-level file should match too.
        assert glob_match("bar.py", "**/bar.py")


class TestQuestionMark:
    def test_single_char(self):
        assert glob_match("test_a.py", "test_?.py")
        assert not glob_match("test_ab.py", "test_?.py")

    def test_does_not_cross_slash(self):
        assert not glob_match("a/b", "?")


class TestCharClass:
    def test_includes(self):
        assert glob_match("a.py", "[abc].py")
        assert glob_match("c.py", "[abc].py")
        assert not glob_match("d.py", "[abc].py")

    def test_excludes(self):
        assert not glob_match("a.py", "[!abc].py")
        assert glob_match("d.py", "[!abc].py")


class TestLiterals:
    def test_exact_match(self):
        assert glob_match("src/foo.py", "src/foo.py")
        assert not glob_match("src/bar.py", "src/foo.py")

    def test_regex_metachars_are_literal(self):
        # `+` is not a glob metachar; treat as literal.
        assert glob_match("a+b", "a+b")
        assert not glob_match("aab", "a+b")


class TestSeparatorNormalisation:
    """Backslash paths must match forward-slash globs.

    Globs are posix by contract, but callers stringify ``Path`` objects that
    are backslash-separated on Windows. Matching one against the other used to
    return False and void the exclusion silently. Written against literal
    backslash strings so these fail on POSIX too if the normalisation is
    removed — a platform-conditional test would not have caught the original.
    """

    def test_backslash_path_matches_posix_glob(self):
        assert glob_match(r"src\config\api_toggles.py", "src/config/**")

    def test_backslash_path_matches_recursive_glob(self):
        assert glob_match(r"src\a\b\c.py", "src/**/*.py")

    def test_forward_slash_path_still_matches(self):
        assert glob_match("src/config/api_toggles.py", "src/config/**")

    def test_normalisation_does_not_make_everything_match(self):
        """Guard against 'fixing' this by loosening the matcher."""
        assert not glob_match(r"src\workflow\stage.py", "src/config/**")
        assert not glob_match(r"src\foo\bar.py", "src/*.py")


class TestRealWorldPatterns:
    @pytest.mark.parametrize("path,pattern,expected", [
        # The bug we hit twice: `**/*.py` should recurse.
        ("src/operations_center/cli/colors.py", "src/operations_center/cli/**/*.py", True),
        ("src/operations_center/cli/main.py", "src/operations_center/cli/**", True),
        ("src/operations_center/cli/sub/foo.py", "src/operations_center/cli/**/*.py", True),
        # Adapter-pattern exclusions.
        ("src/custodian/adapters/ruff.py", "src/custodian/adapters/**", True),
        ("src/custodian/adapters/sub/foo.py", "src/custodian/adapters/**", True),
        # Test exclusions for integration suites.
        ("tests/integration/test_e2e.py", "tests/integration/**", True),
        ("tests/integration/api/test_a.py", "tests/integration/**", True),
        ("tests/unit/test_a.py", "tests/integration/**", False),
    ])
    def test_path_glob(self, path, pattern, expected):
        assert glob_match(path, pattern) == expected
