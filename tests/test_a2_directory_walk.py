# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for the A2 directory-structure walk (detectors/directory.py).

Regression cover for 2026-07-26: an unreadable entry inside a hidden
directory aborted the ENTIRE audit before any detector reported. A repo
carrying a HuggingFace model cache could not be audited at all on Windows,
because hub snapshots are symlinks into blobs/ created inside Linux
containers and stat'ing one raises OSError (WinError 1920).

The walk must therefore (a) never descend into hidden/generated trees, and
(b) survive an entry that raises while being walked.
"""
from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.directory import _iter_candidate_dirs, detect_d1


def _ctx(tmp_path: Path, config: dict | None = None) -> AuditContext:
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
    )


class TestCandidateWalk:
    def test_hidden_and_generated_trees_are_pruned(self, tmp_path):
        (tmp_path / "src" / "keep").mkdir(parents=True)
        (tmp_path / ".cache" / "huggingface" / "hub").mkdir(parents=True)
        (tmp_path / "__pycache__" / "inner").mkdir(parents=True)

        names = {p.name for p in _iter_candidate_dirs(tmp_path)}
        assert "keep" in names
        # Not just the hidden dir itself — its whole subtree must be unvisited,
        # which is the part rglob could not do.
        assert "huggingface" not in names
        assert "hub" not in names
        assert "inner" not in names

    def test_does_not_descend_into_hidden_subtree(self, tmp_path):
        # If the walk descends, it stats what is inside; that is the crash.
        deep = tmp_path / ".venv" / "lib" / "site-packages"
        deep.mkdir(parents=True)
        visited = [str(p) for p in _iter_candidate_dirs(tmp_path)]
        assert not any(".venv" in v for v in visited)

    def test_unreadable_subtree_does_not_abort_the_walk(self, tmp_path, monkeypatch):
        (tmp_path / "src").mkdir()
        (tmp_path / "other").mkdir()

        import custodian.audit_kit.detectors.directory as mod

        real_walk = mod.os.walk

        def _exploding_walk(top, onerror=None, **kwargs):
            # Simulate the OS refusing a subtree mid-walk: os.walk reports it
            # via onerror and continues, which is exactly what must not become
            # fatal.
            if onerror is not None:
                onerror(OSError(1920, "The file cannot be accessed by the system"))
            yield from real_walk(top, onerror=onerror, **kwargs)

        monkeypatch.setattr(mod.os, "walk", _exploding_walk)
        names = {p.name for p in _iter_candidate_dirs(tmp_path)}
        assert {"src", "other"} <= names

    def test_walk_is_deterministic(self, tmp_path):
        for name in ("c", "a", "b"):
            (tmp_path / name).mkdir()
        first = [p.name for p in _iter_candidate_dirs(tmp_path)]
        assert first == sorted(first)


class TestDetectorSurvivesCacheDirs:
    def test_detector_reports_instead_of_raising(self, tmp_path):
        # A rule that would match, plus a hidden cache alongside it. Before the
        # fix the cache aborted the run; now the rule is evaluated normally.
        (tmp_path / "caps" / "alpha").mkdir(parents=True)
        (tmp_path / ".cache" / "models").mkdir(parents=True)
        config = {
            "architecture": {
                "directory_structure": [
                    {"name": "capability", "glob": "caps/*", "required_dirs": ["domain"]}
                ]
            }
        }
        result = detect_d1(_ctx(tmp_path, config))
        assert result.count == 1
        assert any("missing dir:domain" in s for s in result.samples)
