# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for the triage layer (joiner + matrix + integrated pass)."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from custodian.triage import (
    Verdict,
    group_findings_by_file,
    parse_sample,
    triage_file,
    triage_result,
)


# ── joiner ────────────────────────────────────────────────────────────────────


class TestParseSample:
    def test_path_line_message(self):
        assert parse_sample("src/foo.py:42: bad thing") == ("src/foo.py", 42, "bad thing")

    def test_path_no_line(self):
        assert parse_sample("src/foo.py: bad thing") == ("src/foo.py", None, "bad thing")

    def test_no_match_for_non_python(self):
        assert parse_sample("README.md:5: oops") is None

    def test_no_match_for_freeform(self):
        assert parse_sample("just a sentence") is None


class TestGroupByFile:
    def test_groups_across_detectors(self):
        patterns = {
            "U1": {"count": 1, "samples": ["src/a.py:10: stub"]},
            "D1": {"count": 1, "samples": ["src/a.py:10: never called"]},
            "C29": {"count": 1, "samples": ["src/b.py: too big"]},
        }
        out = group_findings_by_file(patterns)
        assert set(out["src/a.py"]) == {"U1", "D1"}
        assert set(out["src/b.py"]) == {"C29"}

    def test_skips_zero_count(self):
        patterns = {"U1": {"count": 0, "samples": []}}
        assert group_findings_by_file(patterns) == {}


# ── matrix ────────────────────────────────────────────────────────────────────


class TestTriageFile:
    def test_uncalled_plus_stub_is_delete(self):
        assert triage_file({"U1": [(1, "stub")], "D1": [(1, "uncalled")]}) == (Verdict.DELETE,)

    def test_stub_alone_is_implement(self):
        assert triage_file({"U1": [(1, "stub")]}) == (Verdict.IMPLEMENT,)

    def test_uncalled_alone_is_delete(self):
        assert triage_file({"D1": [(1, "uncalled")]}) == (Verdict.DELETE,)

    def test_unwired_is_wire(self):
        assert triage_file({"D6": [(1, "class never constructed")]}) == (Verdict.WIRE,)

    def test_bloat_plus_noise_is_redesign(self):
        assert triage_file({"C29": [(1, "big")], "C33": [(1, "noisy")]}) == (Verdict.REDESIGN,)

    def test_bloat_alone_is_no_verdict(self):
        assert triage_file({"C29": [(1, "big")]}) == ()

    def test_dead_text_is_cleanup(self):
        assert triage_file({"C34": [(1, "commented def")]}) == (Verdict.CLEANUP,)

    def test_multiple_verdicts_priority_order(self):
        hits = {
            "U1": [(1, "stub")],
            "D1": [(1, "uncalled")],
            "D6": [(1, "unwired")],
            "C34": [(1, "commented")],
        }
        assert triage_file(hits) == (Verdict.DELETE, Verdict.WIRE, Verdict.CLEANUP)

    def test_vulture_counts_as_uncalled(self):
        assert triage_file({"VULTURE": [(1, "unused fn")], "U1": [(1, "stub")]}) == (Verdict.DELETE,)


class TestTriageResult:
    def test_full_pipeline(self):
        patterns = {
            "U1": {"count": 1, "samples": ["src/dead.py:1: stub"]},
            "D1": {"count": 1, "samples": ["src/dead.py:1: never called"]},
            "C29": {"count": 1, "samples": ["src/big.py: too big"]},
            "C33": {"count": 1, "samples": ["src/big.py: noisy"]},
            "C34": {"count": 1, "samples": ["src/comments.py:5: # def old():"]},
        }
        out = triage_result(patterns)
        verdicts_by_path = {fv.path: fv.verdicts for fv in out}
        assert verdicts_by_path["src/dead.py"] == (Verdict.DELETE,)
        assert verdicts_by_path["src/big.py"] == (Verdict.REDESIGN,)
        assert verdicts_by_path["src/comments.py"] == (Verdict.CLEANUP,)

    def test_priority_sort(self):
        patterns = {
            "C34": {"count": 1, "samples": ["src/c.py:1: commented"]},
            "U1":  {"count": 1, "samples": ["src/a.py:1: stub"]},
            "D1":  {"count": 1, "samples": ["src/a.py:1: uncalled"]},
            "D6":  {"count": 1, "samples": ["src/b.py:1: unwired"]},
        }
        primaries = [fv.primary() for fv in triage_result(patterns)]
        assert primaries == [Verdict.DELETE, Verdict.WIRE, Verdict.CLEANUP]


# ── CLI integration ──────────────────────────────────────────────────────────


class TestCLI:
    def test_reads_audit_json(self, tmp_path):
        audit = {
            "patterns": {
                "U1": {"count": 1, "samples": ["src/x.py:1: stub"]},
                "D1": {"count": 1, "samples": ["src/x.py:1: uncalled"]},
            }
        }
        p = tmp_path / "audit.json"
        p.write_text(json.dumps(audit))
        proc = subprocess.run(
            [sys.executable, "-m", "custodian.cli.triage", str(p)],
            capture_output=True, text=True, check=True,
        )
        assert "DELETE" in proc.stdout
        assert "src/x.py" in proc.stdout

    def test_json_output(self, tmp_path):
        audit = {"patterns": {"D6": {"count": 1, "samples": ["src/y.py:1: unwired"]}}}
        p = tmp_path / "audit.json"
        p.write_text(json.dumps(audit))
        proc = subprocess.run(
            [sys.executable, "-m", "custodian.cli.triage", "--json", str(p)],
            capture_output=True, text=True, check=True,
        )
        out = json.loads(proc.stdout)
        assert out[0]["primary"] == "WIRE"
        assert out[0]["path"] == "src/y.py"

    def test_only_filter(self, tmp_path):
        audit = {
            "patterns": {
                "U1": {"count": 1, "samples": ["src/a.py:1: stub"]},
                "D1": {"count": 1, "samples": ["src/a.py:1: uncalled"]},
                "D6": {"count": 1, "samples": ["src/b.py:1: unwired"]},
            }
        }
        p = tmp_path / "audit.json"
        p.write_text(json.dumps(audit))
        proc = subprocess.run(
            [sys.executable, "-m", "custodian.cli.triage", "--only", "WIRE", str(p)],
            capture_output=True, text=True, check=True,
        )
        assert "src/b.py" in proc.stdout
        assert "src/a.py" not in proc.stdout


# ── integrated pass ─────────────────────────────────────────────────────────


class TestIntegratedPass:
    def test_audit_triage_flag_emits_triage_patterns(self, tmp_path):
        repo = tmp_path / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / ".custodian").mkdir()
        # A stub file flagged by U1; nothing else uses it (Vulture should flag).
        (repo / "src" / "dead.py").write_text(
            "def unused_fn():\n    raise NotImplementedError\n"
        )
        (repo / ".custodian" / "config.yaml").write_text(
            "repo_key: t\nsrc_root: src\ntests_root: tests\n"
            "audit:\n  triage: true\n"
            "tools:\n  ruff: false\n  vulture: false\n"
        )
        from custodian.cli.runner import run_repo_audit
        result = run_repo_audit(repo)
        triage_keys = [k for k in result.patterns if k.startswith("TRIAGE_")]
        # U1 alone (no uncalled signal) → IMPLEMENT
        assert any("IMPLEMENT" in k for k in triage_keys)
        for k in triage_keys:
            assert result.patterns[k]["source"] == "triage"
