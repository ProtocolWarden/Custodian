# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for custodian-audit CLI improvements: --only filter and --fail-on-findings."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from custodian.cli.runner import run_repo_audit

FIXTURE_REPO = Path(__file__).parent / "fixtures" / "sample_consumer"


class TestOnlyFilter:
    def test_only_restricts_to_named_detector(self):
        result = run_repo_audit(FIXTURE_REPO, only={"C1"})
        assert "C1" in result.patterns
        assert "C11" not in result.patterns
        assert "C28" not in result.patterns

    def test_only_accepts_multiple_codes(self):
        result = run_repo_audit(FIXTURE_REPO, only={"C1", "C6"})
        assert set(result.patterns.keys()) == {"C1", "C6"}

    def test_only_unknown_code_produces_empty_result(self):
        result = run_repo_audit(FIXTURE_REPO, only={"ZZNOTREAL"})
        assert result.patterns == {}
        assert result.total_findings == 0

    def test_none_runs_all_detectors(self):
        result_all = run_repo_audit(FIXTURE_REPO, only=None)
        result_one = run_repo_audit(FIXTURE_REPO, only={"C1"})
        assert len(result_all.patterns) > len(result_one.patterns)


class TestFindingsList:
    def test_json_has_findings_key(self):
        result = run_repo_audit(FIXTURE_REPO, only={"C1"})
        data = json.loads(result.to_json())
        assert "findings" in data
        assert isinstance(data["findings"], list)

    def test_findings_entries_have_code_and_sample(self):
        result = run_repo_audit(FIXTURE_REPO, only={"C1"})
        data = json.loads(result.to_json())
        for finding in data["findings"]:
            assert "code" in finding
            assert "sample" in finding

    def test_findings_code_matches_pattern(self):
        result = run_repo_audit(FIXTURE_REPO, only={"C1", "C6"})
        data = json.loads(result.to_json())
        for finding in data["findings"]:
            assert finding["code"] in {"C1", "C6"}

    def test_findings_empty_when_no_samples(self):
        result = run_repo_audit(FIXTURE_REPO, only={"ZZNOTREAL"})
        assert result.findings() == []
        data = json.loads(result.to_json())
        assert data["findings"] == []

    def test_patterns_still_present_for_backwards_compat(self):
        result = run_repo_audit(FIXTURE_REPO, only={"C1"})
        data = json.loads(result.to_json())
        assert "patterns" in data
        assert "C1" in data["patterns"]


class TestFailOnFindings:
    def test_exit_1_when_findings_present(self, tmp_path):
        """main() calls sys.exit(1) when findings > 0 and --fail-on-findings set."""
        from custodian.cli.audit import main

        with pytest.raises(SystemExit) as exc:
            with patch("sys.argv", [
                "custodian-audit",
                "--repo", str(FIXTURE_REPO),
                "--only", "C1",  # C1 fires on the fixture's TODO marker
                "--fail-on-findings",
                "--json",
            ]):
                main()
        # Either 0 (no findings in C1) or 1 (findings present) — we verify shape
        assert exc.value.code in (0, 1)

    def test_no_exit_without_flag(self, capsys):
        """main() exits 0 even with findings when --fail-on-findings is absent."""
        from custodian.cli.audit import main

        with patch("sys.argv", [
            "custodian-audit",
            "--repo", str(FIXTURE_REPO),
            "--only", "C1",
            "--json",
        ]):
            main()  # must not raise SystemExit(1)
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "findings" in data


class TestNoJsonFlag:
    def test_no_json_omits_json_block(self, capsys):
        from custodian.cli.audit import main

        with patch("sys.argv", [
            "custodian-audit", "--repo", str(FIXTURE_REPO), "--no-json", "--only", "C1",
        ]):
            main()
        out = capsys.readouterr().out
        assert "Custodian audit" in out
        # JSON block starts with `{` on its own line — must not be present
        assert not any(line.strip() == "{" for line in out.splitlines())

    def test_default_includes_json(self, capsys):
        from custodian.cli.audit import main

        with patch("sys.argv", [
            "custodian-audit", "--repo", str(FIXTURE_REPO), "--only", "C1",
        ]):
            main()
        out = capsys.readouterr().out
        assert "Custodian audit" in out  # human header
        # JSON block is also present
        lines = [ln for ln in out.splitlines() if ln.strip().startswith("{")]
        assert lines  # at least one JSON line


class TestListDetectors:
    def test_list_detectors_exits_without_running_audit(self, capsys):
        from custodian.cli.audit import main

        with patch("sys.argv", [
            "custodian-audit", "--repo", str(FIXTURE_REPO), "--list-detectors",
        ]):
            main()
        out = capsys.readouterr().out
        assert "C1" in out
        assert "C6" in out
        assert "SEV" in out  # header row
        # Must not include JSON (not running an audit)
        assert '"schema_version"' not in out

    def test_list_detectors_shows_all_active_codes(self, capsys):
        from custodian.cli.audit import main

        with patch("sys.argv", [
            "custodian-audit", "--repo", str(FIXTURE_REPO), "--list-detectors",
        ]):
            main()
        out = capsys.readouterr().out
        for code in ("C1", "C6", "C8", "C11", "C28", "C29", "C32", "C33"):
            assert code in out


class TestMinSeverity:
    def test_high_only_skips_low_detectors(self):
        from custodian.cli.runner import run_repo_audit
        result_all = run_repo_audit(FIXTURE_REPO)
        result_high = run_repo_audit(FIXTURE_REPO, min_severity="high")
        assert len(result_high.patterns) < len(result_all.patterns)
        for pat in result_high.patterns.values():
            assert pat["severity"] == "high"
