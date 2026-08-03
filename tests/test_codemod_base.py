# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations


from custodian.codemods.base import Codemod, CodemodeResult, run_codemods
from custodian.core.finding import Finding, LOW


def _finding(rule="F401", path="src/foo.py"):
    return Finding(tool="ruff", rule=rule, severity=LOW, path=path, line=1, message="msg")


class _AddCommentCodemod(Codemod):
    applies_to = frozenset({"F401"})

    def transform(self, path, source, findings):
        return "# fixed\n" + source


class _NoOpCodemod(Codemod):
    applies_to = frozenset({"F401"})

    def transform(self, path, source, findings):
        return None


class _UnrelatedCodemod(Codemod):
    applies_to = frozenset({"E722"})

    def transform(self, path, source, findings):
        return "# changed\n" + source


class TestCodemodeResult:
    def test_diff_generated(self, tmp_path):
        f = tmp_path / "x.py"
        r = CodemodeResult(path=f, original="a = 1\n", modified="# changed\na = 1\n")
        assert "# changed" in r.diff
        assert "@@" in r.diff

    def test_empty_diff_when_unchanged(self, tmp_path):
        f = tmp_path / "x.py"
        r = CodemodeResult(path=f, original="a = 1\n", modified="a = 1\n")
        assert r.diff == ""


class TestRunCodemods:
    def test_applies_matching_codemod(self, tmp_path):
        f = tmp_path / "src" / "foo.py"
        f.parent.mkdir(parents=True)
        f.write_text("x = 1\n", encoding="utf-8")
        findings = [_finding(rule="F401", path="src/foo.py")]
        results = run_codemods(tmp_path, findings, [_AddCommentCodemod()], dry_run=True)
        assert len(results) == 1
        assert "# fixed" in results[0].modified

    def test_dry_run_does_not_write(self, tmp_path):
        f = tmp_path / "src" / "foo.py"
        f.parent.mkdir(parents=True)
        f.write_text("x = 1\n", encoding="utf-8")
        findings = [_finding(rule="F401", path="src/foo.py")]
        run_codemods(tmp_path, findings, [_AddCommentCodemod()], dry_run=True)
        assert f.read_text(encoding="utf-8") == "x = 1\n"

    def test_apply_writes_file(self, tmp_path):
        f = tmp_path / "src" / "foo.py"
        f.parent.mkdir(parents=True)
        f.write_text("x = 1\n", encoding="utf-8")
        findings = [_finding(rule="F401", path="src/foo.py")]
        run_codemods(tmp_path, findings, [_AddCommentCodemod()], dry_run=False)
        assert "# fixed" in f.read_text(encoding="utf-8")

    def test_noop_codemod_no_result(self, tmp_path):
        f = tmp_path / "src" / "foo.py"
        f.parent.mkdir(parents=True)
        f.write_text("x = 1\n", encoding="utf-8")
        findings = [_finding(rule="F401", path="src/foo.py")]
        results = run_codemods(tmp_path, findings, [_NoOpCodemod()])
        assert results == []

    def test_unrelated_codemod_not_applied(self, tmp_path):
        f = tmp_path / "src" / "foo.py"
        f.parent.mkdir(parents=True)
        f.write_text("x = 1\n", encoding="utf-8")
        findings = [_finding(rule="F401", path="src/foo.py")]
        results = run_codemods(tmp_path, findings, [_UnrelatedCodemod()], dry_run=True)
        assert results == []

    def test_finding_with_no_path_skipped(self, tmp_path):
        f = Finding(tool="t", rule="F401", severity=LOW, path=None, line=None, message="m")
        results = run_codemods(tmp_path, [f], [_AddCommentCodemod()])
        assert results == []

    def test_nonexistent_file_skipped(self, tmp_path):
        findings = [_finding(path="src/does_not_exist.py")]
        results = run_codemods(tmp_path, findings, [_AddCommentCodemod()])
        assert results == []

    def test_can_fix_uses_tool_colon_rule(self, tmp_path):
        class SpecificCodemod(Codemod):
            applies_to = frozenset({"ruff:F401"})
            def transform(self, path, source, findings): return "# x\n" + source

        f = tmp_path / "src" / "foo.py"
        f.parent.mkdir(parents=True)
        f.write_text("x = 1\n", encoding="utf-8")
        findings = [_finding(rule="F401", path="src/foo.py")]
        results = run_codemods(tmp_path, findings, [SpecificCodemod()], dry_run=True)
        assert len(results) == 1
