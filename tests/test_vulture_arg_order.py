# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Vulture argument order, and not mistaking a failed run for a clean one.

Two defects, one masking the other:

1. Every PATH must precede the options. The adapter used to emit
   ``vulture <src> --min-confidence=N <tests>``; vulture's argparse rejects a
   positional after an option and exits 2 with an empty stdout.
2. The adapter ignored the return code, so that empty stdout became
   ``count=0, status=pass`` — a tool that never ran, reported as a clean repo.

This fired for any repo whose tests directory exists, which is most of them.
Measured on a consumer repo: 0 findings before, 489 after.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from custodian.adapters.vulture import VultureAdapter


def _run(tmp_path, *, stdout="", stderr="", returncode=0, make_tests=True):
    (tmp_path / "src").mkdir(exist_ok=True)
    if make_tests:
        (tmp_path / "tests").mkdir(exist_ok=True)
    proc = MagicMock(stdout=stdout, stderr=stderr, returncode=returncode)
    with patch("custodian.adapters.vulture.find_tool", return_value="vulture"), \
         patch("custodian.adapters.vulture.subprocess.run", return_value=proc) as run:
        findings = VultureAdapter().run(tmp_path, {"src_root": "src", "tests_root": "tests"})
    return findings, run.call_args[0][0]


class TestArgumentOrder:
    def test_all_paths_precede_the_options(self, tmp_path):
        """The regression: a positional after --min-confidence exits 2."""
        _, cmd = _run(tmp_path)
        opt_index = next(i for i, a in enumerate(cmd) if a.startswith("--min-confidence"))
        path_indexes = [i for i, a in enumerate(cmd) if "src" in a or "tests" in a]
        assert path_indexes, "expected path arguments in the command"
        assert max(path_indexes) < opt_index, f"path follows an option: {cmd}"

    def test_tests_root_is_still_included(self, tmp_path):
        _, cmd = _run(tmp_path)
        assert any(a.endswith("tests") for a in cmd)

    def test_whitelist_is_included_before_options(self, tmp_path):
        (tmp_path / ".vulture_whitelist.py").write_text("# wl\n", encoding="utf-8")
        _, cmd = _run(tmp_path)
        wl = next(i for i, a in enumerate(cmd) if a.endswith(".vulture_whitelist.py"))
        opt = next(i for i, a in enumerate(cmd) if a.startswith("--min-confidence"))
        assert wl < opt


class TestFailedRunIsNotAPass:
    def test_bad_arguments_report_a_tool_error(self, tmp_path):
        findings, _ = _run(
            tmp_path,
            returncode=2,
            stderr="usage: vulture [options] [PATH ...]\nvulture: error: unrecognized arguments: tests",
        )
        assert len(findings) == 1
        assert findings[0].rule == "TOOL_ERROR"
        assert "exited 2" in findings[0].message
        assert "unrecognized arguments" in findings[0].message

    def test_clean_repo_is_still_clean(self, tmp_path):
        """Exit 0 with no output is a genuine pass, not an error."""
        findings, _ = _run(tmp_path, returncode=0, stdout="")
        assert findings == []

    def test_exit_3_means_findings_and_is_parsed(self, tmp_path):
        """vulture exits 3 when it HAS findings — that is not a failure."""
        out = "src/a.py:12: unused variable 'x' (60% confidence)\n"
        findings, _ = _run(tmp_path, returncode=3, stdout=out)
        assert len(findings) == 1
        assert findings[0].rule == "UNUSED_VARIABLE"
        assert findings[0].line == 12

    def test_nonzero_with_output_still_parses(self, tmp_path):
        """Output present means it ran; do not discard real findings."""
        out = "src/a.py:5: unused import 'os' (90% confidence)\n"
        findings, _ = _run(tmp_path, returncode=1, stdout=out)
        assert len(findings) == 1
        assert findings[0].rule == "UNUSED_IMPORT"
