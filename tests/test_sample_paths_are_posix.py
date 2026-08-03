# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Every sample path must be a repo-relative POSIX string.

Triage (``custodian.triage.joiner``) groups findings per file by the raw path
string it parses out of a sample, so a file must have exactly ONE spelling
across every producer. Two regressions broke that:

1. **Native separators.** Detectors formatted ``path.relative_to(repo_root)``
   straight into the sample, and ``str(WindowsPath)`` yields backslashes. The
   adapters spelled the same file ``src/foo.py`` while detectors spelled it
   ``src\\foo.py``, so corroborating signals for one file landed in two groups
   and every cross-source verdict was lost on Windows.
2. **Absolute paths.** C1/C6/C8/C13/C28 interpolated the absolute path instead
   of relativising at all. On Windows the drive-letter colon defeats the
   joiner's regex outright, so those findings were dropped from triage; on
   POSIX they formed a third, distinct key for the same file.

Platform coverage is deliberate, because CI runs on Linux where ``str()`` and
``as_posix()`` are indistinguishable:

* ``test_reported_paths_are_repo_relative_posix`` catches regression (2) on
  **both** platforms — an absolute path is absolute everywhere — while
  ``test_every_file_anchored_sample_is_parseable`` covers its Windows form,
  where the drive-letter colon defeats the joiner's regex outright.
* ``test_sample_helper_uses_posix_separators`` and
  ``test_adapter_normalises_*`` drive real Windows path semantics via
  ``PureWindowsPath`` on any host, so they catch regression (1) on **Linux
  CI too**. A platform-conditional test would not have caught the original bug.
* The remaining backslash assertions are exact on Windows and trivially true
  on POSIX; they are kept as executable documentation of the invariant.
"""
from __future__ import annotations

import re
from pathlib import PureWindowsPath
from types import SimpleNamespace

import pytest

from custodian.adapters import ruff as ruff_adapter
from custodian.audit_kit.detectors.stubs import _sample
from custodian.cli.runner import run_repo_audit
from custodian.triage.joiner import group_findings_by_file, parse_sample

# Nested on purpose: a single-component path cannot expose a separator bug.
OFFENDER_REL = "src/pkg/deep/nested/offender.py"
TEST_FILE_REL = "tests/unit/sub/test_probe.py"

_DRIVE_LETTER_RE = re.compile(r"^[A-Za-z]:")

# Trips C1 (TODO), C2 (print), C4, C5, C11, C13 (os.environ), C17, C28 (IP
# literal), C31, C36, C38, C42, D4, D5, D10, G1, N1 and more — a wide enough
# span that a reverted `.as_posix()` anywhere in the detector layer shows up.
OFFENDER_SOURCE = '''
import hashlib
import os
import subprocess
import warnings

ENDPOINT = "10.1.2.3"
TOKEN = os.environ.get("PROBE_TOKEN")


class BadThing(Exception):
    pass


class NeverConstructed:
    pass


def probe(url, headers={}):
    # TODO: revisit ThisSymbolIsGone
    print("probing")
    try:
        pass
    except OSError:
        pass
    except ValueError as exc:
        pass
    subprocess.run("ls", shell=True)
    hashlib.md5(b"x")
    warnings.warn("nope")
    open("f.txt")
    if len(url) == 0:
        return None
    return f"no interpolation"


async def never_awaits():
    return 1


def unreachable():
    return 1
    print("dead")
'''

TEST_SOURCE = '''
import pytest


def test_without_assert():
    x = 1


def helper_never_collected():
    pass


@pytest.mark.parametrize("a", [1])
def test_single_case(a):
    assert a
'''

CONFIG = """
src_root: src
tests_root: tests
architecture:
  invariants:
    - name: tiny
      glob: "src/pkg/deep/**"
      max_lines: 5
"""


@pytest.fixture(scope="module")
def audited(tmp_path_factory):
    """A nested synthetic repo plus its audit result.

    No ``tools:`` block, so no adapter subprocesses run — the adapter half of
    the invariant is covered by the unit tests below instead.
    """
    repo = tmp_path_factory.mktemp("posix_samples") / "repo"
    nested = repo / "src" / "pkg" / "deep" / "nested"
    nested.mkdir(parents=True)
    for pkg in (repo / "src" / "pkg", repo / "src" / "pkg" / "deep", nested):
        (pkg / "__init__.py").write_text("", encoding="utf-8")
    (nested / "offender.py").write_text(OFFENDER_SOURCE, encoding="utf-8")

    sub = repo / "tests" / "unit" / "sub"
    sub.mkdir(parents=True)
    (repo / "tests" / "conftest.py").write_text("# no venv guard\n", encoding="utf-8")
    (sub / "test_probe.py").write_text(TEST_SOURCE, encoding="utf-8")

    design = repo / "docs" / "design"
    design.mkdir(parents=True)
    (design / "0001-a-plan.md").write_text(
        "# Plan\n\nSee [gone](docs/nope.md).\n", encoding="utf-8",
    )
    (repo / "README.md").write_text("# repo\n", encoding="utf-8")
    (repo / ".custodian.yaml").write_text(CONFIG, encoding="utf-8")

    return repo, run_repo_audit(repo)


def _samples(result):
    """Every (detector_id, sample) pair from a firing detector."""
    for det_id, pattern in result.patterns.items():
        if not pattern.get("count", 0):
            continue
        for sample in pattern.get("samples", []):
            yield det_id, sample


def _parsed_paths(result):
    """Every (detector_id, leading path) the joiner can extract."""
    for det_id, sample in _samples(result):
        parsed = parse_sample(sample)
        if parsed is not None:
            yield det_id, parsed[0]


def test_fixture_trips_enough_detectors_to_be_meaningful(audited):
    """Guard the guard: a fixture that stopped firing would pass vacuously."""
    _repo, result = audited
    firing = {det_id for det_id, _ in _samples(result)}
    assert len(firing) >= 15, f"only {len(firing)} detectors fired: {sorted(firing)}"


def test_reported_paths_are_repo_relative_posix(audited):
    """The core invariant, on every path any detector reports."""
    repo, result = audited
    paths = sorted({path for _, path in _parsed_paths(result)})
    assert paths, "no file-anchored samples to check"

    for path in paths:
        assert "\\" not in path, f"native separator in {path!r}"
        assert not path.startswith("/"), f"absolute path in {path!r}"
        assert not _DRIVE_LETTER_RE.match(path), f"absolute path in {path!r}"
        assert (repo / path).exists(), f"{path!r} is not a file relative to the repo"


def test_every_file_anchored_sample_is_parseable(audited):
    """An unparseable sample is silently dropped from triage, not reported.

    This is how the absolute-path regression hid on Windows: ``C:\\...\\x.py``
    fails the joiner's regex at the drive-letter colon.
    """
    _repo, result = audited
    unparseable = [
        (det_id, sample)
        for det_id, sample in _samples(result)
        if ".py:" in sample and parse_sample(sample) is None
    ]
    assert not unparseable, f"samples dropped by the joiner: {unparseable}"


def test_nested_file_has_exactly_one_spelling(audited):
    """The bug's actual shape: one file, two keys, split corroboration."""
    _repo, result = audited
    spellings = {path for _, path in _parsed_paths(result) if path.endswith("offender.py")}
    assert spellings == {OFFENDER_REL}


def test_triage_groups_the_nested_file_under_one_key(audited):
    """End-to-end: what the split keys actually cost."""
    _repo, result = audited
    by_file = group_findings_by_file(result.patterns)

    keys = sorted(k for k in by_file if k.endswith("offender.py"))
    assert keys == [OFFENDER_REL]
    assert len(by_file[OFFENDER_REL]) >= 5, (
        "corroborating detectors are split across keys: "
        f"{sorted(by_file[OFFENDER_REL])}"
    )

    test_keys = sorted(k for k in by_file if k.endswith("test_probe.py"))
    assert test_keys == [TEST_FILE_REL]


def test_c1_reports_a_relative_path(audited):
    """C1 interpolated the absolute path and so never reached triage."""
    _repo, result = audited
    c1_paths = {path for det_id, path in _parsed_paths(result) if det_id == "C1"}
    assert c1_paths == {OFFENDER_REL}


def test_sample_helper_uses_posix_separators():
    """Windows semantics on any host, so Linux CI catches a reverted as_posix().

    ``stubs._sample`` is the extractable form of the pattern every detector
    uses: relativise against ``repo_root``, then format into the sample.
    """
    context = SimpleNamespace(repo_root=PureWindowsPath(r"C:\repo"))
    func = SimpleNamespace(lineno=12, name="do_thing")
    path = PureWindowsPath(r"C:\repo\src\pkg\deep\thing.py")

    assert _sample(path, func, context) == "src/pkg/deep/thing.py:12: do_thing()"


def test_adapter_normalises_absolute_paths(monkeypatch):
    """Adapters must agree with detectors on the spelling, or keys still split.

    Ruff reports absolute filenames; the other adapters share this two-branch
    shape (``relative_to`` else fall back), so this pins the contract for all.
    """
    monkeypatch.setattr(ruff_adapter, "Path", PureWindowsPath)
    result = ruff_adapter._make_relative(
        r"C:\repo\src\pkg\deep\thing.py", PureWindowsPath(r"C:\repo"),
    )
    assert result == "src/pkg/deep/thing.py"


def test_adapter_normalises_cwd_relative_paths(monkeypatch):
    """The fallback branch, which is the one vulture and mypy actually take.

    Both run with ``cwd=repo_path`` and report cwd-relative paths, so
    ``relative_to()`` raises and the ``except`` branch decides the spelling.
    Returning the tool's string verbatim there left native separators intact.
    """
    monkeypatch.setattr(ruff_adapter, "Path", PureWindowsPath)
    result = ruff_adapter._make_relative(
        r"src\pkg\deep\thing.py", PureWindowsPath(r"C:\repo"),
    )
    assert result == "src/pkg/deep/thing.py"


def test_adapter_leaves_empty_filename_as_none(monkeypatch):
    """Normalising the fallback must not turn 'no path' into '.'."""
    monkeypatch.setattr(ruff_adapter, "Path", PureWindowsPath)
    assert ruff_adapter._make_relative("", PureWindowsPath(r"C:\repo")) is None
