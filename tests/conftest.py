# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parent.parent.resolve()
_EXPECTED_VENV = (_REPO_ROOT / ".venv").resolve()
_ACTIVE_PREFIX = Path(sys.prefix).resolve()
_IN_CI = os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")

if _EXPECTED_VENV.is_dir() and not _IN_CI and _ACTIVE_PREFIX != _EXPECTED_VENV:
    raise SystemExit(
        f"ERROR: Tests must be run inside this project's virtual environment.\n"
        f"Expected: {_EXPECTED_VENV}\n"
        f"Active:   {_ACTIVE_PREFIX}\n\n"
        f"Activate it first:\n"
        f"  source .venv/bin/activate\n"
        f"Or invoke pytest through the venv directly:\n"
        f"  .venv/bin/pytest"
    )


# Ambient environment that must never reach a test. Anyone who runs the audit
# locally, or pushes through .hooks/pre-push, legitimately has this exported —
# so a developer with a WORKING setup saw a red suite while CI stayed green,
# which is the wrong way round and trains people to ignore failures.
#
# Two tests asserted behaviour for the "no artifact configured" case and were
# contradicted by the inherited value:
#   test_reconcile.py::TestAC1SingleSourceOfTruth::test_no_artifact_no_scrub_targets
#   test_boundary_detectors.py::TestB2Required::test_b2_flags_missing_required_boundary_source
#
# Cleared for every test rather than patched at those two call sites: the bug is
# that the suite reads ambient config at all, and a per-test fix leaves the next
# artifact-sensitive test to rediscover it. Tests that WANT the variable set it
# explicitly with monkeypatch.setenv (see test_boundary_detectors.py), which still
# works — this only removes what leaked in from the caller's shell.
_AMBIENT_ENV_VARS = ("REPOGRAPH_BOUNDARY_ARTIFACT_FILE",)


@pytest.fixture(autouse=True)
def _isolate_ambient_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _AMBIENT_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
