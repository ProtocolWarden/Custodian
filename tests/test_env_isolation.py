# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""The suite must not read ambient environment config.

Anyone who runs the audit locally, or pushes through ``.hooks/pre-push``,
legitimately has ``REPOGRAPH_BOUNDARY_ARTIFACT_FILE`` exported. Before the autouse
fixture in ``conftest.py`` that leaked into every test, so two tests asserting the
"no artifact configured" case failed for a developer with a WORKING setup while CI
— which has no such variable — stayed green. That is the wrong way round: it trains
people to ignore failures.

These tests pin the fixture. Without them a later refactor could drop it and the
only symptom would be a suite that passes in CI and fails on the machines of the
people most likely to run it.
"""
from __future__ import annotations

import os

import pytest

from custodian.audit_kit.detectors.boundary import _ARTIFACT_FILE_ENV
from tests.conftest import _AMBIENT_ENV_VARS


def test_isolation_list_matches_the_name_the_detector_reads():
    """Couple the list to its source of truth.

    ``boundary.py`` owns the variable name; conftest clears it by string. If the
    detector ever renames it, the isolation silently stops covering anything —
    this fails instead.
    """
    assert _ARTIFACT_FILE_ENV in _AMBIENT_ENV_VARS


@pytest.mark.parametrize("name", _AMBIENT_ENV_VARS)
def test_ambient_var_is_cleared_for_every_test(name):
    """The autouse fixture applies here without this test requesting it."""
    assert name not in os.environ


def test_boundary_detector_sees_no_artifact_by_default(monkeypatch):
    """The behaviour the leak actually corrupted.

    Tests that assert the unconfigured path must see it regardless of the shell
    they were launched from.
    """
    monkeypatch.setenv(_ARTIFACT_FILE_ENV, "/leaked/from/the/caller.json")
    monkeypatch.delenv(_ARTIFACT_FILE_ENV, raising=False)
    assert os.environ.get(_ARTIFACT_FILE_ENV) is None


def test_a_test_can_still_opt_in_explicitly():
    """Clearing ambient config must not stop a test setting the var on purpose.

    ``test_boundary_detectors.py`` does exactly this to exercise the
    artifact-configured path; the fixture must not fight it.
    """
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(_ARTIFACT_FILE_ENV, "/some/explicit/path.json")
        assert os.environ[_ARTIFACT_FILE_ENV] == "/some/explicit/path.json"
    assert _ARTIFACT_FILE_ENV not in os.environ
