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

Imports the variable name from the detector that owns it, never from ``conftest``:
``tests/`` is not a package, so ``from tests.conftest import ...`` resolves only when
the repo root happens to be on ``sys.path`` — true under ``python -m pytest``, false
under the bare ``pytest`` CI runs.
"""
from __future__ import annotations

import os

import pytest

from custodian.audit_kit.detectors.boundary import _ARTIFACT_FILE_ENV


def test_ambient_var_is_cleared_for_every_test():
    """The autouse fixture applies here without this test requesting it."""
    assert _ARTIFACT_FILE_ENV not in os.environ


def test_the_cleared_name_is_the_one_the_detector_reads():
    """Guard against the isolation drifting off the real variable.

    ``conftest`` builds its list from this same constant, so this asserts the
    wiring rather than a duplicated string.
    """
    assert _ARTIFACT_FILE_ENV == "REPOGRAPH_BOUNDARY_ARTIFACT_FILE"


def test_a_test_can_still_opt_in_explicitly():
    """Clearing ambient config must not stop a test setting the var on purpose.

    ``test_boundary_detectors.py`` does exactly this to exercise the
    artifact-configured path; the fixture must not fight it.
    """
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv(_ARTIFACT_FILE_ENV, "/some/explicit/path.json")
        assert os.environ[_ARTIFACT_FILE_ENV] == "/some/explicit/path.json"
    assert _ARTIFACT_FILE_ENV not in os.environ
