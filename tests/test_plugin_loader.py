# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from custodian.audit_kit.detector import Detector
from custodian.plugins.loader import load_detectors, load_plugins


def _with_fixture_path(fn):
    """Run fn() with the sample fixture root on sys.path."""
    fixture_root = Path("tests/fixtures/sample_consumer").resolve()
    sys.path.insert(0, str(fixture_root))
    try:
        return fn()
    finally:
        sys.path.remove(str(fixture_root))


def test_load_plugins_imports_sample_callable():
    loaded = _with_fixture_path(
        lambda: load_plugins({"plugins": [{"module": "_custodian.log_scanner:OCLogScanner"}]})
    )
    assert loaded
    assert loaded[0].__name__ == "OCLogScanner"


def test_load_plugins_missing_module_error():
    with pytest.raises(ImportError, match="Failed to import plugin module"):
        load_plugins({"plugins": ["does.not.exist:Thing"]})


def test_load_detectors_imports_and_calls_contributor():
    detectors = _with_fixture_path(
        lambda: load_detectors({"detectors": [{"module": "_custodian.detectors:build_sample_detectors"}]})
    )
    assert len(detectors) == 1
    assert isinstance(detectors[0], Detector)
    assert detectors[0].id == "X1"


def test_load_detectors_rejects_wrong_return_type():
    """A callable that does not return list[Detector] must error clearly."""
    # OCLogScanner() builds an instance, not a list — second guard should fire.
    with pytest.raises(TypeError, match="must return list"):
        _with_fixture_path(
            lambda: load_detectors({"detectors": [{"module": "_custodian.log_scanner:OCLogScanner"}]})
        )


def test_load_detectors_missing_module_error():
    with pytest.raises(ImportError, match="Failed to import plugin module"):
        load_detectors({"detectors": ["does.not.exist:thing"]})
