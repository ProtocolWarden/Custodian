# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""I-class detectors removed — placeholder so the file exists without import errors."""
from __future__ import annotations

from custodian.audit_kit.detectors.imports import build_import_detectors


def test_no_import_detectors():
    assert build_import_detectors() == []
