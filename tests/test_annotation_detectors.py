# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""E-class detectors removed — placeholder so the file exists without import errors."""
from __future__ import annotations

from custodian.audit_kit.detectors.annotations import build_annotation_detectors


def test_no_annotation_detectors():
    assert build_annotation_detectors() == []
