# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""X-class detectors removed — placeholder so the file exists without import errors."""
from __future__ import annotations

from custodian.audit_kit.detectors.complexity import build_complexity_detectors


def test_no_complexity_detectors():
    assert build_complexity_detectors() == []
