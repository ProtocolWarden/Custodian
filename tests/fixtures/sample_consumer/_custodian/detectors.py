# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

from custodian.audit_kit.detector import AuditContext, Detector, DetectorResult


def _smoke(_: AuditContext) -> DetectorResult:
    return DetectorResult(count=0, samples=[])


def build_sample_detectors() -> list[Detector]:
    """Sample plugin-contributed detector — proves the registration path runs."""
    return [Detector(id="X1", description="sample plugin detector", status="open", detect=_smoke)]
