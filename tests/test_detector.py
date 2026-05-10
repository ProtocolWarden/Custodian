# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

from custodian.audit_kit.detector import AuditContext, Detector, DetectorResult


def test_detector_dataclasses_construct(tmp_path):
    def detect(_: AuditContext) -> DetectorResult:
        return DetectorResult(count=1, samples=["a"])

    detector = Detector(id="C1", description="desc", status="open", detect=detect)
    result = detector.detect(None)  # type: ignore[arg-type]

    assert detector.id == "C1"
    assert result.count == 1
    assert result.samples == ["a"]
