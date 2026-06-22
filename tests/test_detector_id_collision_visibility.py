# SPDX-License-Identifier: AGPL-3.0-or-later
"""Detector-ID collisions must be VISIBLE, not silently misattributed.

When two detectors share an id (builtin readme R2 vs a repo's custom .console R2),
their findings merge under one entry whose title is only the first detector's — so a
.console violation surfaced as "README first H1" and wedged a consumer's goal lane.
#48 fixed the count masking; this covers making the collision *visible* in output +
at load time."""

from __future__ import annotations

import logging

from custodian.audit_kit.result import AuditResult, collision_note


def _entry(desc, count, source, samples=()):
    return {
        "description": desc,
        "count": count,
        "severity": "medium",
        "source": source,
        "samples": list(samples),
    }


def test_collision_note_marks_collided_pattern():
    r = AuditResult()
    r.add_pattern("R2", _entry("README first H1 does not match repo name", 0, "builtin"))
    r.add_pattern("R2", _entry(".console budget", 1, "custom", [".console/task.md missing ## Objective"]))
    pat = r.patterns["R2"]
    assert pat["count"] == 1  # #48: count un-masked
    note = collision_note(pat)
    assert "COLLISION" in note
    assert "builtin" in note and "custom" in note  # names the colliding sources


def test_collision_note_empty_for_normal_pattern():
    assert collision_note({"count": 3}) == ""
    assert collision_note({"count": 3, "collision": False}) == ""


def test_warn_detector_id_collisions_logs_each_duplicate(caplog):
    from custodian.cli.runner import _warn_detector_id_collisions

    class _D:
        def __init__(self, id_, desc, source):
            self.id = id_
            self.description = desc
            self.source = source

    detectors = [
        _D("R2", "README first H1", "builtin"),
        _D("R2", ".console budget", "custom"),
        _D("D12", "incomplete integration", "builtin"),  # unique → no warning
    ]
    with caplog.at_level(logging.WARNING):
        _warn_detector_id_collisions(detectors)
    msgs = [r.getMessage() for r in caplog.records]
    collide = [m for m in msgs if "collision on 'R2'" in m]
    assert collide, msgs
    assert "builtin" in collide[0] and "custom" in collide[0]
    assert not any("D12" in m for m in msgs)  # unique id never warns
