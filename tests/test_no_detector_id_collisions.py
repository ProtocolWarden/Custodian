# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""No two builtin detectors may register the same id.

Colliding ids merge under a single entry whose displayed title is only the
first-registered detector's, so findings get misattributed. A ".console file
over its line budget" finding was reported as "README.md missing at repo root"
for as long as reconcile.py's R1/R2 sat on top of readme.py's R1..R6 family.

`_warn_detector_id_collisions` logs this at runtime, but a warning in a stream
of hundreds of findings is easy to miss — and reading it required running the
audit. This asserts it structurally instead.
"""
from __future__ import annotations

from collections import defaultdict

import pytest

from custodian.audit_kit.code_health import build_code_health_detectors
from custodian.audit_kit.detectors.dead_code import build_dead_code_detectors
from custodian.audit_kit.detectors.doc_conventions import build_doc_convention_detectors
from custodian.audit_kit.detectors.docs import build_docs_detectors
from custodian.audit_kit.detectors.naming import build_naming_detectors
from custodian.audit_kit.detectors.readme import build_readme_detectors
from custodian.audit_kit.detectors.reconcile import build_reconcile_detectors
from custodian.audit_kit.detectors.structure import build_structure_detectors
from custodian.audit_kit.detectors.stubs import build_stub_detectors
from custodian.audit_kit.detectors.test_shape import build_test_shape_detectors

_BUILDERS = [
    build_code_health_detectors,
    build_dead_code_detectors,
    build_doc_convention_detectors,
    build_docs_detectors,
    build_naming_detectors,
    build_readme_detectors,
    build_reconcile_detectors,
    build_structure_detectors,
    build_stub_detectors,
    build_test_shape_detectors,
]


def _all_detectors():
    out = []
    for build in _BUILDERS:
        out.extend(build())
    return out


def test_no_two_builtin_detectors_share_an_id():
    by_id: dict[str, list[str]] = defaultdict(list)
    for d in _all_detectors():
        by_id[d.id].append(d.description)

    collisions = {i: descs for i, descs in by_id.items() if len(descs) > 1}
    assert not collisions, (
        "detector id collisions — findings will be reported under the wrong "
        f"title: { {i: d for i, d in collisions.items()} }"
    )


@pytest.mark.parametrize("expected", ["RC1", "RC2"])
def test_reconcile_detectors_use_the_rc_namespace(expected):
    """readme.py owns R1..R6; reconcile must not re-enter that range."""
    ids = {d.id for d in build_reconcile_detectors()}
    assert expected in ids


def test_readme_keeps_its_r_family():
    ids = {d.id for d in build_readme_detectors()}
    assert {"R1", "R2"} <= ids


class TestLegacyConfigKeysStillWork:
    """Renaming an id must not silently disable a consumer's existing opt-out."""

    def _ctx(self, tmp_path, audit: dict):
        from custodian.audit_kit.detector import AuditContext
        (tmp_path / "src").mkdir(exist_ok=True)
        return AuditContext(
            repo_root=tmp_path,
            src_root=tmp_path / "src",
            tests_root=tmp_path / "tests",
            config={"audit": audit},
            plugin_modules=[],
        )

    def test_legacy_r1_enabled_false_still_disables(self, tmp_path):
        from custodian.audit_kit.detectors.reconcile import detect_r1
        ctx = self._ctx(tmp_path, {"reconcile_enforce": True, "r1_enabled": False})
        assert detect_r1(ctx).count == 0

    def test_new_rc1_enabled_false_disables(self, tmp_path):
        from custodian.audit_kit.detectors.reconcile import detect_r1
        ctx = self._ctx(tmp_path, {"reconcile_enforce": True, "rc1_enabled": False})
        assert detect_r1(ctx).count == 0
