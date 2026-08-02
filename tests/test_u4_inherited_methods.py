# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""U4 must count methods inherited from non-Protocol bases as implemented.

U4 collected the implementing class's own body only, so the ordinary mixin
shape — ``class Impl(ConcreteBase, SomeProtocol)`` where ConcreteBase supplies
the method — was reported as a Protocol gap. Python resolves that through the
MRO, so it is complete.

Found in a consumer repo while removing a duplicated probe: the fix replaced a
copy-pasted method body with inheritance from the class that already had it,
and U4 then reported the method as missing.
"""
from __future__ import annotations

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.stubs import detect_u4
from custodian.audit_kit.passes.ast_forest import build_ast_forest


def _ctx(tmp_path, files: dict[str, str]) -> AuditContext:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    for name, body in files.items():
        p = src / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")

    class _G:
        ast_forest = build_ast_forest(src)

    return AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=_G(),
    )


_PROTO = """
from typing import Protocol


class FrameProbe(Protocol):
    def frame_size(self, path: str) -> tuple[int, int] | None: ...
"""


def test_method_inherited_from_a_concrete_base_is_not_missing(tmp_path):
    """The regression: inheritance satisfies the Protocol via the MRO."""
    files = {
        "ports.py": _PROTO,
        "impl.py": """
from ports import FrameProbe


class BaseProbe:
    def frame_size(self, path: str) -> tuple[int, int] | None:
        return (1, 2)


class Impl(BaseProbe, FrameProbe):
    \"\"\"frame_size comes from BaseProbe.\"\"\"
""",
    }
    assert detect_u4(_ctx(tmp_path, files)).count == 0


def test_method_inherited_transitively_is_not_missing(tmp_path):
    """Resolution walks the whole non-Protocol ancestor chain, not one level."""
    files = {
        "ports.py": _PROTO,
        "impl.py": """
from ports import FrameProbe


class Root:
    def frame_size(self, path: str) -> tuple[int, int] | None:
        return (1, 2)


class Middle(Root):
    pass


class Impl(Middle, FrameProbe):
    pass
""",
    }
    assert detect_u4(_ctx(tmp_path, files)).count == 0


def test_a_genuine_gap_is_still_reported(tmp_path):
    """Guard against 'fixing' the false positive by disabling the detector."""
    files = {
        "ports.py": _PROTO,
        "impl.py": """
from ports import FrameProbe


class Unrelated:
    def something_else(self) -> None:
        return None


class Impl(Unrelated, FrameProbe):
    pass
""",
    }
    result = detect_u4(_ctx(tmp_path, files))
    assert result.count == 1
    assert "frame_size" in result.samples[0]


def test_class_defining_the_method_itself_still_passes(tmp_path):
    files = {
        "ports.py": _PROTO,
        "impl.py": """
from ports import FrameProbe


class Impl(FrameProbe):
    def frame_size(self, path: str) -> tuple[int, int] | None:
        return (1, 2)
""",
    }
    assert detect_u4(_ctx(tmp_path, files)).count == 0


def test_unknown_base_outside_the_tree_still_reports(tmp_path):
    """A base we cannot see contributes nothing — under-report, never invent."""
    files = {
        "ports.py": _PROTO,
        "impl.py": """
from ports import FrameProbe
from some.external.package import ExternalBase


class Impl(ExternalBase, FrameProbe):
    pass
""",
    }
    assert detect_u4(_ctx(tmp_path, files)).count == 1


def test_aliased_base_is_resolved(tmp_path):
    """`from m import Impl as _Base` — the shape that surfaced this bug.

    A class is commonly re-bound on import to avoid clashing with the subclass
    being built from it. Indexed by real name, the alias resolves to nothing
    and the Protocol looks unimplemented.
    """
    files = {
        "ports.py": _PROTO,
        "base.py": """
class OpenCVResolutionProbe:
    def frame_size(self, path: str) -> tuple[int, int] | None:
        return (1, 2)
""",
        "impl.py": """
from ports import FrameProbe
from base import OpenCVResolutionProbe as _DomainProbe


class OpenCVResolutionProbe(_DomainProbe, FrameProbe):
    \"\"\"frame_size is inherited from the domain probe.\"\"\"
""",
    }
    assert detect_u4(_ctx(tmp_path, files)).count == 0
