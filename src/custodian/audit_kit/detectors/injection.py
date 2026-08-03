# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""INJ1 — prompt-injection signature detector.

Deterministic scan of tracked text for the unambiguous, near-zero-false-positive
signal of injection / obfuscation smuggling: invisible and bidirectional control
characters (zero-width spaces/joiners, LTR/RTL overrides, the BOM mid-file). These
never legitimately appear in source or prose, but are the classic carrier for
hidden instructions and homoglyph tricks aimed at a model (or a human reviewer)
that ingests the text.

Mirrors the boundary-detector shape (``detect_inj1(context) -> DetectorResult``;
``build_injection_detectors()``) per HARNESS_TRUST_HARDENING.md §2.2.6. It is the
**outer** layer of the INJ defense — never load-bearing (the load-bearing control
is the reviewer's code-computed typed verdict). Registered ``deprecated=True`` so
it is SKIPPED by the default audit gate: a repo's own injection-handling code
(regexes that *match* these chars) would otherwise trip it fleet-wide. It is meant
to be invoked deliberately (``--only INJ1 --include-deprecated``) against ingested
PR content, where a hit drives the reviewer to the stricter deterministic path
(D-INJ-2: degrade, never fail-closed-to-human).

A file that legitimately contains such characters (an injection sanitizer, a
unicode test fixture) is exempted by carrying the marker
``custodian:allow-invisible-chars`` anywhere in its text — identified by content,
so consumers needn't maintain a path exclude list.
"""

from __future__ import annotations

import re

from custodian.audit_kit.detector import (
    LOW,
    AuditContext,
    Detector,
    DetectorResult,
)
from custodian.audit_kit.detectors.boundary import _is_binary, _tracked_files

_MAX_SAMPLES = 8
_EXEMPT_MARKER = "custodian:allow-invisible-chars"

# Invisible + bidirectional control characters (\u escapes so THIS file never
# trips its own rule). Covers: zero-width space/non-joiner/joiner, LTR/RTL marks,
# the bidi embedding/override/isolate controls, and a mid-file BOM.
_INVISIBLE = re.compile(
    "["
    "\u200b\u200c\u200d\u200e\u200f"   # ZWSP ZWNJ ZWJ LRM RLM
    "\u202a\u202b\u202c\u202d\u202e"   # LRE RLE PDF LRO RLO
    "\u2066\u2067\u2068\u2069"          # LRI RLI FSI PDI
    "\ufeff\u00ad"                        # BOM/ZWNBSP, SHY
    "]"
)


def detect_inj1(context: AuditContext) -> DetectorResult:
    """Flag tracked text files containing invisible / bidi control characters."""
    samples: list[str] = []
    count = 0
    for path in _tracked_files(context.repo_root):
        if _is_binary(path):
            continue
        try:
            rel = path.relative_to(context.repo_root).as_posix()
        except ValueError:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if _EXEMPT_MARKER in text:
            continue  # a legitimate handler / fixture opted out
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in _INVISIBLE.finditer(line):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    cp = f"U+{ord(m.group()):04X}"
                    # Report codepoint + position only — never the surrounding
                    # text (that would re-launder attacker content through a
                    # trusted channel, the very thing D-INJ-3 forbids).
                    samples.append(f"{rel}:{lineno}: invisible/bidi control char {cp}")
                break  # one finding per line is enough
    return DetectorResult(count=count, samples=samples)


def build_injection_detectors() -> list[Detector]:
    return [
        Detector(
            "INJ1",
            "Tracked file contains invisible / bidirectional control characters "
            "(prompt-injection / homoglyph smuggling signature)",
            "open",
            detect_inj1,
            LOW,
            frozenset(),
            deprecated=True,  # outer defense; opt-in, never the fleet-wide gate
        ),
    ]
