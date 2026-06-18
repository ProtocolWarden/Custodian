# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Decision matrix that maps a file's detector hits to a verdict.

Verdicts are mutually compatible — a single file may earn several
(e.g. CLEANUP + REDESIGN). They are returned in priority order so the
first one in ``verdicts`` is the strongest recommendation.

Priority order (strongest first):
    DELETE > IMPLEMENT > WIRE > REDESIGN > CLEANUP

Update ``docs/usage/triage_signals.md`` when the matrix changes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from custodian.triage.joiner import group_findings_by_file


class Verdict(str, Enum):
    DELETE    = "DELETE"     # uncalled + stub body — code is dead, remove it
    IMPLEMENT = "IMPLEMENT"  # stub body but reachable — finish the work
    WIRE      = "WIRE"       # implementation exists but isn't connected
    REDESIGN  = "REDESIGN"   # bloated + noisy — split or rewrite
    CLEANUP   = "CLEANUP"    # commented-out code or stale references


# Detector ID buckets — keep in sync with the docs matrix.
_UNCALLED   = frozenset({"D1", "D5", "F1", "F2", "VULTURE"})
_STUB_BODY  = frozenset({"U1", "U2", "U3", "D3"})
_UNWIRED    = frozenset({"D6", "U4", "VF6", "D12"})
_BLOAT      = frozenset({"C29"})
_NOISE      = frozenset({"C33"})
_DEAD_TEXT  = frozenset({"C34", "G1", "C8"})

# Priority order for sorting verdicts in the output.
_PRIORITY = {
    Verdict.DELETE:    0,
    Verdict.IMPLEMENT: 1,
    Verdict.WIRE:      2,
    Verdict.REDESIGN:  3,
    Verdict.CLEANUP:   4,
}


@dataclass(frozen=True)
class FileVerdict:
    path: str
    verdicts: tuple[Verdict, ...]
    evidence: dict = field(default_factory=dict)

    def primary(self) -> Verdict:
        return self.verdicts[0]


def triage_file(detector_hits: dict[str, list]) -> tuple[Verdict, ...]:
    """Return the verdicts that apply to a file given its detector hits.

    ``detector_hits`` maps detector ID → non-empty list of findings.
    Empty result tuple means the file has findings but none of them
    combine into a triage verdict (they're advisory style/format issues).
    """
    hit = set(detector_hits.keys())
    out: list[Verdict] = []

    has_uncalled = bool(hit & _UNCALLED)
    has_stub     = bool(hit & _STUB_BODY)

    # DELETE strictly dominates IMPLEMENT — uncalled stubs are dead code.
    if has_uncalled and has_stub:
        out.append(Verdict.DELETE)
    elif has_stub:
        out.append(Verdict.IMPLEMENT)
    elif has_uncalled:
        # Uncalled but no stub: usually still dead, but weaker signal.
        out.append(Verdict.DELETE)

    if hit & _UNWIRED:
        out.append(Verdict.WIRE)

    if (hit & _BLOAT) and (hit & _NOISE):
        out.append(Verdict.REDESIGN)

    if hit & _DEAD_TEXT:
        out.append(Verdict.CLEANUP)

    out.sort(key=lambda v: _PRIORITY[v])
    return tuple(out)


def triage_result(patterns: dict) -> list[FileVerdict]:
    """Triage every file referenced in an audit-result patterns dict.

    Files with no triage verdict (only style/format hits) are omitted.
    Output is sorted by primary verdict priority, then by path.
    """
    by_file = group_findings_by_file(patterns)
    out: list[FileVerdict] = []
    for path, hits in by_file.items():
        verdicts = triage_file(hits)
        if not verdicts:
            continue
        evidence = {det_id: [msg for _, msg in items] for det_id, items in hits.items()}
        out.append(FileVerdict(path=path, verdicts=verdicts, evidence=evidence))
    out.sort(key=lambda fv: (_PRIORITY[fv.primary()], fv.path))
    return out
