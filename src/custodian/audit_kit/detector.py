# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import pathlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from custodian.audit_kit.result import AuditResult

if TYPE_CHECKING:
    from custodian.audit_kit.passes.ast_forest import AstForest
    from custodian.audit_kit.passes.call_graph import CallGraph
    from custodian.audit_kit.passes.import_graph import ImportGraph
    from custodian.audit_kit.passes.symbol_index import SymbolIndex
    from custodian.audit_kit.passes.tests_forest import TestsForest

# Severity constants — use these names in Detector definitions
HIGH   = "high"
MEDIUM = "medium"
LOW    = "low"

_SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}


@dataclass
class AnalysisGraph:
    """Whole-repo derived data built once and shared across cross-file detectors.

    Detectors declare which passes they need via ``Detector.needs``. The runner
    builds only the passes required by active detectors, so file-local detectors
    (C1-C18) never pay the cost of graph construction.

    Pass names (strings used in ``Detector.needs``):
      ``"import_graph"``  — module-level import relationships
      ``"ast_forest"``    — pre-parsed ASTs for every .py file in src_root
      ``"call_graph"``    — static call-graph: defined names, call sites, attr accesses
      ``"symbol_index"``  — all defined names + all text tokens across src
      ``"tests_forest"``  — pre-parsed ASTs for every .py file in tests_root
    """
    import_graph: ImportGraph | None = None
    ast_forest: AstForest | None = None
    call_graph: CallGraph | None = None
    symbol_index: SymbolIndex | None = None
    tests_forest: TestsForest | None = None


@dataclass
class Detector:
    """One audit pattern. id is repo-namespaced (e.g. "C1", "S2", "U1").

    severity: "high" | "medium" | "low"  (default "medium")
      - high:   code that can hide bugs or break prod (bare except, breakpoints)
      - medium: quality issues that should be fixed but are not urgent
      - low:    tracked debt / style that does not block work

    needs: frozenset of pass names this detector requires in context.graph.
      e.g. frozenset({"import_graph"}) or frozenset({"ast_forest"}).
      File-local detectors leave this empty (the default).
    """

    id: str
    description: str
    status: str  # "fixed" | "open" | "partial" | "deferred"
    detect: Callable[[AuditContext], DetectorResult]
    severity: str = field(default=MEDIUM)
    needs: frozenset[str] = field(default_factory=frozenset)
    # Detectors that have an equivalent in an external tool (Ruff, Vulture,
    # ty, Semgrep) are marked deprecated. They are SKIPPED BY DEFAULT
    # since 2026-05-05 — the principle is "use the tool first, don't
    # reimplement successful packages." Pass ``skip_deprecated=False``
    # (or ``--include-deprecated`` on the CLI) to run them alongside their
    # adapter equivalents — useful for parity audits during migration.
    deprecated: bool = False
    # source tracks where this detector originates:
    #   "builtin"  — Custodian's own AST-based detectors (C, D, S, U, T, G, A, I-class)
    #   "custom"   — repo-specific plugin from _custodian/ (set by plugin loader)
    #   "adapter"  — wraps an external tool (RUFF, MYPY, VULTURE, TY, SEMGREP)
    source: str = "builtin"


@dataclass(frozen=True)
class DetectorResult:
    count: int
    samples: list[str]


@dataclass
class AuditContext:
    """Passed to every detector. Carries paths + parsed config.

    graph is populated by the runner before running any detector that declares
    a non-empty ``needs`` set. File-local detectors may ignore it entirely.
    """

    repo_root: pathlib.Path
    src_root: pathlib.Path
    tests_root: pathlib.Path
    config: dict
    plugin_modules: list
    graph: AnalysisGraph | None = None


def run_audit(
    context: AuditContext,
    detectors: list[Detector],
    *,
    min_severity: str | None = None,
    skip_deprecated: bool = True,
    ignore_rules: set[str] | None = None,
) -> AuditResult:
    """Run all detectors consistently so repos can compare outputs across runs.

    Args:
        context:      Audit context (repo root, config, etc.)
        detectors:    List of detectors to run.
        min_severity: If set, skip detectors whose severity is below this level.
                      Accepted values: "high", "medium", "low".
                      "high" runs only HIGH detectors; "medium" runs HIGH + MEDIUM;
                      "low" runs all (equivalent to not filtering).
        ignore_rules: Set of detector IDs to skip entirely (e.g. {"W2", "F3"}).
    """
    cutoff = _SEVERITY_ORDER.get(min_severity or LOW, _SEVERITY_ORDER[LOW])

    result = AuditResult(repo_key=context.config.get("repo_key", ""))
    total = 0
    for detector in detectors:
        if skip_deprecated and detector.deprecated:
            continue
        if ignore_rules and detector.id in ignore_rules:
            continue
        det_order = _SEVERITY_ORDER.get(detector.severity, _SEVERITY_ORDER[MEDIUM])
        if det_order > cutoff:
            continue
        detector_result = detector.detect(context)
        total += detector_result.count
        result.add_pattern(detector.id, {
            "description": detector.description,
            "status": detector.status,
            "severity": detector.severity,
            "source": detector.source,
            "count": detector_result.count,
            "samples": detector_result.samples,
        })
    result.total_findings = total
    return result
