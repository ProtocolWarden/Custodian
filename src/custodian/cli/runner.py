# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import sys
from pathlib import Path

import yaml

from custodian.audit_kit.code_health import build_code_health_detectors
from custodian.audit_kit.detector import AnalysisGraph, AuditContext, run_audit
from custodian.audit_kit.detectors.annotations import build_annotation_detectors
from custodian.audit_kit.detectors.complexity import build_complexity_detectors
from custodian.audit_kit.detectors.dead_code import build_dead_code_detectors
from custodian.audit_kit.detectors.docs import build_docs_detectors
from custodian.audit_kit.detectors.ghost import build_ghost_detectors
from custodian.audit_kit.detectors.imports import build_import_detectors
from custodian.audit_kit.detectors.naming import build_naming_detectors
from custodian.audit_kit.detectors.boundary import build_boundary_detectors
from custodian.audit_kit.detectors.cross_repo import build_cross_repo_detectors
from custodian.audit_kit.detectors.plumbing import build_plumbing_detectors
from custodian.audit_kit.detectors.workspace import build_workspace_detectors
from custodian.audit_kit.detectors.envvar import build_envvar_detectors
from custodian.audit_kit.detectors.doc_conventions import build_doc_convention_detectors
from custodian.audit_kit.detectors.repo_meta import build_repo_meta_detectors
from custodian.audit_kit.detectors.directory import build_directory_detectors
from custodian.audit_kit.detectors.readme import build_readme_detectors
from custodian.audit_kit.detectors.structure import build_structure_detectors
from custodian.audit_kit.detectors.stubs import build_stub_detectors
from custodian.audit_kit.detectors.test_shape import build_test_shape_detectors
from custodian.adapters.registry import get_enabled_adapters
from custodian.audit_kit.result import AuditResult
from custodian.plugins.loader import load_detectors, load_plugins


def load_config(repo_root: Path) -> dict:
    # New layout: .custodian/config.yaml — preferred.
    new_path = repo_root / ".custodian" / "config.yaml"
    if new_path.exists():
        with new_path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    # Backward-compat: fall back to the old root-level file.
    config_path = repo_root / ".custodian.yaml"
    with config_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def run_repo_audit(
    repo_root: Path,
    *,
    only: set[str] | None = None,
    min_severity: str | None = None,
    skip_deprecated: bool = True,
    enable_coverage: bool = False,
    coverage_json_path: str | None = None,
) -> AuditResult:
    """Drive one repo through the audit pipeline.

    Args:
        repo_root:    Repository root containing ``.custodian.yaml``.
        only:         Optional set of detector IDs to run (e.g. ``{"C1", "OC7"}``).
                      All other detectors are skipped.  ``None`` runs everything.
        min_severity: If set, skip detectors whose severity is below this level.
                      Accepted values: ``"high"``, ``"medium"``, ``"low"``.
                      ``"high"`` runs only HIGH detectors; ``"medium"`` runs HIGH
                      and MEDIUM; ``"low"`` (the default) runs all.
        enable_coverage: Override the config to enable the coverage adapter
                      for this run only (default: respect config). Used by
                      orchestrators (e.g. OperationsCenter dispatch) that
                      want to opt in coverage analysis without modifying the
                      repo's ``.custodian.yaml``.
        coverage_json_path: When ``enable_coverage`` is True, override the
                      adapter's ``json_path`` config to point at this file.

    Returns AuditResult so callers can decide on JSON, human, or aggregator
    output formatting.
    """
    config = load_config(repo_root)
    if enable_coverage:
        # Shallow-merge the coverage adapter override into the loaded config.
        tools_cfg = dict(config.get("tools") or {})
        cov_cfg = dict(tools_cfg.get("coverage") or {})
        cov_cfg["enabled"] = True
        if coverage_json_path is not None:
            cov_cfg["json_path"] = coverage_json_path
        tools_cfg["coverage"] = cov_cfg
        config["tools"] = tools_cfg
    sys.path.insert(0, str(repo_root))
    # Flush any _custodian.* modules cached from a previous repo so this
    # repo's plugin package is imported fresh.
    _cached = [k for k in sys.modules if k == "_custodian" or k.startswith("_custodian.")]
    _saved = {k: sys.modules.pop(k) for k in _cached}
    try:
        plugins   = load_plugins(config, repo_root)
        extra     = load_detectors(config, repo_root)
    finally:
        sys.path.remove(str(repo_root))
        # Remove this repo's _custodian modules and restore any previously cached ones
        for k in list(sys.modules):
            if k == "_custodian" or k.startswith("_custodian."):
                sys.modules.pop(k, None)
        sys.modules.update(_saved)

    src_root   = repo_root / config.get("src_root", "src")
    tests_root = repo_root / config.get("tests_root", "tests")
    detectors  = (build_code_health_detectors()
                  + build_structure_detectors()
                  + build_directory_detectors()
                  + build_stub_detectors()
                  + build_dead_code_detectors()
                  + build_test_shape_detectors()
                  + build_annotation_detectors()
                  + build_complexity_detectors()
                  + build_ghost_detectors()
                  + build_import_detectors()
                  + build_docs_detectors()
                  + build_naming_detectors()
                  + build_boundary_detectors()
                  + build_readme_detectors()
                  + build_doc_convention_detectors()
                  + build_repo_meta_detectors()
                  + build_cross_repo_detectors()
                  + build_plumbing_detectors()
                  + build_workspace_detectors()
                  + build_envvar_detectors()
                  + extra)

    if only:
        detectors = [d for d in detectors if d.id in only]

    context = AuditContext(
        repo_root=repo_root,
        src_root=src_root,
        tests_root=tests_root,
        config=config,
        plugin_modules=plugins,
        graph=_build_analysis_graph(detectors=detectors,
                                    src_root=src_root, repo_root=repo_root,
                                    tests_root=tests_root),
    )
    result = run_audit(context=context, detectors=detectors, min_severity=min_severity,
                       skip_deprecated=skip_deprecated)

    # Run enabled tool adapters and merge findings into result
    _run_adapters(result, repo_root=repo_root, config=config)

    # Optional triage pass: when audit.triage: true is set, group findings
    # into per-file action recommendations and emit them as TRIAGE_* patterns.
    if (config.get("audit") or {}).get("triage"):
        _run_triage(result)

    return result


def _run_triage(result: AuditResult) -> None:
    """Append TRIAGE_<verdict> patterns summarizing per-file recommendations."""
    from custodian.triage import triage_result

    verdicts = triage_result(result.patterns)
    if not verdicts:
        return
    grouped: dict[str, list[str]] = {}
    for fv in verdicts:
        key = f"TRIAGE_{fv.primary().value}"
        sources = ",".join(sorted(fv.evidence))
        grouped.setdefault(key, []).append(f"{fv.path}: signals={sources}")
    for key, samples in grouped.items():
        result.patterns[key] = {
            "description": f"triage recommendation: {key.split('_', 1)[1].lower()}",
            "status": "open",
            "severity": "low",
            "source": "triage",
            "count": len(samples),
            "samples": samples[:8],
        }


def _run_adapters(result: AuditResult, *, repo_root: Path, config: dict) -> None:
    """Run each enabled adapter and append grouped findings to result.patterns."""
    adapters = get_enabled_adapters(config)
    if not adapters:
        return

    for adapter in adapters:
        tool_id = adapter.name.upper()
        if not adapter.is_available():
            result.patterns[tool_id] = {
                "description": f"{adapter.name} (not installed)",
                "status": "skipped",
                "severity": "low",
                "source": "adapter",
                "count": 0,
                "samples": [f"{adapter.name!r} is not installed — install it to enable findings"],
            }
            continue

        findings = adapter.run(repo_root, config)

        # Filter out TOOL_UNAVAILABLE sentinel (shouldn't happen, but be safe)
        real = [f for f in findings if f.rule != "TOOL_UNAVAILABLE"]

        samples = [
            f"{f.path or '?'}:{f.line or '?'}: [{f.rule}] {f.message}"
            for f in real[:8]
        ]
        count = len(real)
        result.patterns[tool_id] = {
            "description": f"{adapter.name} findings",
            "status": "open" if count else "pass",
            "severity": "medium",
            "source": "adapter",
            "count": count,
            "samples": samples,
        }
        result.total_findings += count


def _build_analysis_graph(
    detectors,
    src_root: Path,
    repo_root: Path,
    tests_root: Path | None = None,
) -> AnalysisGraph:
    needed: set[str] = set()
    for d in detectors:
        needed |= d.needs
    if not needed:
        return AnalysisGraph()

    graph = AnalysisGraph()

    if "import_graph" in needed:
        from custodian.audit_kit.passes.import_graph import build_import_graph
        graph.import_graph = build_import_graph(src_root, repo_root)

    if "ast_forest" in needed:
        from custodian.audit_kit.passes.ast_forest import build_ast_forest
        graph.ast_forest = build_ast_forest(src_root)

    if "call_graph" in needed:
        from custodian.audit_kit.passes.call_graph import build_call_graph
        extra: list[Path] = [tests_root] if tests_root is not None and tests_root.is_dir() else []
        graph.call_graph = build_call_graph(src_root, extra_roots=extra)

    if "symbol_index" in needed:
        from custodian.audit_kit.passes.symbol_index import build_symbol_index
        graph.symbol_index = build_symbol_index(src_root)

    if "tests_forest" in needed and tests_root is not None:
        from custodian.audit_kit.passes.tests_forest import build_tests_forest
        graph.tests_forest = build_tests_forest(tests_root)

    return graph
