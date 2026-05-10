# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Adapter registry — reads the ``tools:`` block in .custodian.yaml and returns
enabled adapter instances.

Schema:
    tools:
      ruff: true          # linting
      mypy: false         # type-checking (use ty instead when available)
      ty: false           # faster type-checker from Astral
      vulture: true       # dead-code detection
      semgrep: false      # custom pattern rules (needs rules/ dir)
"""
from __future__ import annotations

from custodian.adapters.base import ToolAdapter


def get_enabled_adapters(config: dict) -> list[ToolAdapter]:
    """Return adapter instances for every tool enabled in config['tools']."""
    tools_cfg: dict = config.get("tools") or {}
    result: list[ToolAdapter] = []

    if tools_cfg.get("ruff"):
        from custodian.adapters.ruff import RuffAdapter
        ruff_args = tools_cfg.get("ruff_args") or []
        result.append(RuffAdapter(ruff_args=ruff_args if isinstance(ruff_args, list) else []))

    if tools_cfg.get("mypy"):
        from custodian.adapters.mypy import MypyAdapter
        result.append(MypyAdapter())

    if tools_cfg.get("ty"):
        from custodian.adapters.ty import TyAdapter
        result.append(TyAdapter())

    if tools_cfg.get("vulture"):
        from custodian.adapters.vulture import VultureAdapter
        min_conf = tools_cfg.get("vulture_min_confidence", 60)
        result.append(VultureAdapter(min_confidence=int(min_conf)))

    semgrep_cfg = tools_cfg.get("semgrep")
    if semgrep_cfg:
        from custodian.adapters.semgrep import SemgrepAdapter
        # Accept either a bare truthy value (use adapter's default rules dir)
        # or a dict with `configs: [paths...]` for explicit per-repo rule
        # locations (e.g. `.custodian/rules/semgrep`).
        if isinstance(semgrep_cfg, dict):
            configs = semgrep_cfg.get("configs") or []
            if not isinstance(configs, list):
                configs = []
            result.append(SemgrepAdapter(configs=configs))
        else:
            result.append(SemgrepAdapter())

    md_cfg = tools_cfg.get("markdownlint")
    if md_cfg:
        from custodian.adapters.markdownlint import MarkdownlintAdapter
        if isinstance(md_cfg, dict):
            globs = md_cfg.get("globs") or []
            if not isinstance(globs, list):
                globs = []
            mdc = md_cfg.get("config")
            timeout = int(md_cfg.get("timeout", 60))
            result.append(MarkdownlintAdapter(
                globs=globs or None,
                config=mdc if isinstance(mdc, str) else None,
                timeout=timeout,
            ))
        else:
            result.append(MarkdownlintAdapter())

    # Coverage adapter — default OFF. Opt-in by repos that produce a
    # coverage.json (typically via their own end-to-end audit pipeline).
    coverage_cfg = tools_cfg.get("coverage")
    if coverage_cfg:
        cfg_dict = coverage_cfg if isinstance(coverage_cfg, dict) else {}
        from custodian.adapters.coverage import CoverageAdapter
        result.append(CoverageAdapter(
            json_path=cfg_dict.get("json_path", "coverage.json"),
            min_coverage=cfg_dict.get("min_coverage"),
            exclude_paths=cfg_dict.get("exclude_paths") or [],
        ))

    return result
