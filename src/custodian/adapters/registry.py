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

Semgrep also accepts a dict form::

    tools:
      semgrep:
        configs: [.custodian/rules/semgrep]
        docker: true                      # run the official image, not a local binary
        image: semgrep/semgrep:latest     # optional pin
        timeout: 180                      # optional, seconds

``docker: true`` exists because native semgrep does not run on every host —
on Windows ``semgrep-core`` fails rule validation while semgrep still exits 0,
so an authored rule set silently never executes. Rules and source must live
inside the repo, since only the repo is mounted.

ty accepts a dict form too, for a different reason::

    tools:
      ty:
        docker: true
        image: docker-worker:latest       # the repo's own runtime image
        mount: /work                      # where that image expects the repo
        command: /work/.venv/bin/ty       # ty need not be on PATH
        timeout: 180                      # optional, seconds

Here docker mode is about *soundness*, not host support. A type checker
resolves imports against an environment, and for a containerized repo that
environment is inside the image — a venv built ``--system-site-packages``
leaves the dependencies at ``/usr/local/lib/...`` and points ``pyvenv.cfg``
``home`` at a path the host does not have. Imports ty cannot resolve infer as
``Unknown``, which invents attribute errors *and* suppresses real ones, so a
host run is wrong in both directions rather than merely noisy.
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

    ty_cfg = tools_cfg.get("ty")
    # `{"enabled": False}` is a truthy dict — the v1 schema spells every tool
    # that way, so a bare truthiness test silently enables a disabled tool.
    if isinstance(ty_cfg, dict):
        ty_cfg = ty_cfg if ty_cfg.get("enabled", True) else None
    if ty_cfg:
        from custodian.adapters.ty import TyAdapter
        # Accept either a bare truthy value (host binary) or a dict. A
        # containerized repo needs the dict form: the dependencies ty must
        # resolve live inside the image, not on the host disk, and an import
        # ty cannot resolve infers as Unknown — which invents attribute errors
        # and hides real ones, so a host run is unsound rather than noisy.
        if isinstance(ty_cfg, dict):
            image = ty_cfg.get("image")
            mount = ty_cfg.get("mount")
            command = ty_cfg.get("command")
            result.append(TyAdapter(
                docker=bool(ty_cfg.get("docker", False)),
                image=image if isinstance(image, str) else "python:3.12-slim",
                mount=mount if isinstance(mount, str) else "/src",
                command=command if isinstance(command, str) else "ty",
                timeout=int(ty_cfg.get("timeout", 120)),
            ))
        else:
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
            # `docker: true` runs the official image instead of a local
            # binary. Needed on hosts where native semgrep cannot run at all
            # (Windows: semgrep-core fails rule validation, yet exits 0, so
            # the rules silently never execute).
            image = semgrep_cfg.get("image")
            result.append(SemgrepAdapter(
                configs=configs,
                docker=bool(semgrep_cfg.get("docker", False)),
                image=image if isinstance(image, str) else "semgrep/semgrep:latest",
                timeout=int(semgrep_cfg.get("timeout", 120)),
            ))
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
