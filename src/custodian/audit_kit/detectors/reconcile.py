# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""R-class detectors — `.console/` reconciliation gate (Layer A).

These are the always-on, cheap detectors from the `.console/`
reconciliation design ([console-reconciliation.md] / spec §2). They keep
operator workspaces from re-accumulating two problems silently:

R1  (advisory) — a tracked ``.console/*.md`` source file has grown past
    its line budget (``audit.r1_line_budget``, default 400). One finding
    per over-budget file. LOW/advisory — a "reconciliation due" signal,
    no judgement about *what* to prune.

R2  (fail-closed) — a §1 *scrub-target* private name (the public-leak
    vocabulary defined in the boundary artifact) appears in a tracked
    ``.console/**`` file of a **public** repo (public == this repo's name
    is present in ``platform_manifest.yaml``). This is the original leak
    B1 misses because it default-excludes ``.console/**``. R2 deliberately
    overrides that exclusion *for scrub-target names only* — non-scrub
    private names (e.g. the private-manifest repo's own name) keep their
    existing ``.console/**`` exclusion behaviour. MEDIUM, one finding per
    match (capped at samples).

The scrub-target vocabulary is read from a single source of truth — the
boundary artifact's ``forbidden_names`` list (with word-boundary
abbreviations derived from it), via
:func:`custodian.audit_kit.detectors.boundary.load_scrub_targets` — so
there is no second hardcoded copy (spec §1 / AC1). It is the same key
ContextLifecycle's ``cl reconcile`` reads, so both detection paths share
one source. Each name is matched on a word boundary so detector IDs that
embed a scrub token (e.g. ``VF2``/``VF4``) do not trip it.

Both R1 and R2 are **opt-in**: they are silent unless a repo sets
``audit.reconcile_enforce: true``. Enforcement is a deliberate per-repo step
taken *after* the repo's ``.console/`` has been reconciled (spec §6) — so the
detectors can land fleet-wide without breaking every public repo's CI (under
``--fail-on-findings``) before reconciliation.

Configuration::

    audit:
      reconcile_enforce: true    # OPT-IN: activate R1/R2 (default off)
      r1_line_budget: 400        # R1 threshold (lines), default 400
      r1_enabled: true           # set false to suppress R1 even when enforcing
      cross_repo:
        platform_manifest_repo: ../PlatformManifest   # R2 public lookup
    privacy:
      boundary_artifact_file: /path/to/boundary_disclosure_artifact.json
"""
from __future__ import annotations

import re

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW, MEDIUM,
)
from custodian.audit_kit.detectors.boundary import (
    _is_binary, _tracked_files, load_scrub_targets,
)
from custodian.audit_kit.detectors.cross_repo import _load_manifest_info
from custodian.audit_kit.glob_match import glob_match

_MAX_SAMPLES = 8
_DEFAULT_R1_LINE_BUDGET = 400

# R1 scopes to top-level `.console/*.md` source files; R2 scopes to the
# whole `.console/**` subtree (matching B1's exclude that it overrides).
_R1_GLOB = ".console/*.md"
_R2_GLOB = ".console/**"

# A scrub-target is matched as a whole word so that detector IDs which
# embed it (e.g. `VF2`, `VF4`) are NOT flagged. The §1 set itself lives
# in the boundary artifact, not here.
_word_re_cache: dict[str, re.Pattern[str]] = {}


def build_reconcile_detectors() -> list[Detector]:
    return [
        Detector(
            "R1",
            "tracked .console/*.md source file exceeds its line budget "
            "(reconciliation due)",
            "open",
            detect_r1,
            LOW,
            frozenset(),
        ),
        Detector(
            "R2",
            "scrub-target private name in a public repo's tracked "
            ".console/** file",
            "open",
            detect_r2,
            MEDIUM,
            frozenset(),
        ),
    ]


def _audit_block(config: dict) -> dict:
    block = config.get("audit")
    return block if isinstance(block, dict) else {}


def _reconcile_enforced(config: dict) -> bool:
    """R1/R2 are OPT-IN per repo (default off).

    Enforcement is a deliberate activation step a repo takes *after* its
    `.console/` has been reconciled (spec §6 rollout): until `cl reconcile`
    has trimmed the log and scrubbed/archived any leak, R1 (oversized log)
    and R2 (pre-existing leak) would block CI under `--fail-on-findings`.
    Shipping them dormant lets the detectors land fleet-wide without breaking
    every public repo's CI before it has been reconciled. A repo flips
    `audit.reconcile_enforce: true` once it is clean.
    """
    return _audit_block(config).get("reconcile_enforce") is True


def _word_pattern(name: str) -> re.Pattern[str]:
    pat = _word_re_cache.get(name)
    if pat is None:
        pat = re.compile(rf"\b{re.escape(name)}\b")
        _word_re_cache[name] = pat
    return pat


def detect_r1(context: AuditContext) -> DetectorResult:
    """Flag tracked ``.console/*.md`` files over ``audit.r1_line_budget``.

    One finding per over-budget file. Opt-in: silent unless
    ``audit.reconcile_enforce`` is true; also disabled when
    ``audit.r1_enabled`` is false.
    """
    if not _reconcile_enforced(context.config):
        return DetectorResult(count=0, samples=[])
    audit = _audit_block(context.config)
    if audit.get("r1_enabled") is False:
        return DetectorResult(count=0, samples=[])

    budget = audit.get("r1_line_budget", _DEFAULT_R1_LINE_BUDGET)
    try:
        budget = int(budget)
    except (TypeError, ValueError):
        budget = _DEFAULT_R1_LINE_BUDGET

    samples: list[str] = []
    count = 0
    for path in _tracked_files(context.repo_root):
        try:
            rel = path.relative_to(context.repo_root)
        except ValueError:
            continue
        if not glob_match(rel.as_posix(), _R1_GLOB):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        lines = text.count("\n") + (1 if text and not text.endswith("\n") else 0)
        if lines <= budget:
            continue
        count += 1
        if len(samples) < _MAX_SAMPLES:
            samples.append(
                f"{rel.as_posix()}: {lines} lines exceeds r1_line_budget "
                f"({budget}) — reconciliation due"
            )
    return DetectorResult(count=count, samples=samples)


def _repo_is_public(context: AuditContext) -> bool:
    """True when this repo's name is present in ``platform_manifest.yaml``.

    The manifest enumerates only public platform repos (private repos are
    deliberately absent), so presence == public. The repo identity comes
    from ``repo_key`` in ``.custodian/config.yaml``; it is matched against
    the manifest's entry keys and canonical names.
    """
    repo_key = context.config.get("repo_key")
    if not repo_key:
        return False
    info = _load_manifest_info(context.repo_root, _audit_block(context.config))
    if info is None:
        return False
    if repo_key in info.entry_key_to_canonical:
        return True
    return repo_key in set(info.entry_key_to_canonical.values())


def detect_r2(context: AuditContext) -> DetectorResult:
    """Flag scrub-target names in a public repo's tracked ``.console/**``.

    Fail-closed: each match is one finding (samples capped). Opt-in: silent
    unless ``audit.reconcile_enforce`` is true. Also silent when the repo is
    private (not in the manifest) or no scrub-target set is configured.
    Word-boundary match so ``VF2``/``VF4`` are not flagged.
    """
    if not _reconcile_enforced(context.config):
        return DetectorResult(count=0, samples=[])
    if not _repo_is_public(context):
        return DetectorResult(count=0, samples=[])

    scrub_targets = load_scrub_targets(context.config)
    if not scrub_targets:
        return DetectorResult(count=0, samples=[])

    patterns = [(name, _word_pattern(name)) for name in scrub_targets]

    samples: list[str] = []
    count = 0
    for path in _tracked_files(context.repo_root):
        try:
            rel = path.relative_to(context.repo_root)
        except ValueError:
            continue
        if not glob_match(rel.as_posix(), _R2_GLOB):
            continue
        if _is_binary(path):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for name, pat in patterns:
                if pat.search(line):
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        samples.append(
                            f"{rel.as_posix()}:{lineno}: scrub-target "
                            f"{name!r} in public .console/ (must be scrubbed "
                            "or archived to the private side)"
                        )
                    break  # one finding per line is enough
    return DetectorResult(count=count, samples=samples)
