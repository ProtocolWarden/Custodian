# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""CAP-class detectors — capability registry reference integrity.

The fleet capability registry (authored in PlatformManifest, compiled by
RepoGraph) records each capability's ``invocation.ref`` — the entrypoint, CLI
script, or executor symbol that actually runs it. RepoGraph keeps that ref
*opaque*: it never imports the owning repo, so a ref that rots when code is
renamed or moved is invisible there. CAP1 closes that gap.

CAP1 runs in the OWNING repo's audit. It loads the registry from the sibling
PlatformManifest checkout, selects the capabilities this repo owns (via the
manifest's canonical-name ↔ repo_id map), and resolves each owned
``invocation.ref`` against this repo's own code. A ref that no longer resolves
is rot — the registry promises a capability the code can no longer run.

Reference resolution
────────────────────
``kind: entrypoint`` / ``executor``
    ``ref`` is a dotted path (``operations_center.entrypoints.maintenance.board_unblock``).
    Resolves when the dotted prefix names a module/package under the repo's
    source tree, optionally with a trailing top-level symbol (def/class/assign)
    in that module.
``kind: cli``
    ``ref`` is a console-script name (``custodian-multi``). Resolves when it is
    declared in this repo's ``pyproject.toml`` ``[project.scripts]``.

Configuration (opt-in — dormant until enabled)
───────────────────────────────────────────────
::

    audit:
      repo_key: OperationsCenter          # identifies this repo in the manifest
      capabilities:
        enforce: true                      # CAP1 is silent unless this is true
        registry_repo: ../PlatformManifest # locates registry + manifest; does NOT
                                           # enable the X-class cross_repo detectors
        # registry_path: .../capabilities.yaml   # optional direct-file override

An existing ``audit.cross_repo.platform_manifest_repo`` is used if present; a
repo that only wants CAP1 sets ``capabilities.registry_repo`` instead and the
X-class detectors stay off.

CAP1 silently skips when not enabled, when ``repo_key`` is absent, when the
registry or manifest cannot be found, or when this repo owns no capability —
so it ships dormant and never fails a repo that has not opted in.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from custodian.audit_kit.detector import (
    MEDIUM,
    AuditContext,
    Detector,
    DetectorResult,
)
from custodian.audit_kit.detectors.cross_repo import _load_manifest_info

_MAX_SAMPLES = 8

_DEFAULT_CAP_SUBPATHS: tuple[str, ...] = (
    "src/platform_manifest/data/capabilities.yaml",
    "data/capabilities.yaml",
    "capabilities.yaml",
)

_DOTTED_KINDS = frozenset({"entrypoint", "executor"})


def build_capability_detectors() -> list[Detector]:
    return [
        Detector(
            "CAP1",
            "capability invocation.ref does not resolve in the owning repo "
            "(registry points at missing/renamed code)",
            "open",
            detect_cap1,
            MEDIUM,
            frozenset(),
            source="custodian",
        ),
    ]


@dataclass
class _Capability:
    action_id: str
    owner_repo_id: str
    kind: str
    ref: str


# ---------------------------------------------------------------------------
# Registry loading
# ---------------------------------------------------------------------------


def _find_registry_path(repo_root: Path, audit_cfg: dict) -> Path | None:
    cap_cfg = audit_cfg.get("capabilities") or {}
    cross_cfg = audit_cfg.get("cross_repo") or {}

    candidates: list[Path] = []
    explicit = cap_cfg.get("registry_path")
    if explicit:
        candidates.append(repo_root / explicit)
    sibling = cap_cfg.get("registry_repo") or cross_cfg.get("platform_manifest_repo")
    if sibling:
        sib_root = repo_root / sibling
        candidates.extend(sib_root / sub for sub in _DEFAULT_CAP_SUBPATHS)

    for p in candidates:
        if p.is_file():
            return p
    return None


def _load_capabilities(repo_root: Path, audit_cfg: dict) -> list[_Capability]:
    path = _find_registry_path(repo_root, audit_cfg)
    if path is None:
        return []
    try:
        import yaml
    except ImportError:  # pragma: no cover
        return []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeDecodeError):
        return []
    if not isinstance(data, dict):
        return []

    out: list[_Capability] = []
    for item in data.get("capabilities") or []:
        if not isinstance(item, dict):
            continue
        action_id = item.get("action_id")
        owner = item.get("owner_repo_id")
        invocation = item.get("invocation") or {}
        if not (isinstance(action_id, str) and isinstance(owner, str)):
            continue
        kind = invocation.get("kind") if isinstance(invocation, dict) else None
        ref = invocation.get("ref") if isinstance(invocation, dict) else None
        out.append(
            _Capability(
                action_id=action_id,
                owner_repo_id=owner,
                kind=str(kind or ""),
                ref=str(ref or ""),
            )
        )
    return out


def _owner_repo_id_for(repo_key: str, info) -> str | None:
    """Map this repo's canonical ``repo_key`` to its manifest repo_id (entry key)."""
    for entry_key, canonical in info.entry_key_to_canonical.items():
        if canonical == repo_key:
            return entry_key
    return None


# ---------------------------------------------------------------------------
# Reference resolution
# ---------------------------------------------------------------------------


def _base_dirs(context: AuditContext) -> list[Path]:
    """Directories a dotted ref's first segment (the package) may live under.

    Tolerates the two src layouts in the fleet: ``src_root == src`` (package is
    a child of src_root) and ``src_root == src/<pkg>`` (package IS src_root, so
    its parent is the base).
    """
    seen: list[Path] = []
    for base in (
        context.src_root,
        context.src_root.parent,
        context.repo_root / "src",
        context.repo_root,
    ):
        if base.is_dir() and base not in seen:
            seen.append(base)
    return seen


def _has_top_level_symbol(module_file: Path, symbol: str) -> bool:
    try:
        tree = ast.parse(module_file.read_text(encoding="utf-8", errors="replace"))
    except (OSError, SyntaxError):
        return False
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            if node.name == symbol:
                return True
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == symbol:
                    return True
        elif isinstance(node, ast.AnnAssign):  # noqa: SIM102 (inner condition is documented separately)
            if isinstance(node.target, ast.Name) and node.target.id == symbol:
                return True
    return False


def _resolve_dotted_under(base: Path, ref: str) -> bool:
    parts = ref.split(".")
    # Longest dotted prefix that is a module/package; any trailing single
    # segment must be a top-level symbol in that module.
    for split in range(len(parts), 0, -1):
        mod_parts = parts[:split]
        module_file = base.joinpath(*mod_parts).with_suffix(".py")
        package_init = base.joinpath(*mod_parts, "__init__.py")
        target = module_file if module_file.is_file() else (
            package_init if package_init.is_file() else None
        )
        if target is None:
            continue
        remainder = parts[split:]
        if not remainder:
            return True
        if len(remainder) == 1:
            return _has_top_level_symbol(target, remainder[0])
        # A deeper remainder means the prefix is a module but the rest can't be
        # a submodule (we already tried longer prefixes) — treat as unresolved.
        return False
    return False


def _resolve_dotted(context: AuditContext, ref: str) -> bool:
    return any(_resolve_dotted_under(base, ref) for base in _base_dirs(context))


def _resolve_cli(repo_root: Path, ref: str) -> bool:
    pyproject = repo_root / "pyproject.toml"
    if not pyproject.is_file():
        return False
    import tomllib
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    scripts = ((data.get("project") or {}).get("scripts")) or {}
    return ref in scripts


def _ref_resolves(context: AuditContext, cap: _Capability) -> bool:
    if not cap.ref:
        return False
    if cap.kind == "cli":
        return _resolve_cli(context.repo_root, cap.ref)
    # entrypoint / executor / unknown → dotted-path resolution
    return _resolve_dotted(context, cap.ref)


# ---------------------------------------------------------------------------
# CAP1
# ---------------------------------------------------------------------------


def _manifest_cfg(audit_cfg: dict, cap_cfg: dict) -> dict:
    """Config CAP1 uses to locate the manifest (for the repo_key→repo_id map).

    Prefers an existing ``cross_repo`` block, but a repo can instead point CAP1
    at the PlatformManifest checkout via ``capabilities.registry_repo`` (or
    ``manifest_repo``) and keep the X-class cross-repo detectors OFF — enabling
    CAP1 should not silently enable X1/X2/X3. The synthesized block is local to
    the manifest lookup; the repo's real ``audit.cross_repo`` (read by the
    X-class detectors) is never modified.
    """
    cross = audit_cfg.get("cross_repo") or {}
    if cross.get("platform_manifest_repo") or cross.get("platform_manifest_path"):
        return audit_cfg
    repo = cap_cfg.get("manifest_repo") or cap_cfg.get("registry_repo")
    if repo:
        return {**audit_cfg, "cross_repo": {"platform_manifest_repo": repo}}
    return audit_cfg


def detect_cap1(context: AuditContext) -> DetectorResult:
    audit_cfg = context.config.get("audit") or {}
    cap_cfg = audit_cfg.get("capabilities") or {}
    if not cap_cfg.get("enforce"):
        return DetectorResult(count=0, samples=[])

    repo_key = context.config.get("repo_key")
    if not repo_key:
        return DetectorResult(count=0, samples=[])

    info = _load_manifest_info(context.repo_root, _manifest_cfg(audit_cfg, cap_cfg))
    if info is None:
        return DetectorResult(count=0, samples=[])

    owner_repo_id = _owner_repo_id_for(repo_key, info)
    if owner_repo_id is None:
        return DetectorResult(count=0, samples=[])

    owned = [c for c in _load_capabilities(context.repo_root, audit_cfg)
             if c.owner_repo_id == owner_repo_id]
    if not owned:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0
    for cap in owned:
        if _ref_resolves(context, cap):
            continue
        count += 1
        if len(samples) < _MAX_SAMPLES:
            detail = cap.ref or "(empty ref)"
            samples.append(
                f"{cap.action_id}: invocation.ref `{detail}` ({cap.kind or 'unknown'}) "
                f"does not resolve in {repo_key} — capability points at missing code"
            )
    return DetectorResult(count=count, samples=samples)
