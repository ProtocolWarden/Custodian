# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for CAP1 — capability invocation.ref integrity (anti-rot)."""
from __future__ import annotations

import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.capability_refs import (
    build_capability_detectors,
    detect_cap1,
)

_PM_YAML = textwrap.dedent("""\
    manifest_kind: platform
    manifest_version: "1.0.0"
    repos:
      operations_center:
        canonical_name: OperationsCenter
      custodian:
        canonical_name: Custodian
""")

# board_unblock (operations_center, entrypoint) + repo_health_audit (custodian, cli)
_CAP_YAML = textwrap.dedent("""\
    schema_kind: capabilities
    schema_version: 1.0.0
    capabilities:
      - action_id: board_unblock
        owner_repo_id: operations_center
        invocation:
          kind: entrypoint
          ref: operations_center.entrypoints.maintenance.board_unblock
      - action_id: repo_health_audit
        owner_repo_id: custodian
        invocation:
          kind: cli
          ref: custodian-multi
""")


def _write_registry(tmp_path: Path, *, cap_yaml: str = _CAP_YAML) -> None:
    data = tmp_path / "PlatformManifest" / "src" / "platform_manifest" / "data"
    data.mkdir(parents=True, exist_ok=True)
    (data / "platform_manifest.yaml").write_text(_PM_YAML)
    (data / "capabilities.yaml").write_text(cap_yaml)


def _ctx(
    tmp_path: Path,
    src_files: dict[str, str],
    *,
    repo_key: str | None = "OperationsCenter",
    enforce: bool = True,
    pyproject: str | None = None,
) -> AuditContext:
    src_dir = tmp_path / "src"
    src_dir.mkdir(exist_ok=True)
    for relpath, body in src_files.items():
        p = src_dir / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    if pyproject is not None:
        (tmp_path / "pyproject.toml").write_text(pyproject)
    audit: dict = {"cross_repo": {"platform_manifest_repo": "PlatformManifest"}}
    if enforce:
        audit["capabilities"] = {"enforce": True}
    cfg: dict = {"audit": audit}
    if repo_key:
        cfg["repo_key"] = repo_key
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_dir,
        tests_root=tmp_path / "tests",
        config=cfg,
        graph=None,
        plugin_modules=[],
    )


_OC_MODULE = "src/operations_center/entrypoints/maintenance/board_unblock.py"


def test_detector_is_registered_and_dormant_by_default() -> None:
    [det] = build_capability_detectors()
    assert det.id == "CAP1"
    assert det.source == "custodian"


def test_silent_when_not_enforced(tmp_path: Path) -> None:
    _write_registry(tmp_path)
    ctx = _ctx(tmp_path, {}, enforce=False)  # broken ref, but enforce off
    assert detect_cap1(ctx).count == 0


def test_resolved_entrypoint_ref_passes(tmp_path: Path) -> None:
    _write_registry(tmp_path)
    ctx = _ctx(tmp_path, {"operations_center/entrypoints/maintenance/board_unblock.py": "def main():\n    return 0\n"})
    assert detect_cap1(ctx).count == 0


def test_unresolved_entrypoint_ref_flagged(tmp_path: Path) -> None:
    _write_registry(tmp_path)
    ctx = _ctx(tmp_path, {})  # module absent → rot
    result = detect_cap1(ctx)
    assert result.count == 1
    assert "board_unblock" in result.samples[0]
    assert "does not resolve" in result.samples[0]


def test_trailing_symbol_must_exist(tmp_path: Path) -> None:
    cap = _CAP_YAML.replace(
        "ref: operations_center.entrypoints.maintenance.board_unblock",
        "ref: operations_center.entrypoints.maintenance.run_unblock",
    )
    _write_registry(tmp_path, cap_yaml=cap)
    # module exists but lacks `run_unblock` symbol
    ctx = _ctx(tmp_path, {"operations_center/entrypoints/maintenance.py": "def main():\n    return 0\n"})
    assert detect_cap1(ctx).count == 1
    # add the symbol → resolves
    ctx_ok = _ctx(tmp_path, {"operations_center/entrypoints/maintenance.py": "def run_unblock():\n    return 0\n"})
    assert detect_cap1(ctx_ok).count == 0


def test_cli_ref_resolves_via_pyproject_scripts(tmp_path: Path) -> None:
    # repo_key Custodian owns repo_health_audit (cli: custodian-multi)
    _write_registry(tmp_path)
    pyproject = '[project.scripts]\ncustodian-multi = "custodian.cli.multi:main"\n'
    ctx = _ctx(tmp_path, {}, repo_key="Custodian", pyproject=pyproject)
    assert detect_cap1(ctx).count == 0


def test_cli_ref_missing_script_flagged(tmp_path: Path) -> None:
    _write_registry(tmp_path)
    ctx = _ctx(tmp_path, {}, repo_key="Custodian", pyproject='[project.scripts]\nsomething-else = "x:y"\n')
    result = detect_cap1(ctx)
    assert result.count == 1
    assert "repo_health_audit" in result.samples[0]


def test_only_owned_capabilities_are_checked(tmp_path: Path) -> None:
    # As OperationsCenter, custodian's cli ref is NOT our concern even if broken.
    _write_registry(tmp_path)
    ctx = _ctx(tmp_path, {"operations_center/entrypoints/maintenance/board_unblock.py": "def main(): ...\n"})
    assert detect_cap1(ctx).count == 0  # our one owned ref resolves; custodian's is skipped


def test_silent_without_repo_key(tmp_path: Path) -> None:
    _write_registry(tmp_path)
    ctx = _ctx(tmp_path, {}, repo_key=None)
    assert detect_cap1(ctx).count == 0


def test_silent_when_repo_owns_nothing(tmp_path: Path) -> None:
    _write_registry(tmp_path)
    # SwitchBoard owns no capability; even unmapped repo_key → silent
    ctx = _ctx(tmp_path, {}, repo_key="SwitchBoard")
    assert detect_cap1(ctx).count == 0


def test_silent_when_registry_absent(tmp_path: Path) -> None:
    # manifest present, capabilities.yaml absent
    data = tmp_path / "PlatformManifest" / "src" / "platform_manifest" / "data"
    data.mkdir(parents=True)
    (data / "platform_manifest.yaml").write_text(_PM_YAML)
    ctx = _ctx(tmp_path, {})
    assert detect_cap1(ctx).count == 0


def _ctx_registry_repo(tmp_path: Path, src_files: dict[str, str]) -> AuditContext:
    """Context that locates the manifest via capabilities.registry_repo only —
    NO cross_repo block (so the X-class detectors stay off)."""
    src_dir = tmp_path / "src"
    src_dir.mkdir(exist_ok=True)
    for relpath, body in src_files.items():
        p = src_dir / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_dir,
        tests_root=tmp_path / "tests",
        config={
            "repo_key": "OperationsCenter",
            "audit": {"capabilities": {"enforce": True, "registry_repo": "PlatformManifest"}},
        },
        graph=None,
        plugin_modules=[],
    )


def test_registry_repo_locates_manifest_without_cross_repo(tmp_path: Path) -> None:
    # No cross_repo block at all — CAP1 still finds the manifest + registry and
    # enforces (resolves the owned entrypoint ref).
    _write_registry(tmp_path)
    ctx = _ctx_registry_repo(
        tmp_path,
        {"operations_center/entrypoints/maintenance/board_unblock.py": "def main(): ...\n"},
    )
    assert detect_cap1(ctx).count == 0


def test_registry_repo_path_still_flags_broken_ref(tmp_path: Path) -> None:
    _write_registry(tmp_path)
    ctx = _ctx_registry_repo(tmp_path, {})  # module absent → rot, via registry_repo path
    assert detect_cap1(ctx).count == 1
