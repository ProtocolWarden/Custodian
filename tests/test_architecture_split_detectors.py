# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
# ruff: noqa: S101
from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.detectors.architecture_split import (
    detect_arch1,
    detect_arch2,
    detect_arch3,
)
from custodian.audit_kit.detector import AuditContext


def _context(repo_root: Path, repo_key: str) -> AuditContext:
    return AuditContext(
        repo_root=repo_root,
        src_root=repo_root / "src",
        tests_root=repo_root / "tests",
        config={"repo_key": repo_key},
        plugin_modules=[],
    )


def test_arch1_passes_for_utility_wording(tmp_path: Path) -> None:
    repo = tmp_path / "Warehouse"
    repo.mkdir()
    (repo / "README.md").write_text(
        "# Warehouse\n\nWarehouse is a context packaging utility.\n",
        encoding="utf-8",
    )
    result = detect_arch1(_context(repo, "Warehouse"))
    assert result.count == 0


def test_arch2_flags_schema_fork_in_private_topology_repo(tmp_path: Path) -> None:
    repo = tmp_path / "private-topology"
    (repo / "schemas").mkdir(parents=True)
    (repo / "manifests").mkdir(parents=True)
    (repo / "schemas" / "private_manifest.schema.json").write_text("{}", encoding="utf-8")
    result = detect_arch2(_context(repo, "private-topology"))
    assert result.count == 1
    assert "should not define manifest schemas" in result.samples[0]


def test_arch3_flags_old_workstation_canonical_claim(tmp_path: Path) -> None:
    repo = tmp_path / "PlatformDeployment"
    (repo / "docs").mkdir(parents=True)
    (repo / "docs" / "README.md").write_text(
        "PlatformDeployment hosts the canonical platform architecture docs.",
        encoding="utf-8",
    )
    result = detect_arch3(_context(repo, "PlatformDeployment"))
    assert result.count >= 1
    assert "deprecated canonical-architecture claim" in "\n".join(result.samples)
