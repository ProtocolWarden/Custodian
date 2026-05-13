from __future__ import annotations

import json
from pathlib import Path

from custodian.cli.repograph_governance_gate import Finding, _check_public_repo_catalog, _check_repo
from custodian.policy.public_surface_catalog import (
    PUBLIC_REPO_CATALOG,
    PUBLIC_REPO_PAGE_SLUGS,
    allowed_repo_page,
    parse_canonical_repo_catalog,
)


def _write_boundary_artifact(path: Path) -> None:
    payload = {
        "schema_kind": "boundary_artifact",
        "schema_version": "1.0.0",
        "artifact_kind": "boundary_disclosure_artifact",
        "source_graph_id": "PrivateManifest",
        "source_ref_or_commit": "abc123",
        "generated_at": "2026-05-12T00:00:00Z",
        "forbidden_names": ["PrivateImpl"],
        "allowed_aliases": ["ManagedProjectPublic"],
        "redacted_entities": ["private_impl"],
        "redaction_rules_applied": ["forbid_non_public_canonical_names"],
    }
    path.write_text(json.dumps(payload), encoding="utf-8")


def _write_repo_graph_docs(root: Path, *, include_policy: bool, include_explorer: bool) -> None:
    docs = root / "RepoGraph" / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "schema-governance.md").write_text(
        "# RepoGraph Schema Governance\n\nRepoGraph keeps schema governance explicit.",
        encoding="utf-8",
    )
    (root / "RepoGraph" / "src" / "repograph" / "projection").mkdir(parents=True, exist_ok=True)
    (root / "RepoGraph" / "src" / "repograph" / "projection" / "rules.py").write_text(
        "projection_profile = 'PUBLIC_SAFE'\n",
        encoding="utf-8",
    )
    if include_policy:
        (docs / "policy-plane.md").write_text(
            "# RepoGraph Policy Plane\n\nPolicy != semantics.\n",
            encoding="utf-8",
        )
    if include_explorer:
        (docs / "repograph-explorer-spec.md").write_text(
            "# RepoGraph Explorer Spec\n\nThe explorer consumes projection outputs only.\n"
            "The explorer does not implement redaction logic.\n"
            "The public explorer uses `PUBLIC_SAFE` or `PUBLIC_DOCS` only.\n",
            encoding="utf-8",
        )


def test_repo_graph_gate_requires_policy_and_explorer_docs(tmp_path: Path) -> None:
    _write_repo_graph_docs(tmp_path, include_policy=False, include_explorer=False)
    boundary = tmp_path / "boundary.json"
    _write_boundary_artifact(boundary)
    findings: list[Finding] = []

    _check_repo(tmp_path / "RepoGraph", boundary, findings)

    rule_ids = {finding.rule_id for finding in findings}
    assert "policy_plane_separation_required" in rule_ids
    assert "explorer_projection_only" in rule_ids


def test_repo_graph_gate_accepts_policy_and_explorer_docs(tmp_path: Path) -> None:
    _write_repo_graph_docs(tmp_path, include_policy=True, include_explorer=True)
    boundary = tmp_path / "boundary.json"
    _write_boundary_artifact(boundary)
    findings: list[Finding] = []

    _check_repo(tmp_path / "RepoGraph", boundary, findings)

    rule_ids = {finding.rule_id for finding in findings}
    assert "policy_plane_separation_required" not in rule_ids
    assert "explorer_projection_only" not in rule_ids


def test_custodian_gate_requires_semantic_federation_workflow(tmp_path: Path) -> None:
    (tmp_path / "Custodian" / ".github" / "workflows").mkdir(parents=True, exist_ok=True)
    boundary = tmp_path / "boundary.json"
    _write_boundary_artifact(boundary)
    findings: list[Finding] = []

    _check_repo(tmp_path / "Custodian", boundary, findings)

    assert any(f.rule_id == "cross_repo_semantic_ci_required" for f in findings)


def test_public_repo_catalog_accepts_only_approved_public_pages(tmp_path: Path) -> None:
    repo = tmp_path / "ProtocolWarden.github.io"
    (repo / "docs" / "repos").mkdir(parents=True, exist_ok=True)
    (repo / "docs" / "governance").mkdir(parents=True, exist_ok=True)
    (repo / "mkdocs.yml").write_text(
        "nav:\n"
        "  - Repos:\n"
        "      - Overview: repos/index.md\n"
        "      - OperationsCenter: repos/operationscenter.md\n"
        "      - OperatorConsole: repos/operatorconsole.md\n"
        "      - PlatformManifest: repos/platformmanifest.md\n"
        "      - Custodian: repos/custodian.md\n"
        "      - CxRP: repos/cxrp.md\n"
        "      - RxP: repos/rxp.md\n"
        "      - ExecutorRuntime: repos/executorruntime.md\n"
        "      - SwitchBoard: repos/switchboard.md\n"
        "      - SourceRegistry: repos/sourceregistry.md\n"
        "      - PlatformDeployment: repos/platformdeployment.md\n"
        "      - Warehouse: repos/warehouse.md\n",
        encoding="utf-8",
    )
    (repo / "docs" / "governance" / "public-repo-catalog.md").write_text(
        "# Public Repository Catalog\n\nThe browseable repository catalog is curated.\n",
        encoding="utf-8",
    )
    (repo / "docs" / "repos" / "index.md").write_text(
        "# Repository Catalog\n\n## Canonical repos\n\n"
        "| Repo | Role | Notes |\n"
        "| --- | --- | --- |\n"
        "| [OperationsCenter](operationscenter.md) | orchestration consumer | consumes composed graph truth, does not own graph semantics |\n"
        "| [OperatorConsole](operatorconsole.md) | operator-facing control surface | local operator workflows and observability, not graph semantics |\n"
        "| [PlatformManifest](platformmanifest.md) | public graph publisher | public-safe projection surface backed by RepoGraph |\n"
        "| [Custodian](custodian.md) | boundary verifier | fail-closed drift and boundary enforcement |\n"
        "| [CxRP](cxrp.md) | cross-repo protocol | contract surface for execution and routing |\n"
        "| [RxP](rxp.md) | runtime protocol | runtime invocation semantics |\n"
        "| [ExecutorRuntime](executorruntime.md) | runtime mechanics | execution mechanics and adapters |\n"
        "| [SwitchBoard](switchboard.md) | lane selection | routing and backend selection |\n"
        "| [SourceRegistry](sourceregistry.md) | source inventory | source and capability registry |\n"
        "| [PlatformDeployment](platformdeployment.md) | deployment/topography overlay | runtime glue and local/CI ergonomics |\n"
        "| [Warehouse](warehouse.md) | context packaging utility | packaging and staging only |\n"
        "\n## Managed projects\n\nThe public site does not catalog private-truth repos as normal browsable repo pages.\n",
        encoding="utf-8",
    )
    findings: list[Finding] = []

    _check_public_repo_catalog(repo, findings)

    assert not findings


def test_public_repo_catalog_rejects_private_truth_repo_pages(tmp_path: Path) -> None:
    repo = tmp_path / "ProtocolWarden.github.io"
    (repo / "docs" / "repos").mkdir(parents=True, exist_ok=True)
    (repo / "docs" / "governance").mkdir(parents=True, exist_ok=True)
    (repo / "mkdocs.yml").write_text(
        "nav:\n"
        "  - Repos:\n"
        "      - Overview: repos/index.md\n"
        "      - PrivateManifest: repos/privatemanifest.md\n",
        encoding="utf-8",
    )
    (repo / "docs" / "governance" / "public-repo-catalog.md").write_text(
        "# Public Repository Catalog\n\nThe browseable repository catalog is curated.\n",
        encoding="utf-8",
    )
    (repo / "docs" / "repos" / "index.md").write_text(
        "# Repository Catalog\n\n## Canonical repos\n\n"
        "| Repo | Role | Notes |\n"
        "| --- | --- | --- |\n"
        "| [PrivateManifest](privatemanifest.md) | private graph truth | private-truth repo page |\n",
        encoding="utf-8",
    )
    findings: list[Finding] = []

    _check_public_repo_catalog(repo, findings)

    assert any(finding.rule_id == "public_repo_catalog_only" for finding in findings)


def test_public_repo_catalog_rejects_archive_pages(tmp_path: Path) -> None:
    repo = tmp_path / "ProtocolWarden.github.io"
    (repo / "docs" / "repos").mkdir(parents=True, exist_ok=True)
    (repo / "docs" / "architecture").mkdir(parents=True, exist_ok=True)
    (repo / "docs" / "governance").mkdir(parents=True, exist_ok=True)
    (repo / "mkdocs.yml").write_text(
        "nav:\n"
        "  - Repos:\n"
        "      - Overview: repos/index.md\n"
        "      - OperationsCenter: repos/operationscenter.md\n"
        "  - Architecture:\n"
        "      - Overview: architecture/index.md\n"
        "      - Documentation Status: architecture/doc-status.md\n",
        encoding="utf-8",
    )
    (repo / "docs" / "governance" / "public-repo-catalog.md").write_text(
        "# Public Repository Catalog\n\nThe browseable repository catalog is curated.\n",
        encoding="utf-8",
    )
    (repo / "docs" / "repos" / "index.md").write_text(
        "# Repository Catalog\n\n## Canonical repos\n\n"
        "| Repo | Role | Notes |\n"
        "| --- | --- | --- |\n"
        "| [OperationsCenter](operationscenter.md) | orchestration consumer | consumes composed graph truth |\n"
        "\n## Managed projects\n\nThe public site does not catalog private-truth repos as normal browsable repo pages.\n",
        encoding="utf-8",
    )
    (repo / "docs" / "architecture" / "doc-status.md").write_text(
        "# Documentation Status\n\nThe site uses archival labels.\n",
        encoding="utf-8",
    )
    findings: list[Finding] = []

    _check_public_repo_catalog(repo, findings)

    rule_ids = {finding.rule_id for finding in findings}
    assert "public_repo_catalog_only" in rule_ids


def test_public_surface_rejects_private_repo_names(tmp_path: Path) -> None:
    repo = tmp_path / "ProtocolWarden.github.io"
    (repo / "docs" / "overview").mkdir(parents=True, exist_ok=True)
    (repo / "README.md").write_text(
        "# ProtocolWarden\n\nPrivateManifest should not appear here.\n",
        encoding="utf-8",
    )
    (repo / "mkdocs.yml").write_text(
        "nav:\n"
        "  - Overview:\n"
        "      - Ecosystem: docs/overview/index.md\n",
        encoding="utf-8",
    )
    (repo / "docs" / "overview" / "index.md").write_text(
        "# Overview\n\nVideoFoundry should not appear here either.\n",
        encoding="utf-8",
    )
    boundary = tmp_path / "boundary.json"
    payload = {
        "schema_kind": "boundary_artifact",
        "schema_version": "1.0.0",
        "artifact_kind": "boundary_disclosure_artifact",
        "source_graph_id": "PrivateManifest",
        "source_ref_or_commit": "abc123",
        "generated_at": "2026-05-13T00:00:00Z",
        "forbidden_names": ["PrivateManifest", "VideoFoundry"],
        "allowed_aliases": [],
        "redacted_entities": [],
        "redaction_rules_applied": [],
    }
    boundary.write_text(json.dumps(payload), encoding="utf-8")
    findings: list[Finding] = []

    _check_repo(repo, boundary, findings)

    rule_ids = {finding.rule_id for finding in findings}
    assert "public_private_repo_names_forbidden" in rule_ids


def test_public_repo_catalog_policy_is_explicit() -> None:
    catalog = "\n".join(
        [
            "# Repository Catalog",
            "",
            "## Core platform repos",
            "",
            "| Repo | Role | Notes |",
            "| --- | --- | --- |",
            "| [OperationsCenter](operationscenter.md) | orchestration consumer | consumes composed graph truth |",
            "| [Warehouse](warehouse.md) | context packaging utility | packaging and staging only |",
        ]
    )
    entries = parse_canonical_repo_catalog(catalog)
    assert [entry.repo for entry in entries] == ["OperationsCenter", "Warehouse"]
    assert allowed_repo_page("RepoGraph") == "repograph.md"
    assert allowed_repo_page("OperationsCenter") == "operationscenter.md"
    assert "operationscenter.md" in PUBLIC_REPO_PAGE_SLUGS
    assert PUBLIC_REPO_CATALOG["Warehouse"] == "warehouse.md"
