from __future__ import annotations

import json
from pathlib import Path

from custodian.cli.repograph_migration_gate import Finding, _check_repo


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
