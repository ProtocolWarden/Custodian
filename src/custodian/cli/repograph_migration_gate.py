# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from hashlib import sha256


PUBLIC_REPOS = [
    "OperatorConsole",
    "OperationsCenter",
    "SwitchBoard",
    "CxRP",
    "RxP",
    "ExecutorRuntime",
    "SourceRegistry",
    "PlatformManifest",
    "PlatformDeployment",
    "Custodian",
    "Warehouse",
    "ProtocolWarden.github.io",
    "RepoGraph",
]


@dataclass
class Finding:
    repo: str
    file: str
    rule_id: str
    severity: str
    expected_boundary: str
    observed_violation: str
    recommended_fix: str


def _rg(repo: Path, pattern: str) -> list[str]:
    proc = subprocess.run(
        ["rg", "-n", pattern, "-S", str(repo)],
        capture_output=True,
        text=True,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(proc.stderr.strip() or f"rg failed for {repo}")
    return [line for line in proc.stdout.splitlines() if line.strip()]


def _check_boundary_artifact_required(repo: Path, findings: list[Finding]) -> None:
    cfg = repo / ".custodian" / "config.yaml"
    if not cfg.exists():
        return
    text = cfg.read_text(encoding="utf-8")
    if "require_boundary_artifact: true" not in text:
        findings.append(
            Finding(
                repo=repo.name,
                file=str(cfg),
                rule_id="boundary_artifact_required",
                severity="high",
                expected_boundary="public repos fail closed without boundary artifact",
                observed_violation="privacy.require_boundary_artifact is not true",
                recommended_fix="Set privacy.require_boundary_artifact: true",
            )
        )


def _check_boundary_artifact_provenance(repo: Path, boundary_artifact: Path, findings: list[Finding]) -> None:
    try:
        data = json.loads(boundary_artifact.read_text(encoding="utf-8"))
    except Exception as exc:
        findings.append(
            Finding(
                repo=repo.name,
                file=str(boundary_artifact),
                rule_id="boundary_artifact_invalid",
                severity="high",
                expected_boundary="valid RepoGraph boundary artifact JSON",
                observed_violation=f"json decode error: {exc}",
                recommended_fix="Regenerate artifact from PrivateManifest exporter",
            )
        )
        return

    if data.get("schema_kind") != "boundary_artifact" or data.get("schema_version") != "1.0.0":
        findings.append(
            Finding(
                repo=repo.name,
                file=str(boundary_artifact),
                rule_id="schema_version_supported",
                severity="high",
                expected_boundary="supported boundary artifact schema version",
                observed_violation=f"schema={data.get('schema_kind')!r} version={data.get('schema_version')!r}",
                recommended_fix="Regenerate artifact with supported RepoGraph schema version",
            )
        )
    if not data.get("source_graph_id") or not data.get("generated_at"):
        findings.append(
            Finding(
                repo=repo.name,
                file=str(boundary_artifact),
                rule_id="boundary_artifact_provenance_required",
                severity="high",
                expected_boundary="artifact includes provenance fields",
                observed_violation="missing source_graph_id or generated_at",
                recommended_fix="Generate artifact via PrivateManifest exporter",
            )
        )
    if not data.get("artifact_hash"):
        findings.append(
            Finding(
                repo=repo.name,
                file=str(boundary_artifact),
                rule_id="boundary_artifact_hash_valid",
                severity="high",
                expected_boundary="artifact hash present and valid",
                observed_violation="artifact_hash is missing",
                recommended_fix="Regenerate artifact with RepoGraph hash support",
            )
        )
    else:
        material = {
            key: value
            for key, value in data.items()
            if key not in {"artifact_hash", "signature", "signed_at", "public_projection_redaction_report"}
        }
        canonical = json.dumps(material, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        observed = sha256(canonical.encode("utf-8")).hexdigest()
        if observed != data["artifact_hash"]:
            findings.append(
                Finding(
                    repo=repo.name,
                    file=str(boundary_artifact),
                    rule_id="boundary_artifact_hash_valid",
                    severity="high",
                    expected_boundary="artifact hash matches payload",
                    observed_violation="artifact hash mismatch",
                    recommended_fix="Regenerate artifact from PrivateManifest exporter",
                )
            )


def _check_legacy_inputs(repo: Path, findings: list[Finding]) -> None:
    legacy_pattern = (
        r"CUSTODIAN_PRIVATE_"
        r"REPO_NAMES(_FILE)?|"
        r"privacy\.private_" r"repo_names(_file)?|"
        r"require_private_name_source|"
        r"private_" r"repo_names\.ya?ml"
    )
    for hit in _rg(repo, legacy_pattern):
        file_path = hit.split(":", 1)[0]
        if file_path.endswith("repograph_migration_gate.py"):
            continue
        if "/report/" in file_path.replace("\\", "/"):
            continue
        findings.append(
            Finding(
                repo=repo.name,
                file=file_path,
                rule_id="legacy_private_name_input_forbidden",
                severity="high",
                expected_boundary="no legacy private-name inputs",
                observed_violation=hit,
                recommended_fix="Remove legacy private-name env/config/file references",
            )
        )


def _check_workflow_artifact_file_only(repo: Path, findings: list[Finding]) -> None:
    wf = repo / ".github" / "workflows" / "custodian-audit.yml"
    if not wf.exists():
        return
    text = wf.read_text(encoding="utf-8")
    if "REPOGRAPH_BOUNDARY_ARTIFACT_FILE" not in text:
        findings.append(
            Finding(
                repo=repo.name,
                file=str(wf),
                rule_id="boundary_artifact_required",
                severity="high",
                expected_boundary="workflow uses REPOGRAPH_BOUNDARY_ARTIFACT_FILE",
                observed_violation="boundary artifact file env is missing",
                recommended_fix="Wire REPOGRAPH_BOUNDARY_ARTIFACT_FILE into workflow",
            )
        )
    if "REPOGRAPH_BOUNDARY_ARTIFACT:" in text:
        findings.append(
            Finding(
                repo=repo.name,
                file=str(wf),
                rule_id="manual_private_blocklist_forbidden",
                severity="high",
                expected_boundary="no inline artifact/private payload in workflow",
                observed_violation="inline REPOGRAPH_BOUNDARY_ARTIFACT env is configured",
                recommended_fix="Remove inline env and use boundary artifact file flow",
            )
        )


def _check_repo(repo: Path, boundary_artifact: Path, findings: list[Finding]) -> None:
    _check_boundary_artifact_required(repo, findings)
    _check_legacy_inputs(repo, findings)
    _check_workflow_artifact_file_only(repo, findings)
    if boundary_artifact.exists():
        _check_boundary_artifact_provenance(repo, boundary_artifact, findings)

    # Minimal ownership boundary checks required by migration gate.
    if repo.name == "Warehouse":
        for hit in _rg(repo, r"graph authority|topology owner|registry owner|scheduler|governance authority"):
            findings.append(
                Finding(
                    repo=repo.name,
                    file=hit.split(":", 1)[0],
                    rule_id="warehouse_not_graph_authority",
                    severity="medium",
                    expected_boundary="Warehouse is context packaging utility only",
                    observed_violation=hit,
                    recommended_fix="Rewrite Warehouse docs/config to utility-only ownership",
                )
            )

    if repo.name == "OperationsCenter":
        for hit in _rg(repo, r"owns (the )?(ontology|topology|projection|graph semantics)"):
            findings.append(
                Finding(
                    repo=repo.name,
                    file=hit.split(":", 1)[0],
                    rule_id="operations_center_not_graph_semantics_owner",
                    severity="medium",
                    expected_boundary="OperationsCenter consumes, not defines, graph semantics",
                    observed_violation=hit,
                    recommended_fix="Rewrite docs/code comments to consumer-only framing",
                )
            )

    if repo.name == "PlatformDeployment":
        for hit in _rg(repo, r"owns (the )?(ontology|topology|projection)"):
            findings.append(
                Finding(
                    repo=repo.name,
                    file=hit.split(":", 1)[0],
                    rule_id="platform_deployment_topography_only",
                    severity="medium",
                    expected_boundary="PlatformDeployment owns deployment/topography overlay only",
                    observed_violation=hit,
                    recommended_fix="Remove semantic-ownership wording from docs/code",
                )
            )

    if repo.name == "RepoGraph":
        docs = repo / "docs" / "schema-governance.md"
        if not docs.exists():
            findings.append(
                Finding(
                    repo=repo.name,
                    file=str(docs),
                    rule_id="schema_version_supported",
                    severity="medium",
                    expected_boundary="RepoGraph schema governance docs exist",
                    observed_violation="schema governance docs missing",
                    recommended_fix="Add docs/schema-governance.md documenting schema versions",
                )
            )
        rules = repo / "src" / "repograph" / "projection" / "rules.py"
        if rules.exists():
            text = rules.read_text(encoding="utf-8")
            if "projection_profile" not in text or "PUBLIC_SAFE" not in text:
                findings.append(
                    Finding(
                        repo=repo.name,
                        file=str(rules),
                        rule_id="projection_profile_public_safety",
                        severity="medium",
                        expected_boundary="public projection explicitly marks PUBLIC_SAFE",
                        observed_violation="projection profile safety marker missing",
                        recommended_fix="Write projection_profile=PUBLIC_SAFE into public manifest output",
                    )
                )

    if repo.name == "ProtocolWarden.github.io":
        doc_status = repo / "docs" / "architecture" / "doc-status.md"
        if not doc_status.exists():
            findings.append(
                Finding(
                    repo=repo.name,
                    file=str(doc_status),
                    rule_id="archival_doc_status_required",
                    severity="medium",
                    expected_boundary="docs architecture status convention page exists",
                    observed_violation="doc status page missing",
                    recommended_fix="Add docs/architecture/doc-status.md with current/historical rules",
                )
            )
        simple_model = repo / "docs" / "architecture" / "simple-platform-model.md"
        if not simple_model.exists():
            findings.append(
                Finding(
                    repo=repo.name,
                    file=str(simple_model),
                    rule_id="archival_doc_status_required",
                    severity="medium",
                    expected_boundary="simple platform model page exists with status metadata",
                    observed_violation="simple platform model page missing",
                    recommended_fix="Add current canonical simple-platform-model page with frontmatter",
                )
            )
        else:
            text = simple_model.read_text(encoding="utf-8")
            if "architecture_status: CURRENT" not in text or "canonical: true" not in text:
                findings.append(
                    Finding(
                        repo=repo.name,
                        file=str(simple_model),
                        rule_id="archival_doc_status_required",
                        severity="medium",
                        expected_boundary="current docs carry explicit archival status metadata",
                        observed_violation="missing CURRENT/canonical frontmatter",
                        recommended_fix="Add architecture_status: CURRENT and canonical: true",
                    )
                )
        workstation = repo / "docs" / "repos" / "workstation.md"
        if not workstation.exists():
            findings.append(
                Finding(
                    repo=repo.name,
                    file=str(workstation),
                    rule_id="archival_doc_status_required",
                    severity="medium",
                    expected_boundary="historical workstation page remains labeled",
                    observed_violation="historical workstation page missing",
                    recommended_fix="Keep the archival workstation page with HISTORICAL frontmatter",
                )
            )
        else:
            text = workstation.read_text(encoding="utf-8")
            if "architecture_status: HISTORICAL" not in text or "canonical: false" not in text:
                findings.append(
                    Finding(
                        repo=repo.name,
                        file=str(workstation),
                        rule_id="archival_doc_status_required",
                        severity="medium",
                        expected_boundary="historical workstation page is labeled non-canonical",
                        observed_violation="missing HISTORICAL/canonical: false frontmatter",
                        recommended_fix="Mark docs/repos/workstation.md as HISTORICAL and canonical: false",
                    )
                )

    # Boundary provenance checks live in _check_boundary_artifact_provenance().


def _write_markdown(path: Path, findings: list[Finding]) -> None:
    verdict = "PASS" if not findings else "FAIL"
    lines = [
        "# Full RepoGraph Migration Verification Report",
        "",
        "## Verdict",
        "",
        verdict,
        "",
        "## Enforcement findings",
        "",
    ]
    if not findings:
        lines.append("No findings.")
    else:
        for f in findings:
            lines.append(
                f"- `{f.rule_id}` `{f.repo}` `{f.file}`: {f.observed_violation} -> {f.recommended_fix}"
            )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--repo-root", type=Path, required=True)
    p.add_argument("--boundary-artifact", type=Path, required=True)
    p.add_argument("--json-out", type=Path, required=True)
    p.add_argument("--summary-out", type=Path, required=True)
    args = p.parse_args()

    if not args.boundary_artifact.exists():
        print("boundary artifact missing; failing closed", file=sys.stderr)
        sys.exit(1)

    findings: list[Finding] = []
    for name in PUBLIC_REPOS:
        repo = args.repo_root / name
        if not repo.exists():
            findings.append(
                Finding(
                    repo=name,
                    file=str(repo),
                    rule_id="repograph_required",
                    severity="high",
                    expected_boundary="required public repo exists in workspace",
                    observed_violation="repo missing",
                    recommended_fix="clone/sync required repo into workspace root",
                )
            )
            continue
        _check_repo(repo, args.boundary_artifact, findings)

    payload = {
        "verdict": "PASS" if not findings else "FAIL",
        "finding_count": len(findings),
        "findings": [asdict(f) for f in findings],
    }
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _write_markdown(args.summary_out, findings)

    if findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
