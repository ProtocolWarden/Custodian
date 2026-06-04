# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from hashlib import sha256

from custodian.policy.public_surface_catalog import (
    PUBLIC_REPO_PAGE_SLUGS,
    allowed_repo_page,
    parse_canonical_repo_catalog,
)


PUBLIC_REPOS = [
    "OperatorConsole",
    "OperationsCenter",
    "SwitchBoard",
    "CxRP",
    "RxP",
    "CoreRunner",
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
        timeout=30,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(proc.stderr.strip() or f"rg failed for {repo}")
    return [line for line in proc.stdout.splitlines() if line.strip()]


def _check_public_repo_catalog(repo: Path, findings: list[Finding]) -> None:
    if repo.name != "ProtocolWarden.github.io":
        return

    index = repo / "docs" / "repos" / "index.md"
    if not index.exists():
        return
    text = index.read_text(encoding="utf-8")
    entries = parse_canonical_repo_catalog(text)
    for entry in entries:
        approved_slug = allowed_repo_page(entry.repo)
        if approved_slug is None:
            findings.append(
                Finding(
                    repo=repo.name,
                    file=str(index),
                    rule_id="public_repo_catalog_only",
                    severity="high",
                    expected_boundary="canonical repo catalog lists only approved public repos",
                    observed_violation=f"unapproved repo catalog entry: {entry.repo} -> {entry.slug}",
                    recommended_fix="Remove private-truth or unmanaged repos from the browseable catalog",
                )
            )
        elif approved_slug != Path(entry.slug).name:
            findings.append(
                Finding(
                    repo=repo.name,
                    file=str(index),
                    rule_id="public_repo_catalog_only",
                    severity="high",
                    expected_boundary="canonical repo catalog entry maps to the approved page slug",
                    observed_violation=f"{entry.repo} is linked to {entry.slug}, expected {approved_slug}",
                    recommended_fix="Update the catalog link to the approved repo page slug",
                )
            )

    nav = repo / "mkdocs.yml"
    if nav.exists():
        nav_text = nav.read_text(encoding="utf-8")
        nav_pages = {
            Path(match.group(1)).name
            for match in re.finditer(r"repos/([A-Za-z0-9_.-]+\.md)", nav_text)
        }
        unexpected = sorted(
            page
            for page in nav_pages
            if page not in PUBLIC_REPO_PAGE_SLUGS | {"index.md"}
        )
        for page in unexpected:
            findings.append(
                Finding(
                    repo=repo.name,
                    file=str(nav),
                    rule_id="public_repo_catalog_only",
                    severity="high",
                    expected_boundary="site nav only exposes approved public repo pages",
                    observed_violation=f"unexpected repo page in nav: {page}",
                    recommended_fix="Remove non-catalog repo pages from the public repository navigation",
                )
            )

    if "private-truth repos as normal browsable repo pages" not in text.lower() and "private-truth repos are not normal browsable repo pages" not in text.lower():
        findings.append(
            Finding(
                repo=repo.name,
                file=str(index),
                rule_id="public_repo_catalog_only",
                severity="medium",
                expected_boundary="catalog explains private-truth repos are not browseable repo pages",
                observed_violation="catalog does not state the private-truth / catalog boundary",
                recommended_fix="Add the managed-projects note that private-truth repos are not normal browsable repo pages",
            )
        )

    policy_doc = repo / "docs" / "governance" / "public-repo-catalog.md"
    if not policy_doc.exists():
        findings.append(
            Finding(
                repo=repo.name,
                file=str(policy_doc),
                rule_id="public_repo_catalog_only",
                severity="high",
                expected_boundary="public repo catalog policy is documented",
                observed_violation="public repo catalog policy doc missing",
                recommended_fix="Add docs/governance/public-repo-catalog.md and link it from the governance index",
            )
        )

    if "historical" in text.lower() or "archival" in text.lower():
        findings.append(
            Finding(
                repo=repo.name,
                file=str(index),
                rule_id="public_repo_catalog_only",
                severity="medium",
                expected_boundary="public repo catalog contains only current entries",
                observed_violation="historical or archival catalog language remains",
                recommended_fix="Remove archival/historical repo catalog language and keep only current entries",
            )
        )

    doc_status = repo / "docs" / "architecture" / "doc-status.md"
    if doc_status.exists():
        findings.append(
            Finding(
                repo=repo.name,
                file=str(doc_status),
                rule_id="public_repo_catalog_only",
                severity="high",
                expected_boundary="no archival status system in the public site",
                observed_violation="doc-status page still present",
                recommended_fix="Remove docs/architecture/doc-status.md and its nav entry",
            )
        )



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
                recommended_fix="Regenerate artifact with the private-manifest exporter",
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
                recommended_fix="Generate artifact with the private-manifest exporter",
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
                    recommended_fix="Regenerate artifact with the private-manifest exporter",
                )
            )


def _load_forbidden_names(boundary_artifact: Path) -> frozenset[str]:
    """Return the forbidden repo names from the boundary artifact, or empty set if unavailable."""
    try:
        data = json.loads(boundary_artifact.read_text(encoding="utf-8"))
        names = data.get("forbidden_names") or []
        return frozenset(str(n) for n in names if isinstance(n, str))
    except Exception:
        return frozenset()


def _check_public_private_repo_names(
    repo: Path, forbidden_names: frozenset[str], findings: list[Finding]
) -> None:
    if repo.name != "ProtocolWarden.github.io" or not forbidden_names:
        return

    search_roots = [repo / "README.md", repo / "mkdocs.yml", repo / "docs"]
    for name in sorted(forbidden_names):
        for root in search_roots:
            if not root.exists():
                continue
            for hit in _rg(root, rf"\b{re.escape(name)}\b"):
                findings.append(
                    Finding(
                        repo=repo.name,
                        file=hit.split(":", 1)[0],
                        rule_id="public_private_repo_names_forbidden",
                        severity="high",
                        expected_boundary="public docs do not name private-truth repos as public surfaces",
                        observed_violation=hit,
                        recommended_fix=f"Remove {name} from the public docs surface and keep it out of browseable pages",
                    )
                )

    for name in sorted(forbidden_names):
        slug = name.lower() + ".md"
        for hit in _rg(repo / "docs", rf"\b{re.escape(slug)}\b"):
            findings.append(
                Finding(
                    repo=repo.name,
                    file=hit.split(":", 1)[0],
                    rule_id="public_private_repo_names_forbidden",
                    severity="high",
                    expected_boundary="public docs do not expose private-truth repo page slugs",
                    observed_violation=hit,
                    recommended_fix=f"Remove the {name} repo page from docs and navigation",
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
        if file_path.endswith("repograph_governance_gate.py"):
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
    _check_public_repo_catalog(repo, findings)
    _check_public_private_repo_names(repo, _load_forbidden_names(boundary_artifact), findings)

    # Minimal ownership boundary checks required by the RepoGraph governance gate.
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
        policy = repo / "docs" / "policy-plane.md"
        if not policy.exists():
            findings.append(
                Finding(
                    repo=repo.name,
                    file=str(policy),
                    rule_id="policy_plane_separation_required",
                    severity="medium",
                    expected_boundary="RepoGraph policy boundary doc exists",
                    observed_violation="policy plane doc missing",
                    recommended_fix="Add docs/policy-plane.md documenting policy != semantics",
                )
            )
        else:
            text = policy.read_text(encoding="utf-8")
            if "policy is not semantics" not in text.lower() and "policy != semantics" not in text.lower():
                findings.append(
                    Finding(
                        repo=repo.name,
                        file=str(policy),
                        rule_id="policy_plane_separation_required",
                        severity="medium",
                        expected_boundary="policy stays separate from graph semantics",
                        observed_violation="policy/semantics separation is not stated",
                        recommended_fix="State that policy is adjacent to semantics, not the semantics layer",
                    )
                )
        explorer = repo / "docs" / "repograph-explorer-spec.md"
        if not explorer.exists():
            findings.append(
                Finding(
                    repo=repo.name,
                    file=str(explorer),
                    rule_id="explorer_projection_only",
                    severity="medium",
                    expected_boundary="public-safe explorer spec exists",
                    observed_violation="explorer spec missing",
                    recommended_fix="Add docs/repograph-explorer-spec.md describing projection-only rendering",
                )
            )
        else:
            text = explorer.read_text(encoding="utf-8")
            required_phrases = (
                "projection outputs only",
                "does not implement redaction logic",
                "public explorer uses `PUBLIC_SAFE` or `PUBLIC_DOCS` only",
            )
            if not all(phrase.lower() in text.lower() for phrase in required_phrases):
                findings.append(
                    Finding(
                        repo=repo.name,
                        file=str(explorer),
                        rule_id="explorer_projection_only",
                        severity="medium",
                        expected_boundary="explorer renders projections only",
                        observed_violation="explorer spec does not constrain projection bypass",
                        recommended_fix="State that the explorer consumes projections only and cannot redact",
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

    if repo.name == "Custodian":
        federation = repo / ".github" / "workflows" / "semantic-federation.yml"
        if not federation.exists():
            findings.append(
                Finding(
                    repo=repo.name,
                    file=str(federation),
                    rule_id="cross_repo_semantic_ci_required",
                    severity="medium",
                    expected_boundary="federated semantic CI workflow exists",
                    observed_violation="semantic federation workflow missing",
                    recommended_fix="Add .github/workflows/semantic-federation.yml to run the cross-repo gate",
                )
            )
        else:
            text = federation.read_text(encoding="utf-8")
            if "custodian-repograph-governance-gate" not in text or "ProtocolWarden.github.io" not in text:
                findings.append(
                    Finding(
                        repo=repo.name,
                        file=str(federation),
                        rule_id="cross_repo_semantic_ci_required",
                        severity="medium",
                        expected_boundary="workflow clones and audits the public repo set",
                        observed_violation="semantic federation workflow is not wired to the full public repo set",
                        recommended_fix="Clone the public repos and run custodian-repograph-governance-gate over them",
                    )
                )

    if repo.name == "ProtocolWarden.github.io":
        simple_model = repo / "docs" / "architecture" / "simple-platform-model.md"
        if not simple_model.exists():
            findings.append(
                Finding(
                    repo=repo.name,
                    file=str(simple_model),
                    rule_id="public_repo_catalog_only",
                    severity="medium",
                    expected_boundary="simple platform model page exists",
                    observed_violation="simple platform model page missing",
                    recommended_fix="Add current simple-platform-model page",
                )
            )
        else:
            text = simple_model.read_text(encoding="utf-8")
            if "architecture_status:" in text or "canonical:" in text:
                findings.append(
                    Finding(
                        repo=repo.name,
                        file=str(simple_model),
                        rule_id="public_repo_catalog_only",
                        severity="medium",
                        expected_boundary="simple platform model contains no archival frontmatter",
                        observed_violation="status frontmatter remains on a current page",
                        recommended_fix="Remove architecture_status/canonical frontmatter from the public model page",
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
    args.json_out.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    _write_markdown(args.summary_out, findings)

    if findings:
        sys.exit(1)


if __name__ == "__main__":
    main()
