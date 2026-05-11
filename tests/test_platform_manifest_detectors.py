# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
# ruff: noqa: S101
from __future__ import annotations

import json
from pathlib import Path
import sys

from custodian.audit_kit.detector import AuditContext
from custodian.cli.runner import run_repo_audit

_PM_SRC = Path(__file__).resolve().parents[2] / "PlatformManifest" / "src"
if str(_PM_SRC) not in sys.path:
    sys.path.insert(0, str(_PM_SRC))


def _pmv_detect():
    from platform_manifest.custodian_native import detect_pmv1, detect_pmv2

    return detect_pmv1, detect_pmv2


def _context(repo_root: Path, manifest_path: str = "public_manifest.json") -> AuditContext:
    return AuditContext(
        repo_root=repo_root,
        src_root=repo_root / "src",
        tests_root=repo_root / "tests",
        config={
            "repo_key": "sample",
            "audit": {
                "platform_manifest": {
                    "public_manifest_paths": [manifest_path],
                    "private_terms": ["PrivateImpl"],
                    "detector_contributor": "platform_manifest.custodian_native:build_custodian_detectors",
                }
            },
        },
        plugin_modules=[],
    )


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def test_pmv1_flags_forbidden_fields_private_urls_and_internal_paths(
    tmp_path: Path,
) -> None:
    _write_json(
        tmp_path / "public_manifest.json",
        {
            "manifest_kind": "platform",
            "manifest_version": "1.0.0",
            "repos": {
                "public_docs": {
                    "canonical_name": "PublicDocs",
                    "visibility": "public",
                    "private_url": "https://github.com/private/private-impl",
                    "metadata": {
                        "internal_path": "/home/dev/private/private-impl",
                        "note": "wraps PrivateImpl",
                    },
                }
            },
            "edges": [],
        },
    )

    detect_pmv1, _ = _pmv_detect()
    result = detect_pmv1(_context(tmp_path))

    assert result.count >= 4
    rendered = "\n".join(result.samples)
    assert "forbidden public field `private_url`" in rendered
    assert "private URL" in rendered
    assert "forbidden public field `internal_path`" in rendered
    assert "private term `PrivateImpl`" in rendered


def test_pmv1_passes_clean_public_projection(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "public_manifest.json",
        {
            "manifest_kind": "platform",
            "manifest_version": "1.0.0",
            "repos": {
                "public_docs": {
                    "canonical_name": "PublicDocs",
                    "visibility": "public",
                    "metadata": {"docs_url": "https://github.com/ProtocolWarden/PublicDocs"},
                }
            },
            "edges": [],
        },
    )

    detect_pmv1, _ = _pmv_detect()
    result = detect_pmv1(_context(tmp_path))

    assert result.count == 0


def test_pmv2_flags_edges_to_private_or_unknown_nodes(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "public_manifest.json",
        {
            "manifest_kind": "platform",
            "manifest_version": "1.0.0",
            "repos": {
                "public_docs": {"canonical_name": "PublicDocs", "visibility": "public"},
                "private_impl": {"canonical_name": "PrivateImpl", "visibility": "private"},
            },
            "edges": [
                {"from": "private_impl", "to": "public_docs", "type": "dispatches_to"},
                {"from": "public_docs", "to": "missing_repo", "type": "dispatches_to"},
            ],
        },
    )

    _, detect_pmv2 = _pmv_detect()
    result = detect_pmv2(_context(tmp_path))

    assert result.count == 2
    rendered = "\n".join(result.samples)
    assert "edge references private node private_impl->public_docs" in rendered
    assert "edge references non-public/unknown node public_docs->missing_repo" in rendered


def test_pmv2_flags_relationships_to_private_or_unknown_nodes(tmp_path: Path) -> None:
    _write_json(
        tmp_path / "public_manifest.json",
        {
            "manifest_kind": "platform",
            "manifest_version": "1.0.0",
            "repos": {
                "public_docs": {"canonical_name": "PublicDocs", "visibility": "public"},
                "private_impl": {"canonical_name": "PrivateImpl", "visibility": "private"},
            },
            "edges": [],
            "relationships": [
                {
                    "id": "r1",
                    "source": "public_docs",
                    "target": "private_impl",
                    "kind": "documents",
                    "visibility": "public",
                    "projection_behavior": "public_safe",
                },
                {
                    "id": "r2",
                    "source": "public_docs",
                    "target": "missing_repo",
                    "kind": "documents",
                    "visibility": "public",
                    "projection_behavior": "public_safe",
                },
            ],
        },
    )

    _, detect_pmv2 = _pmv_detect()
    result = detect_pmv2(_context(tmp_path))

    assert result.count == 2
    rendered = "\n".join(result.samples)
    assert "relationship references private node public_docs->private_impl" in rendered
    assert "relationship references non-public/unknown node public_docs->missing_repo" in rendered


def test_run_repo_audit_includes_platform_manifest_detectors(tmp_path: Path) -> None:
    (tmp_path / ".custodian").mkdir()
    (tmp_path / ".custodian" / "config.yaml").write_text(
        "repo_key: sample\n"
        "audit:\n"
        "  platform_manifest:\n"
        "    public_manifest_paths: [public_manifest.json]\n",
        encoding="utf-8",
    )
    _write_json(
        tmp_path / "public_manifest.json",
        {
            "manifest_kind": "platform",
            "manifest_version": "1.0.0",
            "repos": {
                "public_docs": {
                    "canonical_name": "PublicDocs",
                    "visibility": "public",
                    "private_bindings": "secret-runtime",
                }
            },
            "edges": [],
        },
    )

    result = run_repo_audit(tmp_path, only={"PMV1", "PMV2"})

    assert result.patterns["PMV1"]["count"] == 1
    assert result.patterns["PMV2"]["count"] == 0
