# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""B-class detector tests — boundary artifact enforcement."""
from __future__ import annotations

import json
from hashlib import sha256
import subprocess
from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.boundary import build_boundary_detectors, detect_b1, detect_b2


def _ctx(repo_root: Path, config: dict) -> AuditContext:
    src_root = repo_root / "src"
    tests_root = repo_root / "tests"
    src_root.mkdir(parents=True, exist_ok=True)
    tests_root.mkdir(parents=True, exist_ok=True)
    return AuditContext(
        repo_root=repo_root,
        src_root=src_root,
        tests_root=tests_root,
        config=config,
        plugin_modules=[],
        graph=None,
    )


def _git_init(root: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)


def _write_artifact(path: Path, forbidden: list[str]) -> None:
    payload = {
        "schema_kind": "boundary_artifact",
        "schema_version": "1.0.0",
        "artifact_kind": "boundary_disclosure_artifact",
        "source_graph_id": "PrivateGraphFixture",
        "source_ref_or_commit": "abc123",
        "generated_at": "2026-05-13T00:00:00Z",
        "forbidden_names": forbidden,
        "allowed_aliases": ["VideoFoundryPublic"],
        "redacted_entities": [],
        "redaction_rules_applied": [],
    }
    payload["artifact_hash"] = sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    path.write_text(json.dumps(payload), encoding="utf-8")


class TestB1BoundaryArtifact:
    def test_finds_forbidden_name_in_tracked_file(self, tmp_path: Path) -> None:
        artifact = tmp_path / "boundary.json"
        _write_artifact(artifact, ["MyPrivateRepo"])
        (tmp_path / "README.md").write_text("Uses MyPrivateRepo\n", encoding="utf-8")
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"boundary_artifact_file": str(artifact)}})
        result = detect_b1(ctx)
        assert result.count == 1
        assert "README.md:1" in result.samples[0]
        assert "boundary=PrivateGraphFixture@abc123" in result.samples[0]

    def test_uses_artifact_env_file(self, tmp_path: Path, monkeypatch) -> None:
        artifact = tmp_path / "boundary.json"
        _write_artifact(artifact, ["MyPrivateRepo"])
        (tmp_path / "doc.md").write_text("MyPrivateRepo\n", encoding="utf-8")
        _git_init(tmp_path)
        monkeypatch.setenv("REPOGRAPH_BOUNDARY_ARTIFACT_FILE", str(artifact))
        result = detect_b1(_ctx(tmp_path, {}))
        assert result.count == 1

    def test_no_boundary_source_returns_zero(self, tmp_path: Path) -> None:
        (tmp_path / "doc.md").write_text("MyPrivateRepo\n", encoding="utf-8")
        _git_init(tmp_path)
        result = detect_b1(_ctx(tmp_path, {}))
        assert result.count == 0


class TestB2Required:
    def test_b2_flags_missing_required_boundary_source(self, tmp_path: Path) -> None:
        _git_init(tmp_path)
        result = detect_b2(_ctx(tmp_path, {"privacy": {"require_boundary_artifact": True}}))
        assert result.count == 1
        assert "require_boundary_artifact=true" in result.samples[0]

    def test_b2_passes_when_boundary_artifact_present(self, tmp_path: Path) -> None:
        artifact = tmp_path / "boundary.json"
        _write_artifact(artifact, ["MyPrivateRepo"])
        _git_init(tmp_path)
        result = detect_b2(
            _ctx(
                tmp_path,
                {"privacy": {"require_boundary_artifact": True, "boundary_artifact_file": str(artifact)}},
            )
        )
        assert result.count == 0

    def test_b2_content_less_artifact_distinct_message(self, tmp_path: Path) -> None:
        # A provided-but-empty artifact (zero forbidden_names) must report a
        # distinct "content-less" message pointing at the data, not the generic
        # "no file provided" config message — they have different fixes.
        artifact = tmp_path / "boundary.json"
        _write_artifact(artifact, [])  # valid schema, zero forbidden_names
        _git_init(tmp_path)
        result = detect_b2(
            _ctx(
                tmp_path,
                {"privacy": {"require_boundary_artifact": True, "boundary_artifact_file": str(artifact)}},
            )
        )
        assert result.count == 1
        assert "content-less" in result.samples[0]
        assert "zero forbidden_names" in result.samples[0]
        assert "PrivateGraphFixture" in result.samples[0]  # provenance surfaced

    def test_invalid_artifact_fails_closed(self, tmp_path: Path) -> None:
        artifact = tmp_path / "boundary.json"
        artifact.write_text("{}", encoding="utf-8")
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"boundary_artifact_file": str(artifact), "require_boundary_artifact": True}})
        result = detect_b1(ctx)
        assert result.count == 1
        assert "boundary artifact" in result.samples[0]


def test_build_returns_b1_b2() -> None:
    detectors = build_boundary_detectors()
    assert {d.id for d in detectors} == {"B1", "B2"}
