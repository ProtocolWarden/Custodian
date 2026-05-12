# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""B-class detector tests — private-repo-name leakage."""
from __future__ import annotations

import json
import subprocess
from pathlib import Path


from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.boundary import build_boundary_detectors, detect_b1, detect_b2


def _ctx(
    repo_root: Path,
    config: dict,
) -> AuditContext:
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
    """Initialize a git repo and stage all files so git ls-files works."""
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)


class TestB1FlagsLeakedNames:
    def test_finds_name_in_markdown(self, tmp_path: Path):
        (tmp_path / "README.md").write_text(
            "# OperationsCenter\n\nManages MyPrivateRepo workflows.\n",
            encoding="utf-8",
        )
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"private_repo_names": ["MyPrivateRepo"]}})
        result = detect_b1(ctx)
        assert result.count == 1
        assert "README.md:3" in result.samples[0]
        assert "MyPrivateRepo" in result.samples[0]

    def test_finds_name_in_yaml_and_python(self, tmp_path: Path):
        (tmp_path / "config.yaml").write_text(
            "repo: MyPrivateRepo\n", encoding="utf-8",
        )
        (tmp_path / "src").mkdir(exist_ok=True)
        (tmp_path / "src" / "main.py").write_text(
            "REPO_ID = 'myprivaterepo'\n", encoding="utf-8",
        )
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"private_repo_names": [
            "MyPrivateRepo", "myprivaterepo",
        ]}})
        result = detect_b1(ctx)
        assert result.count >= 2

    def test_case_sensitive(self, tmp_path: Path):
        (tmp_path / "doc.md").write_text("Mention of myprivaterepo only.\n", encoding="utf-8")
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"private_repo_names": ["MyPrivateRepo"]}})
        # CamelCase configured — lowercase reference should NOT match.
        result = detect_b1(ctx)
        assert result.count == 0

    def test_multiple_lines_each_flagged(self, tmp_path: Path):
        (tmp_path / "doc.md").write_text(
            "Line 1: MyPrivateRepo\n"
            "Line 2: nothing\n"
            "Line 3: MyPrivateRepo again\n",
            encoding="utf-8",
        )
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"private_repo_names": ["MyPrivateRepo"]}})
        result = detect_b1(ctx)
        assert result.count == 2


class TestB1Excludes:
    def test_default_excludes_console_dir(self, tmp_path: Path):
        (tmp_path / ".console").mkdir()
        (tmp_path / ".console" / "log.md").write_text(
            "Historical: MyPrivateRepo work landed in 2024.\n",
            encoding="utf-8",
        )
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"private_repo_names": ["MyPrivateRepo"]}})
        result = detect_b1(ctx)
        assert result.count == 0

    def test_default_excludes_managed_repos_local(self, tmp_path: Path):
        (tmp_path / "config" / "managed_repos" / "local").mkdir(parents=True)
        (tmp_path / "config" / "managed_repos" / "local" / "binding.yaml").write_text(
            "repo: MyPrivateRepo\n", encoding="utf-8",
        )
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"private_repo_names": ["MyPrivateRepo"]}})
        result = detect_b1(ctx)
        assert result.count == 0

    def test_default_excludes_history_docs(self, tmp_path: Path):
        (tmp_path / "docs" / "history").mkdir(parents=True)
        (tmp_path / "docs" / "history" / "old.md").write_text(
            "MyPrivateRepo migration log.\n", encoding="utf-8",
        )
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"private_repo_names": ["MyPrivateRepo"]}})
        result = detect_b1(ctx)
        assert result.count == 0

    def test_consumer_can_add_excludes(self, tmp_path: Path):
        (tmp_path / "examples").mkdir()
        (tmp_path / "examples" / "demo.md").write_text(
            "MyPrivateRepo demo.\n", encoding="utf-8",
        )
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {
            "private_repo_names": ["MyPrivateRepo"],
            "exclude_paths": ["examples/**"],
        }})
        result = detect_b1(ctx)
        assert result.count == 0

    def test_skips_binary_files(self, tmp_path: Path):
        (tmp_path / "logo.png").write_bytes(b"\x89PNG fake MyPrivateRepo")
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"private_repo_names": ["MyPrivateRepo"]}})
        result = detect_b1(ctx)
        assert result.count == 0


class TestB1ConfigParsing:
    def test_loads_names_from_boundary_artifact_file(self, tmp_path: Path):
        artifact = tmp_path / "boundary.json"
        artifact.write_text(
            json.dumps({
                "source_graph_id": "PrivateManifest",
                "source_ref_or_commit": "abc123",
                "forbidden_names": ["MyPrivateRepo"],
                "allowed_aliases": ["PublicAlias"],
                "redacted_entities": [],
                "redaction_rules_applied": [],
            }),
            encoding="utf-8",
        )
        (tmp_path / "doc.md").write_text("MyPrivateRepo\n", encoding="utf-8")
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"boundary_artifact_file": str(artifact)}})
        result = detect_b1(ctx)
        assert result.count == 1
        assert "boundary=PrivateManifest@abc123" in result.samples[0]

    def test_no_config_returns_zero(self, tmp_path: Path):
        (tmp_path / "doc.md").write_text("MyPrivateRepo\n", encoding="utf-8")
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {})
        result = detect_b1(ctx)
        assert result.count == 0
        assert result.samples == []

    def test_empty_names_returns_zero(self, tmp_path: Path):
        (tmp_path / "doc.md").write_text("MyPrivateRepo\n", encoding="utf-8")
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"private_repo_names": []}})
        result = detect_b1(ctx)
        assert result.count == 0

    def test_loads_names_from_yaml_file(self, tmp_path: Path):
        names_file = tmp_path / "private_repo_names.yaml"
        names_file.write_text("private_repo_names:\n  - MyPrivateRepo\n", encoding="utf-8")
        (tmp_path / "doc.md").write_text("MyPrivateRepo\n", encoding="utf-8")
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"private_repo_names_file": str(names_file)}})
        result = detect_b1(ctx)
        assert result.count == 1

    def test_loads_names_from_env_file(self, tmp_path: Path, monkeypatch):
        names_file = tmp_path / "private_repo_names.txt"
        names_file.write_text("MyPrivateRepo\n", encoding="utf-8")
        (tmp_path / "doc.md").write_text("MyPrivateRepo\n", encoding="utf-8")
        _git_init(tmp_path)
        monkeypatch.setenv("CUSTODIAN_PRIVATE_REPO_NAMES_FILE", str(names_file))
        ctx = _ctx(tmp_path, {})
        result = detect_b1(ctx)
        assert result.count == 1

    def test_loads_names_from_env_blob(self, tmp_path: Path, monkeypatch):
        (tmp_path / "doc.md").write_text("MyPrivateRepo\n", encoding="utf-8")
        _git_init(tmp_path)
        monkeypatch.setenv("CUSTODIAN_PRIVATE_REPO_NAMES", "MyPrivateRepo\nmyprivaterepo")
        ctx = _ctx(tmp_path, {})
        result = detect_b1(ctx)
        assert result.count == 1


class TestB1Build:
    def test_build_returns_p1(self):
        detectors = build_boundary_detectors()
        ids = {d.id for d in detectors}
        assert "B1" in ids
        assert "B2" in ids

    def test_p1_severity_is_medium(self):
        d = next(d for d in build_boundary_detectors() if d.id == "B1")
        assert d.severity == "medium"


class TestB2RequireSource:
    def test_b2_flags_missing_required_source(self, tmp_path: Path):
        _git_init(tmp_path)
        ctx = _ctx(tmp_path, {"privacy": {"require_boundary_artifact": True}})
        result = detect_b2(ctx)
        assert result.count == 1
        assert "require_boundary_artifact" in result.samples[0]

    def test_b2_passes_when_inline_names_present(self, tmp_path: Path):
        _git_init(tmp_path)
        ctx = _ctx(
            tmp_path,
            {"privacy": {"require_private_repo_name_source": True, "private_repo_names": ["MyPrivateRepo"]}},
        )
        result = detect_b2(ctx)
        assert result.count == 0

    def test_b2_passes_when_boundary_artifact_present(self, tmp_path: Path):
        artifact = tmp_path / "boundary.json"
        artifact.write_text(
            json.dumps({
                "source_graph_id": "PrivateManifest",
                "forbidden_names": ["MyPrivateRepo"],
                "allowed_aliases": [],
                "redacted_entities": [],
                "redaction_rules_applied": [],
            }),
            encoding="utf-8",
        )
        _git_init(tmp_path)
        ctx = _ctx(
            tmp_path,
            {"privacy": {"require_boundary_artifact": True, "boundary_artifact_file": str(artifact)}},
        )
        result = detect_b2(ctx)
        assert result.count == 0


class TestB1FallbackWithoutGit:
    def test_falls_back_to_walk_when_git_missing(self, tmp_path: Path, monkeypatch):
        # Simulate "git not installed" by making the binary lookup fail.
        import custodian.audit_kit.detectors.boundary as boundary_mod
        real_run = boundary_mod.subprocess.run

        def fake_run(*args, **kwargs):
            raise FileNotFoundError("git not installed")

        monkeypatch.setattr(boundary_mod.subprocess, "run", fake_run)
        (tmp_path / "doc.md").write_text("MyPrivateRepo\n", encoding="utf-8")
        ctx = _ctx(tmp_path, {"privacy": {"private_repo_names": ["MyPrivateRepo"]}})
        result = detect_b1(ctx)
        assert result.count == 1
        # Restore for any teardown that needs it (no-op on monkeypatch but defensive).
        monkeypatch.setattr(boundary_mod.subprocess, "run", real_run)


def test_default_excludes_custodian_config(tmp_path: Path):
    (tmp_path / ".custodian").mkdir()
    (tmp_path / ".custodian" / "config.yaml").write_text(
        "privacy:\n  private_repo_names:\n    - MyPrivateRepo\n",
        encoding="utf-8",
    )
    _git_init(tmp_path)
    ctx = _ctx(tmp_path, {"privacy": {"private_repo_names": ["MyPrivateRepo"]}})
    result = detect_b1(ctx)
    assert result.count == 0
