# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for new detectors: A1 class_field_count, A2 (directory structure), H1 (hex arch)."""
from __future__ import annotations

from pathlib import Path
import textwrap

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.directory import detect_d1
from custodian.audit_kit.detectors.structure import detect_a1, detect_h1
from custodian.audit_kit.passes.ast_forest import AstForest
from custodian.audit_kit.passes.import_graph import ImportGraph


# ── helpers ──────────────────────────────────────────────────────────────────

def _make_ast_context(tmp_path: Path, src_files: dict[str, str], config: dict) -> AuditContext:
    import ast as _ast
    forest = AstForest()
    for rel, content in src_files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        text = textwrap.dedent(content)
        p.write_text(text, encoding="utf-8")
        forest.trees[p] = _ast.parse(text)
        forest.sources[p] = text
    graph = AnalysisGraph(ast_forest=forest)
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config=config,
        plugin_modules=[],
        graph=graph,
    )


def _make_import_context(
    tmp_path: Path,
    imports: dict[str, list[str]],
    module_to_path: dict[str, str],
    config: dict,
) -> AuditContext:
    ig = ImportGraph()
    for src_rel, targets in imports.items():
        p = Path(src_rel)
        ig.imports[p] = set(targets)
        ig.path_to_module[p] = src_rel.replace("/", ".").removesuffix(".py")
    for mod, rel in module_to_path.items():
        ig.module_to_path[mod] = Path(rel)
    graph = AnalysisGraph(import_graph=ig)
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config=config,
        plugin_modules=[],
        graph=graph,
    )


def _make_dir_context(tmp_path: Path, config: dict) -> AuditContext:
    graph = AnalysisGraph()
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config=config,
        plugin_modules=[],
        graph=graph,
    )


# ── A1 class_field_count ─────────────────────────────────────────────────────

class TestA1ClassFieldCount:
    _config = {
        "architecture": {
            "invariants": [
                {
                    "name": "BigClass guard",
                    "glob": "src/**/*.py",
                    "class_field_count": {"class_name": "BigClass", "max_fields": 3},
                }
            ]
        }
    }

    def test_class_under_limit_no_finding(self, tmp_path):
        src = {
            "src/domain/model.py": """
                class BigClass:
                    x: int
                    y: str
            """
        }
        ctx = _make_ast_context(tmp_path, src, self._config)
        result = detect_a1(ctx)
        assert result.count == 0

    def test_class_over_limit_flagged(self, tmp_path):
        src = {
            "src/domain/model.py": """
                class BigClass:
                    a: int
                    b: str
                    c: float
                    d: bytes
            """
        }
        ctx = _make_ast_context(tmp_path, src, self._config)
        result = detect_a1(ctx)
        assert result.count == 1
        assert "BigClass" in result.samples[0]
        assert "4 declared fields" in result.samples[0]

    def test_other_class_not_flagged(self, tmp_path):
        src = {
            "src/domain/model.py": """
                class OtherClass:
                    a: int
                    b: str
                    c: float
                    d: bytes
            """
        }
        ctx = _make_ast_context(tmp_path, src, self._config)
        result = detect_a1(ctx)
        assert result.count == 0

    def test_excluded_path_skipped(self, tmp_path):
        src = {
            "src/infra/model.py": """
                class BigClass:
                    a: int
                    b: str
                    c: float
                    d: bytes
            """
        }
        config = {
            "audit": {"exclude_paths": {"A1": ["src/infra/**"]}},
            "architecture": {
                "invariants": [
                    {
                        "name": "BigClass guard",
                        "glob": "src/**/*.py",
                        "class_field_count": {"class_name": "BigClass", "max_fields": 3},
                    }
                ]
            },
        }
        ctx = _make_ast_context(tmp_path, src, config)
        result = detect_a1(ctx)
        assert result.count == 0

    def test_init_var_not_counted(self, tmp_path):
        src = {
            "src/domain/model.py": """
                from dataclasses import InitVar
                class BigClass:
                    a: int
                    b: str
                    c: float
                    _extra: InitVar[int]
            """
        }
        ctx = _make_ast_context(tmp_path, src, self._config)
        # 3 real fields + 1 InitVar → 3 counted → at limit, not over
        result = detect_a1(ctx)
        assert result.count == 0


# ── A2 directory structure ────────────────────────────────────────────────────

class TestA2DirectoryStructure:
    def _config(self, required_dirs=None, required_files=None, exclude=None):
        rule = {
            "name": "capability shape",
            "glob": "src/capabilities/*",
        }
        if required_dirs:
            rule["required_dirs"] = required_dirs
        if required_files:
            rule["required_files"] = required_files
        if exclude:
            rule["exclude"] = exclude
        return {"architecture": {"directory_structure": [rule]}}

    def test_no_rules_returns_zero(self, tmp_path):
        ctx = _make_dir_context(tmp_path, {})
        result = detect_d1(ctx)
        assert result.count == 0

    def test_complete_capability_no_finding(self, tmp_path):
        cap = tmp_path / "src" / "capabilities" / "feature"
        for d in ["domain", "ports", "application"]:
            (cap / d).mkdir(parents=True, exist_ok=True)
        ctx = _make_dir_context(tmp_path, self._config(required_dirs=["domain", "ports", "application"]))
        result = detect_d1(ctx)
        assert result.count == 0

    def test_missing_dir_flagged(self, tmp_path):
        cap = tmp_path / "src" / "capabilities" / "feature"
        (cap / "domain").mkdir(parents=True, exist_ok=True)
        # Missing ports and application
        ctx = _make_dir_context(tmp_path, self._config(required_dirs=["domain", "ports", "application"]))
        result = detect_d1(ctx)
        assert result.count == 2
        missing = {s.split("missing dir:")[1].split(" ")[0] for s in result.samples}
        assert missing == {"ports", "application"}

    def test_missing_file_flagged(self, tmp_path):
        cap = tmp_path / "src" / "capabilities" / "feature"
        cap.mkdir(parents=True, exist_ok=True)
        (cap / "domain.py").write_text("", encoding="utf-8")
        ctx = _make_dir_context(tmp_path, self._config(required_files=["domain.py", "ports.py"]))
        result = detect_d1(ctx)
        assert result.count == 1
        assert "ports.py" in result.samples[0]

    def test_excluded_dir_skipped(self, tmp_path):
        cap = tmp_path / "src" / "capabilities" / "shared"
        cap.mkdir(parents=True, exist_ok=True)
        ctx = _make_dir_context(
            tmp_path,
            self._config(
                required_dirs=["domain"],
                exclude=["src/capabilities/shared"],
            ),
        )
        result = detect_d1(ctx)
        assert result.count == 0

    def test_nested_dirs_not_matched(self, tmp_path):
        # src/capabilities/feature/domain/ should NOT be checked — glob is one level deep
        cap = tmp_path / "src" / "capabilities" / "feature"
        (cap / "domain").mkdir(parents=True, exist_ok=True)
        ctx = _make_dir_context(tmp_path, self._config(required_dirs=["domain", "ports"]))
        result = detect_d1(ctx)
        # Only 'feature' matches — it's missing 'ports'
        assert result.count == 1
        assert "src/capabilities/feature" in result.samples[0]

    def test_pycache_skipped(self, tmp_path):
        # __pycache__ under capabilities should not be treated as a capability dir
        pycache = tmp_path / "src" / "capabilities" / "__pycache__"
        pycache.mkdir(parents=True, exist_ok=True)
        ctx = _make_dir_context(tmp_path, self._config(required_dirs=["domain"]))
        result = detect_d1(ctx)
        assert result.count == 0


# ── H1 hexagonal architecture ─────────────────────────────────────────────────

class TestH1HexArch:
    def _hex_config(self, layers: list[dict]) -> dict:
        return {"architecture": {"hex": layers}}

    def test_no_layers_returns_zero(self, tmp_path):
        ctx = _make_import_context(tmp_path, {}, {}, {})
        result = detect_h1(ctx)
        assert result.count == 0

    def test_no_graph_returns_zero(self, tmp_path):
        config = self._hex_config([
            {"name": "domain", "glob": "src/domain/**"},
        ])
        graph = AnalysisGraph(import_graph=None)
        ctx = AuditContext(
            repo_root=tmp_path, src_root=tmp_path / "src", tests_root=tmp_path / "tests",
            config=config, plugin_modules=[], graph=graph,
        )
        result = detect_h1(ctx)
        assert result.count == 0

    def test_valid_dependency_no_finding(self, tmp_path):
        # application → domain is allowed (higher index importing from lower index)
        config = self._hex_config([
            {"name": "domain", "glob": "src/domain/**"},
            {"name": "application", "glob": "src/application/**"},
            {"name": "infrastructure", "glob": "src/infrastructure/**"},
        ])
        ctx = _make_import_context(
            tmp_path,
            imports={"src/application/service.py": ["myapp.domain.model"]},
            module_to_path={"myapp.domain.model": "src/domain/model.py"},
            config=config,
        )
        result = detect_h1(ctx)
        assert result.count == 0

    def test_domain_importing_infra_flagged(self, tmp_path):
        # domain → infrastructure is a violation (domain is lower, infra is higher index)
        config = self._hex_config([
            {"name": "domain", "glob": "src/domain/**"},
            {"name": "application", "glob": "src/application/**"},
            {"name": "infrastructure", "glob": "src/infrastructure/**"},
        ])
        ctx = _make_import_context(
            tmp_path,
            imports={"src/domain/model.py": ["myapp.infrastructure.db"]},
            module_to_path={"myapp.infrastructure.db": "src/infrastructure/db.py"},
            config=config,
        )
        result = detect_h1(ctx)
        assert result.count == 1
        assert "domain→infrastructure" in result.samples[0]

    def test_same_layer_not_flagged(self, tmp_path):
        # domain → domain is fine
        config = self._hex_config([
            {"name": "domain", "glob": "src/domain/**"},
            {"name": "application", "glob": "src/application/**"},
        ])
        ctx = _make_import_context(
            tmp_path,
            imports={"src/domain/service.py": ["myapp.domain.model"]},
            module_to_path={"myapp.domain.model": "src/domain/model.py"},
            config=config,
        )
        result = detect_h1(ctx)
        assert result.count == 0

    def test_external_imports_ignored(self, tmp_path):
        # stdlib/third-party imports not in module_to_path are ignored
        config = self._hex_config([
            {"name": "domain", "glob": "src/domain/**"},
            {"name": "infrastructure", "glob": "src/infrastructure/**"},
        ])
        ctx = _make_import_context(
            tmp_path,
            imports={"src/domain/model.py": ["os", "dataclasses", "pydantic"]},
            module_to_path={},
            config=config,
        )
        result = detect_h1(ctx)
        assert result.count == 0

    def test_multiple_violations_counted(self, tmp_path):
        config = self._hex_config([
            {"name": "domain", "glob": "src/domain/**"},
            {"name": "application", "glob": "src/application/**"},
            {"name": "infrastructure", "glob": "src/infrastructure/**"},
        ])
        ctx = _make_import_context(
            tmp_path,
            imports={
                "src/domain/a.py": ["myapp.infrastructure.db"],
                "src/domain/b.py": ["myapp.application.svc"],
            },
            module_to_path={
                "myapp.infrastructure.db": "src/infrastructure/db.py",
                "myapp.application.svc": "src/application/svc.py",
            },
            config=config,
        )
        result = detect_h1(ctx)
        assert result.count == 2
