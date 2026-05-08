# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for S-class (structure) detectors: S1 and S2."""
from __future__ import annotations

from pathlib import Path


import ast
import textwrap

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.structure import detect_a1, detect_s1, detect_s2, detect_s3, detect_s4
from custodian.audit_kit.passes.ast_forest import AstForest
from custodian.audit_kit.passes.import_graph import ImportGraph


def _make_context(
    tmp_path: Path,
    config: dict | None = None,
    import_graph: ImportGraph | None = None,
) -> AuditContext:
    graph = AnalysisGraph(import_graph=import_graph)
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
        graph=graph,
    )


def _make_import_graph(
    imports: dict[str, list[str]],
    module_to_path: dict[str, str] | None = None,
    path_to_module: dict[str, str] | None = None,
) -> ImportGraph:
    g = ImportGraph()
    m2p = module_to_path or {}
    p2m = path_to_module or {}
    for src_rel, targets in imports.items():
        p = Path(src_rel)
        g.imports[p] = set(targets)
        mod = p2m.get(src_rel, src_rel.replace("/", ".").removesuffix(".py"))
        g.path_to_module[p] = mod
    for mod, rel in m2p.items():
        g.module_to_path[mod] = Path(rel)
    return g


# ── S1 tests ─────────────────────────────────────────────────────────────────

class TestS1:
    def test_no_graph_returns_zero(self, tmp_path):
        ctx = _make_context(tmp_path)
        ctx.graph = AnalysisGraph(import_graph=None)
        result = detect_s1(ctx)
        assert result.count == 0

    def test_no_rules_returns_zero(self, tmp_path):
        ig = _make_import_graph({"src/a.py": ["src.b"]})
        ctx = _make_context(tmp_path, config={}, import_graph=ig)
        result = detect_s1(ctx)
        assert result.count == 0

    def test_clean_imports_no_findings(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/adapters/a.py")] = {"src.domain.model"}
        ig.module_to_path["src.domain.model"] = Path("src/domain/model.py")
        config = {
            "architecture": {
                "layers": [
                    {"name": "adapters", "glob": "src/adapters/**",
                     "may_not_import": ["src/entrypoints/**"]},
                ]
            }
        }
        ctx = _make_context(tmp_path, config=config, import_graph=ig)
        result = detect_s1(ctx)
        assert result.count == 0

    def test_violation_detected(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/domain/model.py")] = {"src.adapters.db"}
        ig.module_to_path["src.adapters.db"] = Path("src/adapters/db.py")
        config = {
            "architecture": {
                "layers": [
                    {"name": "domain", "glob": "src/domain/**",
                     "may_not_import": ["src/adapters/**"]},
                ]
            }
        }
        ctx = _make_context(tmp_path, config=config, import_graph=ig)
        result = detect_s1(ctx)
        assert result.count == 1
        assert "domain" in result.samples[0]

    def test_external_import_not_flagged(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/domain/model.py")] = {"requests"}
        # requests not in module_to_path → external
        config = {
            "architecture": {
                "layers": [
                    {"name": "domain", "glob": "src/domain/**",
                     "may_not_import": ["src/adapters/**"]},
                ]
            }
        }
        ctx = _make_context(tmp_path, config=config, import_graph=ig)
        result = detect_s1(ctx)
        assert result.count == 0

    def test_multiple_violations_capped_at_max_samples(self, tmp_path):
        ig = ImportGraph()
        for i in range(12):
            ig.imports[Path(f"src/domain/m{i}.py")] = {f"src.adapters.db{i}"}
            ig.module_to_path[f"src.adapters.db{i}"] = Path(f"src/adapters/db{i}.py")
        config = {
            "architecture": {
                "layers": [
                    {"name": "domain", "glob": "src/domain/**",
                     "may_not_import": ["src/adapters/**"]},
                ]
            }
        }
        ctx = _make_context(tmp_path, config=config, import_graph=ig)
        result = detect_s1(ctx)
        assert result.count == 12
        assert len(result.samples) == 8  # _MAX_SAMPLES


# ── S2 tests ─────────────────────────────────────────────────────────────────

class TestS2:
    def test_no_graph_returns_zero(self, tmp_path):
        ctx = _make_context(tmp_path)
        ctx.graph = AnalysisGraph(import_graph=None)
        result = detect_s2(ctx)
        assert result.count == 0

    def test_no_mutual_imports_returns_zero(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/a.py")] = {"src.b"}
        ig.imports[Path("src/b.py")] = {"src.c"}
        ig.module_to_path["src.a"] = Path("src/a.py")
        ig.module_to_path["src.b"] = Path("src/b.py")
        ig.module_to_path["src.c"] = Path("src/c.py")
        ig.path_to_module[Path("src/a.py")] = "src.a"
        ig.path_to_module[Path("src/b.py")] = "src.b"
        ctx = _make_context(tmp_path, import_graph=ig)
        result = detect_s2(ctx)
        assert result.count == 0

    def test_mutual_import_detected(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/a.py")] = {"src.b"}
        ig.imports[Path("src/b.py")] = {"src.a"}
        ig.module_to_path["src.a"] = Path("src/a.py")
        ig.module_to_path["src.b"] = Path("src/b.py")
        ig.path_to_module[Path("src/a.py")] = "src.a"
        ig.path_to_module[Path("src/b.py")] = "src.b"
        ctx = _make_context(tmp_path, import_graph=ig)
        result = detect_s2(ctx)
        assert result.count == 1
        assert "↔" in result.samples[0]

    def test_mutual_pair_reported_once(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/a.py")] = {"src.b"}
        ig.imports[Path("src/b.py")] = {"src.a"}
        ig.module_to_path["src.a"] = Path("src/a.py")
        ig.module_to_path["src.b"] = Path("src/b.py")
        ig.path_to_module[Path("src/a.py")] = "src.a"
        ig.path_to_module[Path("src/b.py")] = "src.b"
        ctx = _make_context(tmp_path, import_graph=ig)
        result = detect_s2(ctx)
        assert result.count == 1  # not 2

    def test_three_way_cycle_not_reported_as_mutual(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/a.py")] = {"src.b"}
        ig.imports[Path("src/b.py")] = {"src.c"}
        ig.imports[Path("src/c.py")] = {"src.a"}
        ig.module_to_path["src.a"] = Path("src/a.py")
        ig.module_to_path["src.b"] = Path("src/b.py")
        ig.module_to_path["src.c"] = Path("src/c.py")
        ig.path_to_module[Path("src/a.py")] = "src.a"
        ig.path_to_module[Path("src/b.py")] = "src.b"
        ig.path_to_module[Path("src/c.py")] = "src.c"
        ctx = _make_context(tmp_path, import_graph=ig)
        result = detect_s2(ctx)
        assert result.count == 0  # three-way cycle, no direct mutual


# ── S3 tests ──────────────────────────────────────────────────────────────────

def _s3_context(tmp_path: Path, src_text: str) -> AuditContext:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    path = src_root / "module.py"
    src = textwrap.dedent(src_text)
    path.write_text(src, encoding="utf-8")
    tree = ast.parse(src)
    forest = AstForest()
    forest.trees[path] = tree
    forest.sources[path] = src
    graph = AnalysisGraph(ast_forest=forest)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=graph,
    )


class TestS3:
    def test_import_tests_package_flagged(self, tmp_path):
        ctx = _s3_context(tmp_path, "from tests.helpers import make_fixture\n")
        assert detect_s3(ctx).count == 1

    def test_import_test_module_flagged(self, tmp_path):
        ctx = _s3_context(tmp_path, "import test_utils\n")
        assert detect_s3(ctx).count == 1

    def test_import_test_underscore_module_flagged(self, tmp_path):
        ctx = _s3_context(tmp_path, "from test_helpers import something\n")
        assert detect_s3(ctx).count == 1

    def test_normal_import_not_flagged(self, tmp_path):
        ctx = _s3_context(tmp_path, "import os\nfrom pathlib import Path\n")
        assert detect_s3(ctx).count == 0

    def test_src_import_not_flagged(self, tmp_path):
        ctx = _s3_context(tmp_path, "from myapp.utils import helper\n")
        assert detect_s3(ctx).count == 0

    def test_no_graph_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path,
            src_root=tmp_path / "src",
            tests_root=tmp_path / "tests",
            config={},
            plugin_modules=[],
            graph=None,
        )
        assert detect_s3(ctx).count == 0


# ── A1 tests ──────────────────────────────────────────────────────────────────

class TestA1:
    def _ctx(self, src: str, tmp_path: Path, config: dict) -> AuditContext:
        src_root = tmp_path / "src"
        src_root.mkdir(parents=True, exist_ok=True)
        path = src_root / "myapp" / "domain" / "model.py"
        path.parent.mkdir(parents=True, exist_ok=True)
        src = textwrap.dedent(src)
        path.write_text(src, encoding="utf-8")
        tree = ast.parse(src)
        forest = AstForest()
        forest.trees[path] = tree
        forest.sources[path] = src
        return AuditContext(
            repo_root=tmp_path, src_root=src_root, tests_root=tmp_path / "tests",
            config=config, plugin_modules=[],
            graph=AnalysisGraph(ast_forest=forest),
        )

    def test_no_invariants_returns_zero(self, tmp_path):
        ctx = self._ctx("x = 1\n", tmp_path, config={})
        assert detect_a1(ctx).count == 0

    def test_max_lines_ok(self, tmp_path):
        ctx = self._ctx("x = 1\n", tmp_path, config={
            "architecture": {"invariants": [
                {"name": "small", "glob": "src/myapp/**/*.py", "max_lines": 100}
            ]}
        })
        assert detect_a1(ctx).count == 0

    def test_max_lines_violation(self, tmp_path):
        big_src = "\n".join(f"x{i} = {i}" for i in range(50))
        ctx = self._ctx(big_src, tmp_path, config={
            "architecture": {"invariants": [
                {"name": "tiny", "glob": "src/myapp/**/*.py", "max_lines": 10}
            ]}
        })
        assert detect_a1(ctx).count == 1

    def test_max_classes_violation(self, tmp_path):
        src = "\n".join(f"class C{i}: pass" for i in range(5))
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [
                {"name": "few classes", "glob": "src/myapp/**/*.py", "max_classes": 3}
            ]}
        })
        assert detect_a1(ctx).count == 1

    def test_glob_not_matching_no_violation(self, tmp_path):
        src = "\n".join(f"class C{i}: pass" for i in range(5))
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [
                {"name": "only adapters", "glob": "src/adapters/**/*.py", "max_classes": 1}
            ]}
        })
        assert detect_a1(ctx).count == 0

    # ── forbidden_import_prefix tests ────────────────────────────────────────

    def test_forbidden_import_prefix_direct_import(self, tmp_path):
        src = "import tools.audit.runner\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [
                {"name": "no tools.audit", "glob": "src/**/*.py", "forbidden_import_prefix": "tools.audit"}
            ]}
        })
        assert detect_a1(ctx).count == 1

    def test_forbidden_import_prefix_from_import(self, tmp_path):
        src = "from tools.audit import runner\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [
                {"name": "no tools.audit", "glob": "src/**/*.py", "forbidden_import_prefix": "tools.audit"}
            ]}
        })
        assert detect_a1(ctx).count == 1

    def test_forbidden_import_prefix_submodule(self, tmp_path):
        src = "from tools.audit.checks.imports import detect\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [
                {"name": "no tools.audit", "glob": "src/**/*.py", "forbidden_import_prefix": "tools.audit"}
            ]}
        })
        assert detect_a1(ctx).count == 1

    def test_forbidden_import_prefix_exact_match(self, tmp_path):
        # "import tools" is the parent package — must NOT match prefix "tools.audit"
        src = "import tools\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [
                {"name": "no tools.audit", "glob": "src/**/*.py", "forbidden_import_prefix": "tools.audit"}
            ]}
        })
        assert detect_a1(ctx).count == 0

    def test_forbidden_import_prefix_partial_name_no_match(self, tmp_path):
        # "tools.auditor" must not match prefix "tools.audit"
        src = "import tools.auditor\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [
                {"name": "no tools.audit", "glob": "src/**/*.py", "forbidden_import_prefix": "tools.audit"}
            ]}
        })
        assert detect_a1(ctx).count == 0

    def test_forbidden_import_prefix_glob_not_matching(self, tmp_path):
        src = "import tools.audit.runner\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [
                {"name": "no tools.audit", "glob": "src/other/**/*.py", "forbidden_import_prefix": "tools.audit"}
            ]}
        })
        assert detect_a1(ctx).count == 0

    def test_forbidden_import_prefix_clean_file(self, tmp_path):
        src = "import os\nfrom pathlib import Path\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [
                {"name": "no tools.audit", "glob": "src/**/*.py", "forbidden_import_prefix": "tools.audit"}
            ]}
        })
        assert detect_a1(ctx).count == 0

    def test_forbidden_import_prefix_relative_import_not_flagged(self, tmp_path):
        # "from .example_repo import X" is a relative import — must NOT match prefix "example_repo"
        src = "from .example_repo import ExampleRepoProfile\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [
                {"name": "no example_repo", "glob": "src/**/*.py", "forbidden_import_prefix": "example_repo"}
            ]}
        })
        assert detect_a1(ctx).count == 0

    # ── public_api_only tests ────────────────────────────────────────────────

    def _public_api_rule(self) -> dict:
        return {
            "name": "ER public API only",
            "glob": "src/**/*.py",
            "public_api_only": {
                "package": "executor_runtime",
                "allowed_paths": [
                    "executor_runtime",
                    "executor_runtime.runners",
                    "executor_runtime.contracts",
                ],
            },
        }

    def test_public_api_only_top_level_import_allowed(self, tmp_path):
        src = "from executor_runtime import ExecutorRuntime\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [self._public_api_rule()]}
        })
        assert detect_a1(ctx).count == 0

    def test_public_api_only_runners_subpackage_allowed(self, tmp_path):
        src = "from executor_runtime.runners import HttpRunner\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [self._public_api_rule()]}
        })
        assert detect_a1(ctx).count == 0

    def test_public_api_only_contracts_subpackage_allowed(self, tmp_path):
        src = "from executor_runtime.contracts import RuntimeInvocation\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [self._public_api_rule()]}
        })
        assert detect_a1(ctx).count == 0

    def test_public_api_only_deep_module_import_flagged(self, tmp_path):
        # Bypassing the runners __init__ — reaches into a private module
        src = "from executor_runtime.runners.subprocess_runner import _run_with_process_group\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [self._public_api_rule()]}
        })
        result = detect_a1(ctx)
        assert result.count == 1
        assert "deep import" in result.samples[0]
        assert "executor_runtime.runners.subprocess_runner" in result.samples[0]

    def test_public_api_only_direct_module_import_flagged(self, tmp_path):
        # `import executor_runtime.runtime` (the bare module path) bypasses the public API
        src = "import executor_runtime.runtime\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [self._public_api_rule()]}
        })
        assert detect_a1(ctx).count == 1

    def test_public_api_only_unrelated_package_not_flagged(self, tmp_path):
        # Imports from a different package should be ignored
        src = "from rxp.contracts import RuntimeInvocation\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [self._public_api_rule()]}
        })
        assert detect_a1(ctx).count == 0

    def test_public_api_only_no_config_no_findings(self, tmp_path):
        # If allowed_paths is empty/missing, the rule does nothing (safe default)
        src = "from executor_runtime.runners.subprocess_runner import _x\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [{
                "name": "broken rule",
                "glob": "src/**/*.py",
                "public_api_only": {"package": "executor_runtime"},
            }]}
        })
        assert detect_a1(ctx).count == 0

    def test_public_api_only_relative_import_not_flagged(self, tmp_path):
        # Relative imports never match — they don't reach external packages
        src = "from .executor_runtime import x\n"
        ctx = self._ctx(src, tmp_path, config={
            "architecture": {"invariants": [self._public_api_rule()]}
        })
        assert detect_a1(ctx).count == 0


class TestDetectS4:
    def _ctx(self, tmp_path: Path, tests_root=None) -> AuditContext:
        graph = AnalysisGraph()
        return AuditContext(
            repo_root=tmp_path,
            src_root=tmp_path / "src",
            tests_root=tests_root or tmp_path / "tests",
            config={},
            plugin_modules=[],
            graph=graph,
        )

    def test_no_tests_dir_returns_zero(self, tmp_path):
        ctx = self._ctx(tmp_path, tests_root=tmp_path / "nonexistent")
        assert detect_s4(ctx).count == 0

    def test_missing_conftest_returns_one(self, tmp_path):
        tests = tmp_path / "tests"
        tests.mkdir()
        ctx = self._ctx(tmp_path)
        result = detect_s4(ctx)
        assert result.count == 1
        assert "missing" in result.samples[0].lower() or "conftest" in result.samples[0].lower()

    def test_conftest_with_sys_prefix_guard_passes(self, tmp_path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "conftest.py").write_text(
            "import sys\n_ACTIVE_PREFIX = sys.prefix\n_EXPECTED_VENV = '.venv'\n"
            "if _ACTIVE_PREFIX != _EXPECTED_VENV: raise SystemExit('wrong env')\n"
        )
        ctx = self._ctx(tmp_path)
        assert detect_s4(ctx).count == 0

    def test_conftest_with_expected_venv_marker_passes(self, tmp_path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "conftest.py").write_text("_EXPECTED_VENV = '.venv'\n")
        ctx = self._ctx(tmp_path)
        assert detect_s4(ctx).count == 0

    def test_conftest_without_guard_returns_one(self, tmp_path):
        tests = tmp_path / "tests"
        tests.mkdir()
        (tests / "conftest.py").write_text("import pytest\n# just fixtures\n")
        ctx = self._ctx(tmp_path)
        result = detect_s4(ctx)
        assert result.count == 1
        assert "venv" in result.samples[0].lower() or "guard" in result.samples[0].lower()
