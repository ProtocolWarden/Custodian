# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for X1/X2/X3 — cross-repo detectors."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.cross_repo import detect_x1, detect_x2, detect_x3


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_PM_YAML = textwrap.dedent("""\
    manifest_kind: platform
    manifest_version: "1.0.0"
    repos:
      operations_center:
        canonical_name: OperationsCenter
        public_label: OperationsCenterPublic
        github_url: https://github.com/ProtocolWarden/OperationsCenter
      operator_console:
        canonical_name: OperatorConsole
        public_label: OperatorConsolePublic
        github_url: https://github.com/ProtocolWarden/OperatorConsole
      cxrp:
        canonical_name: CxRP
        public_label: CxRPContracts
        github_url: https://github.com/ProtocolWarden/CxRP
      switchboard:
        canonical_name: SwitchBoard
        
        github_url: https://github.com/ProtocolWarden/SwitchBoard
    edges:
      - {from: OperatorConsole, to: OperationsCenter, type: dispatches_to}
      - {from: OperationsCenter, to: CxRP, type: depends_on_contracts_from}
      - {from: OperatorConsole, to: CxRP, type: depends_on_contracts_from}
""")

_CROSS_REPO_CFG = {"audit": {"cross_repo": {"platform_manifest_repo": "PlatformManifest"}}}


def _write_pm(tmp_path: Path) -> Path:
    pm_dir = tmp_path / "PlatformManifest" / "src" / "platform_manifest" / "data"
    pm_dir.mkdir(parents=True)
    pm_path = pm_dir / "platform_manifest.yaml"
    pm_path.write_text(_PM_YAML)
    return pm_path


def _ctx(
    tmp_path: Path,
    src_files: dict[str, str],
    *,
    config: dict | None = None,
    repo_key: str | None = None,
    md_files: dict[str, str] | None = None,
) -> AuditContext:
    src_dir = tmp_path / "src"
    src_dir.mkdir(exist_ok=True)
    for relpath, body in src_files.items():
        p = src_dir / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    if md_files:
        for relpath, body in md_files.items():
            p = tmp_path / relpath
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
    cfg = config or {}
    if repo_key:
        cfg = {**cfg, "repo_key": repo_key}
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_dir,
        tests_root=tmp_path / "tests",
        config=cfg,
        graph=None,
        plugin_modules=[],
    )


# ---------------------------------------------------------------------------
# X1 — public-label drift
# ---------------------------------------------------------------------------

class TestX1:
    def test_silent_when_no_manifest_configured(self, tmp_path):
        ctx = _ctx(tmp_path, {"a.py": "x = 1"})
        assert detect_x1(ctx).count == 0

    def test_silent_when_manifest_path_missing(self, tmp_path):
        ctx = _ctx(tmp_path, {"a.py": "x = 1"}, config={
            "audit": {"cross_repo": {"platform_manifest_path": "missing.yaml"}},
        })
        assert detect_x1(ctx).count == 0

    def test_public_label_in_python_caught(self, tmp_path):
        _write_pm(tmp_path)
        ctx = _ctx(
            tmp_path,
            {"a.py": "OperationsCenterPublic = 'stale label'\n"},
            config=_CROSS_REPO_CFG,
        )
        result = detect_x1(ctx)
        assert result.count == 1
        assert "OperationsCenterPublic" in result.samples[0]
        assert "OperationsCenter" in result.samples[0]

    def test_public_label_in_markdown_caught(self, tmp_path):
        _write_pm(tmp_path)
        (tmp_path / "README.md").write_text("OperatorConsolePublic launches the watcher.\n")
        ctx = _ctx(tmp_path, {}, config=_CROSS_REPO_CFG)
        result = detect_x1(ctx)
        assert result.count == 1
        assert "OperatorConsolePublic" in result.samples[0]
        assert "OperatorConsole" in result.samples[0]

    def test_public_label_in_yaml_caught(self, tmp_path):
        _write_pm(tmp_path)
        (tmp_path / "config.yaml").write_text("target: OperationsCenterPublic\n")
        ctx = _ctx(tmp_path, {}, config=_CROSS_REPO_CFG)
        result = detect_x1(ctx)
        assert result.count == 1
        assert "OperationsCenterPublic" in result.samples[0]

    def test_public_label_in_yml_caught(self, tmp_path):
        _write_pm(tmp_path)
        (tmp_path / "deploy.yml").write_text("service: OperatorConsolePublic\n")
        ctx = _ctx(tmp_path, {}, config=_CROSS_REPO_CFG)
        result = detect_x1(ctx)
        assert result.count == 1
        assert "OperatorConsolePublic" in result.samples[0]

    def test_yaml_in_venv_skipped(self, tmp_path):
        _write_pm(tmp_path)
        venv_dir = tmp_path / ".venv" / "lib"
        venv_dir.mkdir(parents=True)
        (venv_dir / "pkg.yaml").write_text("name: ControlPlane\n")
        ctx = _ctx(tmp_path, {}, config=_CROSS_REPO_CFG)
        assert detect_x1(ctx).count == 0

    def test_canonical_name_not_flagged(self, tmp_path):
        _write_pm(tmp_path)
        ctx = _ctx(
            tmp_path,
            {"a.py": "import OperationsCenter\n"},
            config=_CROSS_REPO_CFG,
        )
        assert detect_x1(ctx).count == 0

    def test_history_paths_skipped(self, tmp_path):
        _write_pm(tmp_path)
        history_dir = tmp_path / "docs" / "history"
        history_dir.mkdir(parents=True)
        # Explicit encoding: the arrow is not cp1252-encodable, so the default
        # locale encoding raises UnicodeEncodeError on Windows.
        (history_dir / "rename.md").write_text(
            "FOB → OperatorConsole rename\n", encoding="utf-8",
        )
        ctx = _ctx(tmp_path, {}, config=_CROSS_REPO_CFG)
        assert detect_x1(ctx).count == 0

    def test_exclude_paths_honoured(self, tmp_path):
        _write_pm(tmp_path)
        ctx = _ctx(
            tmp_path,
            {"a.py": "ControlPlane = 1\n"},
            config={
                "audit": {
                    "cross_repo": {"platform_manifest_repo": "PlatformManifest"},
                    "exclude_paths": {"X1": ["src/a.py"]},
                },
            },
        )
        assert detect_x1(ctx).count == 0


# ---------------------------------------------------------------------------
# X2 — undeclared cross-repo imports
# ---------------------------------------------------------------------------

class TestX2:
    def test_silent_when_no_manifest(self, tmp_path):
        ctx = _ctx(tmp_path, {"a.py": "import cxrp\n"}, repo_key="OperatorConsole")
        assert detect_x2(ctx).count == 0

    def test_silent_when_no_repo_key(self, tmp_path):
        _write_pm(tmp_path)
        ctx = _ctx(
            tmp_path,
            {"a.py": "import cxrp\n"},
            config=_CROSS_REPO_CFG,
        )
        assert detect_x2(ctx).count == 0

    def test_declared_edge_not_flagged(self, tmp_path):
        _write_pm(tmp_path)
        # OperationsCenter → CxRP edge exists
        ctx = _ctx(
            tmp_path,
            {"a.py": "from cxrp.contracts import Foo\n"},
            config=_CROSS_REPO_CFG,
            repo_key="OperationsCenter",
        )
        assert detect_x2(ctx).count == 0

    def test_undeclared_import_caught(self, tmp_path):
        _write_pm(tmp_path)
        # SwitchBoard has no edge to CxRP in the test manifest
        ctx = _ctx(
            tmp_path,
            {"a.py": "from cxrp.contracts import Foo\n"},
            config=_CROSS_REPO_CFG,
            repo_key="SwitchBoard",
        )
        result = detect_x2(ctx)
        assert result.count == 1
        assert "cxrp" in result.samples[0]
        assert "CxRP" in result.samples[0]
        assert "SwitchBoard" in result.samples[0]

    def test_multiple_undeclared_imports_deduplicated_per_file(self, tmp_path):
        _write_pm(tmp_path)
        src = "from cxrp.a import A\nfrom cxrp.b import B\n"
        ctx = _ctx(
            tmp_path,
            {"a.py": src},
            config=_CROSS_REPO_CFG,
            repo_key="SwitchBoard",
        )
        # Two imports of cxrp from same file → deduplicated to 1 (same file+target)
        result = detect_x2(ctx)
        assert result.count == 1

    def test_self_import_not_flagged(self, tmp_path):
        _write_pm(tmp_path)
        # switchboard importing its own package
        ctx = _ctx(
            tmp_path,
            {"a.py": "from switchboard.core import Foo\n"},
            config=_CROSS_REPO_CFG,
            repo_key="SwitchBoard",
        )
        assert detect_x2(ctx).count == 0

    def test_non_platform_import_not_flagged(self, tmp_path):
        _write_pm(tmp_path)
        ctx = _ctx(
            tmp_path,
            {"a.py": "import requests\nfrom pathlib import Path\n"},
            config=_CROSS_REPO_CFG,
            repo_key="SwitchBoard",
        )
        assert detect_x2(ctx).count == 0

    def test_exclude_paths_honoured(self, tmp_path):
        _write_pm(tmp_path)
        ctx = _ctx(
            tmp_path,
            {"a.py": "from cxrp.contracts import Foo\n"},
            config={
                "audit": {
                    "cross_repo": {"platform_manifest_repo": "PlatformManifest"},
                    "exclude_paths": {"X2": ["src/a.py"]},
                },
            },
            repo_key="SwitchBoard",
        )
        assert detect_x2(ctx).count == 0

    def test_import_style_both_forms(self, tmp_path):
        _write_pm(tmp_path)
        # bare `import cxrp` form
        ctx = _ctx(
            tmp_path,
            {"a.py": "import cxrp\n"},
            config=_CROSS_REPO_CFG,
            repo_key="SwitchBoard",
        )
        result = detect_x2(ctx)
        assert result.count == 1
        assert "cxrp" in result.samples[0]


# ---------------------------------------------------------------------------
# X3 — stale GitHub URLs
# ---------------------------------------------------------------------------

class TestX3:
    def test_silent_when_no_manifest(self, tmp_path):
        (tmp_path / "README.md").write_text("See https://github.com/ProtocolWarden/ControlPlane\n")
        ctx = _ctx(tmp_path, {})
        assert detect_x3(ctx).count == 0

    def test_stale_url_in_markdown_caught(self, tmp_path):
        _write_pm(tmp_path)
        (tmp_path / "README.md").write_text(
            "See https://github.com/ProtocolWarden/OperationsCenterPublic for details.\n"
        )
        ctx = _ctx(tmp_path, {}, config=_CROSS_REPO_CFG)
        result = detect_x3(ctx)
        assert result.count == 1
        assert "OperationsCenterPublic" in result.samples[0]
        assert "OperationsCenter" in result.samples[0]

    def test_canonical_url_not_flagged(self, tmp_path):
        _write_pm(tmp_path)
        (tmp_path / "README.md").write_text(
            "See https://github.com/ProtocolWarden/OperationsCenter\n"
        )
        ctx = _ctx(tmp_path, {}, config=_CROSS_REPO_CFG)
        assert detect_x3(ctx).count == 0

    def test_multiple_stale_urls(self, tmp_path):
        _write_pm(tmp_path)
        (tmp_path / "README.md").write_text(
            "- https://github.com/ProtocolWarden/OperationsCenterPublic\n"
            "- https://github.com/ProtocolWarden/OperatorConsolePublic\n"
        )
        ctx = _ctx(tmp_path, {}, config=_CROSS_REPO_CFG)
        result = detect_x3(ctx)
        assert result.count == 2

    def test_stale_url_without_https_caught(self, tmp_path):
        _write_pm(tmp_path)
        (tmp_path / "README.md").write_text(
            "See github.com/ProtocolWarden/OperationsCenterPublic\n"
        )
        ctx = _ctx(tmp_path, {}, config=_CROSS_REPO_CFG)
        result = detect_x3(ctx)
        assert result.count == 1
        assert "OperationsCenterPublic" in result.samples[0]

    def test_no_stale_urls_when_empty_public_labels(self, tmp_path):
        # SwitchBoard has no public labels → no stale URLs possible
        _write_pm(tmp_path)
        (tmp_path / "README.md").write_text(
            "See https://github.com/ProtocolWarden/SwitchBoard\n"
        )
        ctx = _ctx(tmp_path, {}, config=_CROSS_REPO_CFG)
        assert detect_x3(ctx).count == 0

    def test_python_files_not_scanned_for_x3(self, tmp_path):
        _write_pm(tmp_path)
        ctx = _ctx(
            tmp_path,
            {"a.py": "url = 'https://github.com/ProtocolWarden/ControlPlane'\n"},
            config=_CROSS_REPO_CFG,
        )
        # X3 only scans .md files
        assert detect_x3(ctx).count == 0

    def test_history_paths_skipped(self, tmp_path):
        _write_pm(tmp_path)
        history_dir = tmp_path / "docs" / "history"
        history_dir.mkdir(parents=True)
        (history_dir / "notes.md").write_text(
            "Formerly github.com/ProtocolWarden/ControlPlane\n"
        )
        ctx = _ctx(tmp_path, {}, config=_CROSS_REPO_CFG)
        assert detect_x3(ctx).count == 0

    def test_exclude_paths_honoured(self, tmp_path):
        _write_pm(tmp_path)
        (tmp_path / "README.md").write_text(
            "See https://github.com/ProtocolWarden/ControlPlane\n"
        )
        ctx = _ctx(tmp_path, {}, config={
            "audit": {
                "cross_repo": {"platform_manifest_repo": "PlatformManifest"},
                "exclude_paths": {"X3": ["README.md"]},
            },
        })
        assert detect_x3(ctx).count == 0
