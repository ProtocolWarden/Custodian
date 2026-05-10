# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import textwrap
from pathlib import Path

from custodian.policy.architecture import run_architecture_policy
from custodian.core.finding import HIGH


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(content))


class TestRunArchitecturePolicy:
    def test_no_rules_returns_empty(self, tmp_path):
        assert run_architecture_policy(tmp_path, {}) == []

    def test_no_violations_returns_empty(self, tmp_path):
        _write(tmp_path / "src" / "domain" / "model.py",
               "from domain.service import Svc\n")
        config = {
            "policy": {"architecture": {"rules": [
                {"description": "domain must not import adapters",
                 "from_glob": "src/domain/**",
                 "forbid_import_prefix": ["adapters."]}
            ]}}
        }
        findings = run_architecture_policy(tmp_path, config)
        assert findings == []

    def test_detects_forbidden_import(self, tmp_path):
        _write(tmp_path / "src" / "domain" / "model.py",
               "from adapters.db import session\n")
        config = {
            "policy": {"architecture": {"rules": [
                {"description": "domain must not import adapters",
                 "from_glob": "src/domain/**",
                 "forbid_import_prefix": ["adapters."]}
            ]}}
        }
        findings = run_architecture_policy(tmp_path, config)
        assert len(findings) == 1
        f = findings[0]
        assert f.tool == "policy"
        assert f.rule == "ARCH_VIOLATION"
        assert f.severity == HIGH
        assert "adapters" in f.message

    def test_detects_bare_import(self, tmp_path):
        _write(tmp_path / "src" / "domain" / "x.py", "import adapters.db\n")
        config = {
            "policy": {"architecture": {"rules": [
                {"from_glob": "src/domain/**",
                 "forbid_import_prefix": ["adapters."]}
            ]}}
        }
        findings = run_architecture_policy(tmp_path, config)
        assert len(findings) == 1

    def test_file_outside_from_glob_not_checked(self, tmp_path):
        _write(tmp_path / "src" / "adapters" / "glue.py",
               "from adapters.db import session\n")
        config = {
            "policy": {"architecture": {"rules": [
                {"from_glob": "src/domain/**",
                 "forbid_import_prefix": ["adapters."]}
            ]}}
        }
        assert run_architecture_policy(tmp_path, config) == []

    def test_old_schema_architecture_key(self, tmp_path):
        _write(tmp_path / "src" / "domain" / "m.py",
               "from adapters.x import Y\n")
        config = {
            "architecture": {"rules": [
                {"from_glob": "src/domain/**",
                 "forbid_import_prefix": ["adapters."]}
            ]}
        }
        findings = run_architecture_policy(tmp_path, config)
        assert len(findings) == 1

    def test_syntax_error_file_skipped(self, tmp_path):
        f = tmp_path / "src" / "domain" / "broken.py"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("def (:\n")
        config = {
            "policy": {"architecture": {"rules": [
                {"from_glob": "src/domain/**",
                 "forbid_import_prefix": ["adapters."]}
            ]}}
        }
        findings = run_architecture_policy(tmp_path, config)
        assert findings == []

    def test_multiple_rules(self, tmp_path):
        _write(tmp_path / "src" / "domain" / "a.py", "from adapters.db import X\n")
        _write(tmp_path / "src" / "cli" / "b.py", "from domain.internal import Y\n")
        config = {
            "policy": {"architecture": {"rules": [
                {"from_glob": "src/domain/**", "forbid_import_prefix": ["adapters."]},
                {"from_glob": "src/cli/**", "forbid_import_prefix": ["domain.internal"]},
            ]}}
        }
        findings = run_architecture_policy(tmp_path, config)
        assert len(findings) == 2
