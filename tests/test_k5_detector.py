# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for K5 — broken relative documentation links."""
from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.docs import build_docs_detectors, detect_k5


def _ctx(tmp_path: Path, audit: dict | None = None) -> AuditContext:
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config={"repo_key": "MyRepo", "audit": audit or {}},
        plugin_modules=[],
    )


def _doc(tmp_path: Path, rel: str, body: str) -> Path:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")
    return p


class TestRegistration:
    def test_k5_is_registered_with_the_k_family(self):
        ds = build_docs_detectors()
        assert [d.id for d in ds] == ["K1", "K2", "K3", "K4", "K5"]

    def test_k5_matches_family_severity_and_needs_no_graph(self):
        k5 = next(d for d in build_docs_detectors() if d.id == "K5")
        assert k5.severity == "low"
        assert k5.needs == frozenset()
        assert k5.source == "builtin"


class TestResolves:
    def test_existing_sibling_is_clean(self, tmp_path):
        _doc(tmp_path, "docs/target.md", "# Target\n")
        _doc(tmp_path, "docs/a.md", "See [target](target.md).\n")
        assert detect_k5(_ctx(tmp_path)).count == 0

    def test_existing_parent_relative_is_clean(self, tmp_path):
        _doc(tmp_path, "docs/target.md", "# Target\n")
        _doc(tmp_path, "docs/sub/a.md", "See [t](../target.md).\n")
        assert detect_k5(_ctx(tmp_path)).count == 0

    def test_directory_target_is_clean(self, tmp_path):
        _doc(tmp_path, "docs/adr/0001.md", "# ADR\n")
        _doc(tmp_path, "docs/a.md", "See [adrs](adr/).\n")
        assert detect_k5(_ctx(tmp_path)).count == 0

    def test_non_markdown_target_is_checked_too(self, tmp_path):
        """A .md-only check misses exactly the bug this was written for."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "real.py").write_text("x = 1\n", encoding="utf-8")
        _doc(tmp_path, "docs/a.md", "See [code](../src/real.py).\n")
        assert detect_k5(_ctx(tmp_path)).count == 0

        _doc(tmp_path, "docs/b.md", "See [gone](../src/missing.py).\n")
        res = detect_k5(_ctx(tmp_path))
        assert res.count == 1
        assert "missing.py" in res.samples[0]

    def test_anchor_on_existing_file_is_clean(self, tmp_path):
        _doc(tmp_path, "docs/target.md", "# Target\n")
        _doc(tmp_path, "docs/a.md", "See [t](target.md#section).\n")
        assert detect_k5(_ctx(tmp_path)).count == 0

    def test_percent_encoded_space_resolves(self, tmp_path):
        _doc(tmp_path, "docs/my target.md", "# T\n")
        _doc(tmp_path, "docs/a.md", "See [t](my%20target.md).\n")
        assert detect_k5(_ctx(tmp_path)).count == 0


class TestFlags:
    def test_missing_target_is_flagged(self, tmp_path):
        _doc(tmp_path, "docs/a.md", "See [gone](nope.md).\n")
        res = detect_k5(_ctx(tmp_path))
        assert res.count == 1
        assert "docs/a.md:1" in res.samples[0]
        assert "nope.md" in res.samples[0]

    def test_reference_style_definition_is_checked(self, tmp_path):
        _doc(tmp_path, "docs/a.md", "Text [ref].\n\n[ref]: nope.md\n")
        assert detect_k5(_ctx(tmp_path)).count == 1

    def test_readme_at_repo_root_is_scanned(self, tmp_path):
        _doc(tmp_path, "README.md", "See [x](docs/nope.md).\n")
        assert detect_k5(_ctx(tmp_path)).count == 1

    def test_counts_every_occurrence(self, tmp_path):
        _doc(tmp_path, "docs/a.md", "[a](x.md) [b](y.md)\n[c](z.md)\n")
        assert detect_k5(_ctx(tmp_path)).count == 3


class TestDeliberatelyNotFlagged:
    def test_external_urls_ignored(self, tmp_path):
        _doc(
            tmp_path,
            "docs/a.md",
            "[h](https://example.com/x.md) [m](mailto:a@b.c) [f](ftp://h/x.md)\n",
        )
        assert detect_k5(_ctx(tmp_path)).count == 0

    def test_pure_anchor_ignored(self, tmp_path):
        _doc(tmp_path, "docs/a.md", "See [top](#overview).\n")
        assert detect_k5(_ctx(tmp_path)).count == 0

    def test_template_placeholder_ignored(self, tmp_path):
        """`<repo_id>_contract.md` is illustrative, not a link."""
        _doc(tmp_path, "docs/a.md", "See [c](<repo_id>_managed_repo_contract.md).\n")
        assert detect_k5(_ctx(tmp_path)).count == 0

    def test_target_outside_repo_ignored(self, tmp_path):
        """Sibling-checkout links are unverifiable in CI — must not fire."""
        _doc(tmp_path, "docs/a.md", "See [x](../../OtherRepo/docs/thing.md).\n")
        assert detect_k5(_ctx(tmp_path)).count == 0

    def test_history_dir_is_skipped(self, tmp_path):
        """history/ is a graveyard: not maintained, links rot by design."""
        _doc(tmp_path, "docs/history/old.md", "See [gone](nope.md).\n")
        assert detect_k5(_ctx(tmp_path)).count == 0

    def test_changelog_is_skipped(self, tmp_path):
        _doc(tmp_path, "docs/CHANGELOG.md", "See [gone](nope.md).\n")
        assert detect_k5(_ctx(tmp_path)).count == 0


class TestConfig:
    def test_exclude_paths_k5_suppresses(self, tmp_path):
        _doc(tmp_path, "docs/a.md", "See [gone](nope.md).\n")
        assert detect_k5(_ctx(tmp_path)).count == 1
        ctx = _ctx(tmp_path, {"exclude_paths": {"K5": ["docs/a.md"]}})
        assert detect_k5(ctx).count == 0


class TestSamples:
    def test_samples_are_capped(self, tmp_path):
        body = "".join(f"[x{i}](missing{i}.md)\n" for i in range(20))
        _doc(tmp_path, "docs/a.md", body)
        res = detect_k5(_ctx(tmp_path))
        assert res.count == 20
        assert len(res.samples) == 8

    def test_sample_carries_file_and_line(self, tmp_path):
        _doc(tmp_path, "docs/a.md", "intro\n\nSee [gone](nope.md).\n")
        sample = detect_k5(_ctx(tmp_path)).samples[0]
        assert sample.startswith("docs/a.md:3:")
