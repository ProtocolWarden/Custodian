# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""DC-class detector tests — markdown conventions."""
from __future__ import annotations

from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.doc_conventions import (
    build_doc_convention_detectors,
    detect_dc1, detect_dc2, detect_dc3, detect_dc4, detect_dc5,
)


def _ctx(repo_root: Path, config: dict | None = None) -> AuditContext:
    src_root = repo_root / "src"
    tests_root = repo_root / "tests"
    src_root.mkdir(parents=True, exist_ok=True)
    tests_root.mkdir(parents=True, exist_ok=True)
    return AuditContext(
        repo_root=repo_root,
        src_root=src_root,
        tests_root=tests_root,
        config=config or {},
        plugin_modules=[],
        graph=None,
    )


# ── DC1 ──────────────────────────────────────────────────────────────────────


class TestDC1DesignFrontMatter:
    def test_silent_when_design_dir_absent(self, tmp_path: Path):
        ctx = _ctx(tmp_path)
        assert detect_dc1(ctx).count == 0

    def test_missing_front_matter(self, tmp_path: Path):
        d = tmp_path / "docs" / "design"
        d.mkdir(parents=True)
        (d / "spec.md").write_text("# Spec\n\nNo front matter here.\n")
        result = detect_dc1(_ctx(tmp_path))
        assert result.count == 1
        assert "missing YAML front matter" in result.samples[0]

    def test_front_matter_without_status(self, tmp_path: Path):
        d = tmp_path / "docs" / "design"
        d.mkdir(parents=True)
        (d / "spec.md").write_text("---\ntitle: spec\n---\n\nbody\n")
        result = detect_dc1(_ctx(tmp_path))
        assert result.count == 1
        assert "`status:` field missing" in result.samples[0]

    def test_compliant_spec_passes(self, tmp_path: Path):
        d = tmp_path / "docs" / "design"
        d.mkdir(parents=True)
        (d / "spec.md").write_text("---\nstatus: draft\n---\n\nbody\n")
        assert detect_dc1(_ctx(tmp_path)).count == 0

    def test_custom_design_dir_via_config(self, tmp_path: Path):
        d = tmp_path / "specs"
        d.mkdir()
        (d / "spec.md").write_text("no front matter\n")
        ctx = _ctx(tmp_path, {"doc_conventions": {"design_dir": "specs"}})
        assert detect_dc1(ctx).count == 1


# ── DC2 ──────────────────────────────────────────────────────────────────────


class TestDC2DeadDocReferences:
    def test_resolved_reference_passes(self, tmp_path: Path):
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "real.md").write_text("real content")
        (tmp_path / "README.md").write_text("see `docs/real.md`")
        assert detect_dc2(_ctx(tmp_path)).count == 0

    def test_dead_reference_in_readme(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("see `docs/missing.md`")
        result = detect_dc2(_ctx(tmp_path))
        assert result.count == 1
        assert "dead reference" in result.samples[0]
        assert "docs/missing.md" in result.samples[0]

    def test_dead_reference_in_docs_tree(self, tmp_path: Path):
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "guide.md").write_text("see `docs/missing.md` for details")
        result = detect_dc2(_ctx(tmp_path))
        assert result.count == 1

    def test_history_dir_excluded_by_default(self, tmp_path: Path):
        (tmp_path / "docs" / "history").mkdir(parents=True)
        (tmp_path / "docs" / "history" / "old.md").write_text("see `docs/dead.md`")
        assert detect_dc2(_ctx(tmp_path)).count == 0


# ── DC3 ──────────────────────────────────────────────────────────────────────


class TestDC3ADRNaming:
    def test_silent_when_adr_dir_absent(self, tmp_path: Path):
        assert detect_dc3(_ctx(tmp_path)).count == 0

    def test_compliant_adr_passes(self, tmp_path: Path):
        adr = tmp_path / "docs" / "architecture" / "adr"
        adr.mkdir(parents=True)
        (adr / "0001-use-pydantic.md").write_text("ADR")
        assert detect_dc3(_ctx(tmp_path)).count == 0

    def test_non_padded_ordinal_flagged(self, tmp_path: Path):
        adr = tmp_path / "docs" / "architecture" / "adr"
        adr.mkdir(parents=True)
        (adr / "1-use-pydantic.md").write_text("ADR")
        result = detect_dc3(_ctx(tmp_path))
        assert result.count == 1
        assert "NNNN-kebab-case" in result.samples[0]

    def test_capital_kebab_flagged(self, tmp_path: Path):
        adr = tmp_path / "docs" / "architecture" / "adr"
        adr.mkdir(parents=True)
        (adr / "0001-Use-Pydantic.md").write_text("ADR")
        assert detect_dc3(_ctx(tmp_path)).count == 1

    def test_readme_template_index_exempt(self, tmp_path: Path):
        adr = tmp_path / "docs" / "architecture" / "adr"
        adr.mkdir(parents=True)
        (adr / "README.md").write_text("ADR index")
        (adr / "template.md").write_text("template")
        (adr / "index.md").write_text("index")
        assert detect_dc3(_ctx(tmp_path)).count == 0


# ── DC4 ──────────────────────────────────────────────────────────────────────


class TestDC4ReadmeRequiredSections:
    def test_silent_when_readme_missing(self, tmp_path: Path):
        # R1 already flags this; DC4 should not double-count.
        assert detect_dc4(_ctx(tmp_path)).count == 0

    def test_both_sections_present(self, tmp_path: Path):
        (tmp_path / "README.md").write_text(
            "# Repo\n\n## Quick start\nfoo\n\n## Architecture\nbar\n",
        )
        assert detect_dc4(_ctx(tmp_path)).count == 0

    def test_alt_phrasing_accepted(self, tmp_path: Path):
        (tmp_path / "README.md").write_text(
            "# Repo\n\n## Getting started\nfoo\n\n## How it works\nbar\n",
        )
        assert detect_dc4(_ctx(tmp_path)).count == 0

    def test_missing_quick_start(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("# Repo\n\n## Architecture\nbar\n")
        result = detect_dc4(_ctx(tmp_path))
        assert result.count == 1
        assert "Quick start" in result.samples[0]

    def test_missing_both_sections(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("# Repo\n\nJust intro.\n")
        result = detect_dc4(_ctx(tmp_path))
        assert result.count == 2


# ── DC5 ──────────────────────────────────────────────────────────────────────


class TestDC5BareSymbolCitations:
    def test_qualified_symbol_passes(self, tmp_path: Path):
        d = tmp_path / "docs" / "design"
        d.mkdir(parents=True)
        (d / "spec.md").write_text(
            "**Files:** `module.foo_bar`, `path/file.py`\n",
        )
        assert detect_dc5(_ctx(tmp_path)).count == 0

    def test_bare_symbol_flagged(self, tmp_path: Path):
        d = tmp_path / "docs" / "design"
        d.mkdir(parents=True)
        (d / "spec.md").write_text("**Files:** `foo_bar`, `baz_qux`\n")
        result = detect_dc5(_ctx(tmp_path))
        assert result.count == 1
        assert "bare symbol citation" in result.samples[0]

    def test_outside_impl_context_ignored(self, tmp_path: Path):
        d = tmp_path / "docs" / "design"
        d.mkdir(parents=True)
        (d / "spec.md").write_text("Some prose mentioning `foo_bar` casually.\n")
        assert detect_dc5(_ctx(tmp_path)).count == 0

    def test_implementation_label_also_counts(self, tmp_path: Path):
        d = tmp_path / "docs" / "design"
        d.mkdir(parents=True)
        (d / "spec.md").write_text("Implementation: `foo_bar`\n")
        assert detect_dc5(_ctx(tmp_path)).count == 1


# ── builder ──────────────────────────────────────────────────────────────────


class TestBuild:
    def test_returns_all_detectors(self):
        ds = build_doc_convention_detectors()
        ids = {d.id for d in ds}
        assert ids == {"DC1", "DC2", "DC3", "DC4", "DC5", "DC6", "DC7"}

    def test_all_low_severity(self):
        for d in build_doc_convention_detectors():
            assert d.severity == "low"


# ── DC6 ──────────────────────────────────────────────────────────────────────


class TestDC6DocsTaxonomy:
    def test_silent_when_allowlist_unset(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc6
        (tmp_path / "docs" / "weird").mkdir(parents=True)
        assert detect_dc6(_ctx(tmp_path)).count == 0

    def test_silent_when_no_docs_dir(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc6
        ctx = _ctx(tmp_path, {"doc_conventions": {
            "allowed_doc_subdirs": ["architecture"],
        }})
        assert detect_dc6(ctx).count == 0

    def test_allowed_subdir_passes(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc6
        (tmp_path / "docs" / "architecture").mkdir(parents=True)
        ctx = _ctx(tmp_path, {"doc_conventions": {
            "allowed_doc_subdirs": ["architecture", "operator"],
        }})
        assert detect_dc6(ctx).count == 0

    def test_disallowed_subdir_flagged(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc6
        (tmp_path / "docs" / "architecture").mkdir(parents=True)
        (tmp_path / "docs" / "stowaway").mkdir()
        ctx = _ctx(tmp_path, {"doc_conventions": {
            "allowed_doc_subdirs": ["architecture"],
        }})
        result = detect_dc6(ctx)
        assert result.count == 1
        assert "stowaway" in result.samples[0]

    def test_case_insensitive(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc6
        (tmp_path / "docs" / "Architecture").mkdir(parents=True)
        ctx = _ctx(tmp_path, {"doc_conventions": {
            "allowed_doc_subdirs": ["architecture"],
        }})
        assert detect_dc6(ctx).count == 0

    def test_files_in_docs_root_not_flagged(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc6
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "README.md").write_text("index")
        ctx = _ctx(tmp_path, {"doc_conventions": {
            "allowed_doc_subdirs": ["architecture"],
        }})
        assert detect_dc6(ctx).count == 0


# ── DC7 ──────────────────────────────────────────────────────────────────────


class TestDC7OrphanDocs:
    def test_silent_when_no_docs_dir(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc7
        assert detect_dc7(_ctx(tmp_path)).count == 0

    def test_doc_linked_from_readme_passes(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc7
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "guide.md").write_text("body")
        (tmp_path / "README.md").write_text("see [guide](docs/guide.md)")
        assert detect_dc7(_ctx(tmp_path)).count == 0

    def test_doc_linked_via_backticked_path_passes(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc7
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "guide.md").write_text("body")
        (tmp_path / "docs" / "README.md").write_text("see `docs/guide.md`")
        assert detect_dc7(_ctx(tmp_path)).count == 0

    def test_orphan_doc_flagged(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc7
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "orphan.md").write_text("body")
        (tmp_path / "docs" / "linked.md").write_text("body")
        (tmp_path / "README.md").write_text("see [linked](docs/linked.md)")
        result = detect_dc7(_ctx(tmp_path))
        assert result.count == 1
        assert "docs/orphan.md" in result.samples[0]

    def test_history_dir_excluded_by_default(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc7
        (tmp_path / "docs" / "history").mkdir(parents=True)
        (tmp_path / "docs" / "history" / "old.md").write_text("body")
        # No tracked doc references it; default excludes history/
        # so it doesn't get flagged.
        assert detect_dc7(_ctx(tmp_path)).count == 0

    def test_section_readme_not_an_orphan_candidate(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc7
        # Section indices (docs/**/README.md) are exempt — they're the
        # navigation surface, not consumable content.
        (tmp_path / "docs" / "ops").mkdir(parents=True)
        (tmp_path / "docs" / "ops" / "README.md").write_text("ops index")
        (tmp_path / "docs" / "README.md").write_text("docs index")
        assert detect_dc7(_ctx(tmp_path)).count == 0

    def test_relative_link_from_sibling_doc_resolves(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc7
        (tmp_path / "docs" / "ops").mkdir(parents=True)
        (tmp_path / "docs" / "ops" / "page.md").write_text(
            "[other](other.md)\n",
        )
        (tmp_path / "docs" / "ops" / "other.md").write_text("body")
        # ops/page.md links other.md as a sibling — resolves to docs/ops/other.md.
        # docs/ops/page.md itself needs a citation though, so we add one
        # in a top-level doc.
        (tmp_path / "docs" / "README.md").write_text(
            "[ops page](ops/page.md)",
        )
        assert detect_dc7(_ctx(tmp_path)).count == 0
