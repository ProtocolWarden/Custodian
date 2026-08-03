# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
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
        (d / "spec.md").write_text("# Spec\n\nNo front matter here.\n", encoding="utf-8")
        result = detect_dc1(_ctx(tmp_path))
        assert result.count == 1
        assert "missing YAML front matter" in result.samples[0]

    def test_front_matter_without_status(self, tmp_path: Path):
        d = tmp_path / "docs" / "design"
        d.mkdir(parents=True)
        (d / "spec.md").write_text("---\ntitle: spec\n---\n\nbody\n", encoding="utf-8")
        result = detect_dc1(_ctx(tmp_path))
        assert result.count == 1
        assert "missing `status:` field" in result.samples[0]

    def test_compliant_spec_passes(self, tmp_path: Path):
        d = tmp_path / "docs" / "design"
        d.mkdir(parents=True)
        (d / "spec.md").write_text("---\nstatus: draft\n---\n\nbody\n", encoding="utf-8")
        assert detect_dc1(_ctx(tmp_path)).count == 0

    def test_custom_design_dir_via_config(self, tmp_path: Path):
        d = tmp_path / "specs"
        d.mkdir()
        (d / "spec.md").write_text("no front matter\n", encoding="utf-8")
        ctx = _ctx(tmp_path, {"doc_conventions": {"design_dir": "specs"}})
        assert detect_dc1(ctx).count == 1


# ── DC2 ──────────────────────────────────────────────────────────────────────


class TestDC2DeadDocReferences:
    def test_resolved_reference_passes(self, tmp_path: Path):
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "real.md").write_text("real content", encoding="utf-8")
        (tmp_path / "README.md").write_text("see `docs/real.md`", encoding="utf-8")
        assert detect_dc2(_ctx(tmp_path)).count == 0

    def test_dead_reference_in_readme(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("see `docs/missing.md`", encoding="utf-8")
        result = detect_dc2(_ctx(tmp_path))
        assert result.count == 1
        assert "dead reference" in result.samples[0]
        assert "docs/missing.md" in result.samples[0]

    def test_dead_reference_in_docs_tree(self, tmp_path: Path):
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "guide.md").write_text("see `docs/missing.md` for details", encoding="utf-8")
        result = detect_dc2(_ctx(tmp_path))
        assert result.count == 1

    def test_history_dir_excluded_by_default(self, tmp_path: Path):
        (tmp_path / "docs" / "history").mkdir(parents=True)
        (tmp_path / "docs" / "history" / "old.md").write_text("see `docs/dead.md`", encoding="utf-8")
        assert detect_dc2(_ctx(tmp_path)).count == 0


# ── DC3 ──────────────────────────────────────────────────────────────────────


class TestDC3ADRNaming:
    def test_silent_when_adr_dir_absent(self, tmp_path: Path):
        assert detect_dc3(_ctx(tmp_path)).count == 0

    def test_compliant_adr_passes(self, tmp_path: Path):
        adr = tmp_path / "docs" / "architecture" / "adr"
        adr.mkdir(parents=True)
        (adr / "0001-use-pydantic.md").write_text("ADR", encoding="utf-8")
        assert detect_dc3(_ctx(tmp_path)).count == 0

    def test_non_padded_ordinal_flagged(self, tmp_path: Path):
        adr = tmp_path / "docs" / "architecture" / "adr"
        adr.mkdir(parents=True)
        (adr / "1-use-pydantic.md").write_text("ADR", encoding="utf-8")
        result = detect_dc3(_ctx(tmp_path))
        assert result.count == 1
        assert "NNNN-kebab-case" in result.samples[0]

    def test_capital_kebab_flagged(self, tmp_path: Path):
        adr = tmp_path / "docs" / "architecture" / "adr"
        adr.mkdir(parents=True)
        (adr / "0001-Use-Pydantic.md").write_text("ADR", encoding="utf-8")
        assert detect_dc3(_ctx(tmp_path)).count == 1

    def test_readme_template_index_exempt(self, tmp_path: Path):
        adr = tmp_path / "docs" / "architecture" / "adr"
        adr.mkdir(parents=True)
        (adr / "README.md").write_text("ADR index", encoding="utf-8")
        (adr / "template.md").write_text("template", encoding="utf-8")
        (adr / "index.md").write_text("index", encoding="utf-8")
        assert detect_dc3(_ctx(tmp_path)).count == 0


# ── DC4 ──────────────────────────────────────────────────────────────────────


class TestDC4ReadmeRequiredSections:
    def test_silent_when_readme_missing(self, tmp_path: Path):
        # R1 already flags this; DC4 should not double-count.
        assert detect_dc4(_ctx(tmp_path)).count == 0

    def test_both_sections_present(self, tmp_path: Path):
        (tmp_path / "README.md").write_text(
            "# Repo\n\n## Quick start\nfoo\n\n## Architecture\nbar\n",
         encoding="utf-8")
        assert detect_dc4(_ctx(tmp_path)).count == 0

    def test_alt_phrasing_accepted(self, tmp_path: Path):
        (tmp_path / "README.md").write_text(
            "# Repo\n\n## Getting started\nfoo\n\n## How it works\nbar\n",
         encoding="utf-8")
        assert detect_dc4(_ctx(tmp_path)).count == 0

    def test_missing_quick_start(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("# Repo\n\n## Architecture\nbar\n", encoding="utf-8")
        result = detect_dc4(_ctx(tmp_path))
        assert result.count == 1
        assert "Quick start" in result.samples[0]

    def test_missing_both_sections(self, tmp_path: Path):
        (tmp_path / "README.md").write_text("# Repo\n\nJust intro.\n", encoding="utf-8")
        result = detect_dc4(_ctx(tmp_path))
        assert result.count == 2


# ── DC5 ──────────────────────────────────────────────────────────────────────


class TestDC5BareSymbolCitations:
    def test_qualified_symbol_passes(self, tmp_path: Path):
        d = tmp_path / "docs" / "design"
        d.mkdir(parents=True)
        (d / "spec.md").write_text(
            "**Files:** `module.foo_bar`, `path/file.py`\n",
         encoding="utf-8")
        assert detect_dc5(_ctx(tmp_path)).count == 0

    def test_bare_symbol_flagged(self, tmp_path: Path):
        d = tmp_path / "docs" / "design"
        d.mkdir(parents=True)
        (d / "spec.md").write_text("**Files:** `foo_bar`, `baz_qux`\n", encoding="utf-8")
        result = detect_dc5(_ctx(tmp_path))
        assert result.count == 1
        assert "bare symbol citation" in result.samples[0]

    def test_outside_impl_context_ignored(self, tmp_path: Path):
        d = tmp_path / "docs" / "design"
        d.mkdir(parents=True)
        (d / "spec.md").write_text("Some prose mentioning `foo_bar` casually.\n", encoding="utf-8")
        assert detect_dc5(_ctx(tmp_path)).count == 0

    def test_implementation_label_also_counts(self, tmp_path: Path):
        d = tmp_path / "docs" / "design"
        d.mkdir(parents=True)
        (d / "spec.md").write_text("Implementation: `foo_bar`\n", encoding="utf-8")
        assert detect_dc5(_ctx(tmp_path)).count == 1


# ── builder ──────────────────────────────────────────────────────────────────


class TestBuild:
    def test_returns_all_detectors(self):
        ds = build_doc_convention_detectors()
        ids = {d.id for d in ds}
        assert ids == {"DC1", "DC2", "DC3", "DC4", "DC5", "DC6", "DC7", "DC8", "DC9", "DC10"}

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
        (tmp_path / "docs" / "README.md").write_text("index", encoding="utf-8")
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
        (tmp_path / "docs" / "guide.md").write_text("body", encoding="utf-8")
        (tmp_path / "README.md").write_text("see [guide](docs/guide.md)", encoding="utf-8")
        assert detect_dc7(_ctx(tmp_path)).count == 0

    def test_doc_linked_via_backticked_path_passes(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc7
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "guide.md").write_text("body", encoding="utf-8")
        (tmp_path / "docs" / "README.md").write_text("see `docs/guide.md`", encoding="utf-8")
        assert detect_dc7(_ctx(tmp_path)).count == 0

    def test_orphan_doc_flagged(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc7
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "orphan.md").write_text("body", encoding="utf-8")
        (tmp_path / "docs" / "linked.md").write_text("body", encoding="utf-8")
        (tmp_path / "README.md").write_text("see [linked](docs/linked.md)", encoding="utf-8")
        result = detect_dc7(_ctx(tmp_path))
        assert result.count == 1
        assert "docs/orphan.md" in result.samples[0]

    def test_history_dir_excluded_by_default(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc7
        (tmp_path / "docs" / "history").mkdir(parents=True)
        (tmp_path / "docs" / "history" / "old.md").write_text("body", encoding="utf-8")
        # No tracked doc references it; default excludes history/
        # so it doesn't get flagged.
        assert detect_dc7(_ctx(tmp_path)).count == 0

    def test_section_readme_not_an_orphan_candidate(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc7
        # Section indices (docs/**/README.md) are exempt — they're the
        # navigation surface, not consumable content.
        (tmp_path / "docs" / "ops").mkdir(parents=True)
        (tmp_path / "docs" / "ops" / "README.md").write_text("ops index", encoding="utf-8")
        (tmp_path / "docs" / "README.md").write_text("docs index", encoding="utf-8")
        assert detect_dc7(_ctx(tmp_path)).count == 0

    def test_relative_link_from_sibling_doc_resolves(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc7
        (tmp_path / "docs" / "ops").mkdir(parents=True)
        (tmp_path / "docs" / "ops" / "page.md").write_text(
            "[other](other.md)\n",
         encoding="utf-8")
        (tmp_path / "docs" / "ops" / "other.md").write_text("body", encoding="utf-8")
        # ops/page.md links other.md as a sibling — resolves to docs/ops/other.md.
        # docs/ops/page.md itself needs a citation though, so we add one
        # in a top-level doc.
        (tmp_path / "docs" / "README.md").write_text(
            "[ops page](ops/page.md)",
         encoding="utf-8")
        assert detect_dc7(_ctx(tmp_path)).count == 0


# ── DC1 per-dir front matter schemas ─────────────────────────────────────────


class TestDC1FrontMatterSchemas:
    def test_no_schema_means_no_findings_outside_design_dir(self, tmp_path: Path):
        # Files outside docs/design/ are unchecked unless a schema covers them.
        (tmp_path / "docs" / "architecture" / "adr").mkdir(parents=True)
        (tmp_path / "docs" / "architecture" / "adr" / "0001-foo.md").write_text(
            "# ADR\n\nNo front matter.\n",
         encoding="utf-8")
        assert detect_dc1(_ctx(tmp_path)).count == 0

    def test_schema_requires_listed_fields(self, tmp_path: Path):
        (tmp_path / "docs" / "architecture" / "adr").mkdir(parents=True)
        (tmp_path / "docs" / "architecture" / "adr" / "0001-foo.md").write_text(
            "---\nstatus: accepted\n---\n\nADR body\n",
         encoding="utf-8")
        ctx = _ctx(tmp_path, {"doc_conventions": {
            "front_matter_schemas": {
                "docs/architecture/adr/*.md": ["date", "status", "deciders"],
            },
        }})
        result = detect_dc1(ctx)
        # status is present; date and deciders are missing.
        assert result.count == 2
        assert any("date" in s for s in result.samples)
        assert any("deciders" in s for s in result.samples)

    def test_schema_compliant_doc_passes(self, tmp_path: Path):
        (tmp_path / "docs" / "architecture" / "adr").mkdir(parents=True)
        (tmp_path / "docs" / "architecture" / "adr" / "0001-foo.md").write_text(
            "---\ndate: 2026-01-01\nstatus: accepted\ndeciders: [a, b]\n---\nbody\n",
         encoding="utf-8")
        ctx = _ctx(tmp_path, {"doc_conventions": {
            "front_matter_schemas": {
                "docs/architecture/adr/*.md": ["date", "status", "deciders"],
            },
        }})
        assert detect_dc1(ctx).count == 0

    def test_schema_skips_template_and_readme(self, tmp_path: Path):
        adr = tmp_path / "docs" / "architecture" / "adr"
        adr.mkdir(parents=True)
        (adr / "template.md").write_text("# template\n", encoding="utf-8")
        (adr / "README.md").write_text("# index\n", encoding="utf-8")
        (adr / "index.md").write_text("# also index\n", encoding="utf-8")
        ctx = _ctx(tmp_path, {"doc_conventions": {
            "front_matter_schemas": {
                "docs/architecture/adr/*.md": ["status"],
            },
        }})
        assert detect_dc1(ctx).count == 0

    def test_missing_block_reports_once_not_per_field(self, tmp_path: Path):
        (tmp_path / "docs" / "ops").mkdir(parents=True)
        (tmp_path / "docs" / "ops" / "runbook.md").write_text(
            "# Runbook\n\nNo front matter at all.\n",
         encoding="utf-8")
        ctx = _ctx(tmp_path, {"doc_conventions": {
            "front_matter_schemas": {
                "docs/ops/*.md": ["status", "owner", "last_reviewed"],
            },
        }})
        result = detect_dc1(ctx)
        assert result.count == 1
        assert "missing YAML front matter" in result.samples[0]

    def test_schema_runs_alongside_default_design_dir_check(self, tmp_path: Path):
        # Both checks contribute to the count.
        (tmp_path / "docs" / "design").mkdir(parents=True)
        (tmp_path / "docs" / "design" / "spec.md").write_text(
            "# spec without front matter\n",
         encoding="utf-8")
        (tmp_path / "docs" / "ops").mkdir(parents=True)
        (tmp_path / "docs" / "ops" / "runbook.md").write_text(
            "---\nstatus: ready\n---\nbody\n",
         encoding="utf-8")
        ctx = _ctx(tmp_path, {"doc_conventions": {
            "front_matter_schemas": {
                "docs/ops/*.md": ["status", "owner"],
            },
        }})
        result = detect_dc1(ctx)
        # design/spec.md missing block (1) + ops/runbook.md missing owner (1)
        assert result.count == 2


# ── DC8 ──────────────────────────────────────────────────────────────────────


class TestDC8SectionOrdering:
    def test_silent_when_readme_missing(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc8
        assert detect_dc8(_ctx(tmp_path)).count == 0

    def test_default_order_passes(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc8
        (tmp_path / "README.md").write_text(
            "# Repo\n\n"
            "## What this repo is\nA thing.\n\n"
            "## What this repo is not\nNot another thing.\n\n"
            "## Quick start\n```\npip install\n```\n\n"
            "## Architecture\nLayered.\n\n"
            "## License\nMIT\n",
         encoding="utf-8")
        assert detect_dc8(_ctx(tmp_path)).count == 0

    def test_quick_start_after_architecture_flagged(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc8
        (tmp_path / "README.md").write_text(
            "# Repo\n\n"
            "## Architecture\nfirst\n\n"
            "## Quick start\nsecond\n\n"
            "## License\n\n",
         encoding="utf-8")
        result = detect_dc8(_ctx(tmp_path))
        assert result.count >= 1
        assert any("Architecture" in s and "Quick start" in s for s in result.samples)

    def test_license_before_quick_start_flagged(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc8
        (tmp_path / "README.md").write_text(
            "# Repo\n\n"
            "## License\nMIT\n\n"
            "## Quick start\n```\npip install\n```\n\n"
            "## Architecture\nLayered\n\n",
         encoding="utf-8")
        result = detect_dc8(_ctx(tmp_path))
        assert result.count >= 1

    def test_unknown_sections_in_middle_ignored(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc8
        (tmp_path / "README.md").write_text(
            "# Repo\n\n"
            "## What this repo is\nA thing.\n\n"
            "## Quick start\n```\npip install\n```\n\n"
            "## My Custom Section\nrandom\n\n"
            "## Another Custom Section\nrandom\n\n"
            "## License\n\n",
         encoding="utf-8")
        # Custom sections are in the middle but aren't in the order
        # list — they should be silently ignored.
        assert detect_dc8(_ctx(tmp_path)).count == 0

    def test_missing_sections_skipped(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc8
        # README only has Quick start + License — DC4 covers the missing
        # ones; DC8 only enforces ordering of present sections.
        (tmp_path / "README.md").write_text(
            "# Repo\n\n## Quick start\nfoo\n\n## License\n\n",
         encoding="utf-8")
        assert detect_dc8(_ctx(tmp_path)).count == 0

    def test_custom_order_via_config(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc8
        (tmp_path / "README.md").write_text(
            "# Repo\n\n## Public API\nfirst\n\n## Examples\nsecond\n\n",
         encoding="utf-8")
        # Custom order: Examples should come before Public API
        ctx = _ctx(tmp_path, {"doc_conventions": {
            "required_section_order": [
                ["Examples",   r"^##\s+Examples\b"],
                ["Public API", r"^##\s+Public\s+API\b"],
            ],
        }})
        result = detect_dc8(ctx)
        assert result.count == 1
        assert "Examples" in result.samples[0]


# ── DC9 ──────────────────────────────────────────────────────────────────────


class TestDC9IndexCoverage:
    def _repo(self, tmp_path: Path, *, index_text: str) -> Path:
        arch = tmp_path / "docs" / "architecture"
        arch.mkdir(parents=True)
        (tmp_path / "docs" / "README.md").write_text(index_text, encoding="utf-8")
        (arch / "indexed.md").write_text("# Indexed", encoding="utf-8")
        (arch / "sibling-only.md").write_text("# Cited only by a sibling", encoding="utf-8")
        # The DC7 escape hatch this detector exists to close: a sibling link
        # keeps sibling-only.md from being an orphan, but not from being
        # missing from the index.
        (arch / "indexed.md").write_text(
            "# Indexed\n\nSee [sibling](sibling-only.md).\n"
        , encoding="utf-8")
        return tmp_path

    def test_silent_when_config_unset(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc9
        self._repo(tmp_path, index_text="[i](architecture/indexed.md)")
        assert detect_dc9(_ctx(tmp_path)).count == 0

    def test_silent_when_no_index_file(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc9
        (tmp_path / "docs" / "architecture").mkdir(parents=True)
        (tmp_path / "docs" / "architecture" / "a.md").write_text("# A", encoding="utf-8")
        ctx = _ctx(tmp_path, {"doc_conventions": {"dc9_index_dirs": ["docs/architecture"]}})
        assert detect_dc9(ctx).count == 0

    def test_sibling_linked_doc_flagged_when_unindexed(self, tmp_path: Path):
        """The DC7 gap: sibling-cited but index-absent docs must be flagged."""
        from custodian.audit_kit.detectors.doc_conventions import detect_dc9
        self._repo(tmp_path, index_text="See [indexed](architecture/indexed.md).\n")
        ctx = _ctx(tmp_path, {"doc_conventions": {"dc9_index_dirs": ["docs/architecture"]}})
        result = detect_dc9(ctx)
        assert result.count == 1
        assert "sibling-only.md" in result.samples[0]
        assert "not cited from docs/README.md" in result.samples[0]

    def test_passes_when_all_indexed_via_link(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc9
        self._repo(
            tmp_path,
            index_text=(
                "- [indexed](architecture/indexed.md)\n"
                "- [sibling](architecture/sibling-only.md)\n"
            ),
        )
        ctx = _ctx(tmp_path, {"doc_conventions": {"dc9_index_dirs": ["docs/architecture"]}})
        assert detect_dc9(ctx).count == 0

    def test_backtick_citation_counts(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc9
        self._repo(
            tmp_path,
            index_text=(
                "- [indexed](architecture/indexed.md)\n"
                "- see `docs/architecture/sibling-only.md`\n"
            ),
        )
        ctx = _ctx(tmp_path, {"doc_conventions": {"dc9_index_dirs": ["docs/architecture"]}})
        assert detect_dc9(ctx).count == 0

    def test_readme_and_excluded_paths_skipped(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc9
        repo = self._repo(
            tmp_path,
            index_text=(
                "- [indexed](architecture/indexed.md)\n"
                "- [sibling](architecture/sibling-only.md)\n"
            ),
        )
        arch = repo / "docs" / "architecture"
        (arch / "README.md").write_text("# section index", encoding="utf-8")        # exempt
        (arch / "archive").mkdir()
        (arch / "archive" / "old.md").write_text("# archived", encoding="utf-8")    # excluded
        ctx = _ctx(tmp_path, {"doc_conventions": {"dc9_index_dirs": ["docs/architecture"]}})
        assert detect_dc9(ctx).count == 0

    def test_missing_configured_dir_is_silent(self, tmp_path: Path):
        from custodian.audit_kit.detectors.doc_conventions import detect_dc9
        (tmp_path / "docs").mkdir()
        (tmp_path / "docs" / "README.md").write_text("index", encoding="utf-8")
        ctx = _ctx(tmp_path, {"doc_conventions": {"dc9_index_dirs": ["docs/nope"]}})
        assert detect_dc9(ctx).count == 0


# ── DC10: claims-integrated-while-deferring-the-integration ───────────────────

from custodian.audit_kit.detectors.doc_conventions import detect_dc10  # noqa: E402


def _write(repo: Path, rel: str, text: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class TestDC10ClaimsIntegratedWhileDeferring:
    _313 = (
        "## Stage 4\n**Status**: ✅ end-to-end integration complete & verified\n\n"
        "## Next Steps\n**Stage 5 (Ready to Start)**:\n"
        "- Update haiku_collector_prompt.md STEP 3 to call get_extraction_health()\n"
    )

    def test_313_self_contradiction_flagged(self, tmp_path: Path):
        _write(tmp_path, ".console/backlog.md", self._313)
        assert detect_dc10(_ctx(tmp_path)).count == 1

    def test_not_yet_wired_variant_flagged(self, tmp_path: Path):
        _write(tmp_path, "docs/design/x.md", "Fully integrated end-to-end.\nNote: the metric is not yet wired into the collector.\n")
        assert detect_dc10(_ctx(tmp_path)).count == 1

    def test_legit_staged_work_not_flagged(self, tmp_path: Path):
        # "Stage 1 complete, Stage 2 next" is NOT an integration self-contradiction.
        _write(tmp_path, ".console/backlog.md", "## Stage 1 ✅ Complete\n## Next Steps\nStage 2: add the API surface\n")
        assert detect_dc10(_ctx(tmp_path)).count == 0

    def test_integration_claim_only_not_flagged(self, tmp_path: Path):
        _write(tmp_path, "docs/design/x.md", "The feature is wired end-to-end and shipped. All green.\n")
        assert detect_dc10(_ctx(tmp_path)).count == 0

    def test_defer_only_not_flagged(self, tmp_path: Path):
        _write(tmp_path, "docs/design/x.md", "TODO: not yet wired into the collector — tracked separately.\n")
        assert detect_dc10(_ctx(tmp_path)).count == 0

    def test_non_integration_next_steps_not_flagged(self, tmp_path: Path):
        _write(tmp_path, ".console/log.md", "Feature done.\n## Next Steps\n- write more docs\n- add a benchmark\n")
        assert detect_dc10(_ctx(tmp_path)).count == 0

    def test_baseline_accepts_existing(self, tmp_path: Path):
        _write(tmp_path, ".console/backlog.md", self._313)
        cfg = {"audit": {"dc10_baseline": [".console/backlog.md"]}}
        assert detect_dc10(_ctx(tmp_path, cfg)).count == 0

    def test_exclude_path(self, tmp_path: Path):
        _write(tmp_path, ".console/backlog.md", self._313)
        cfg = {"audit": {"exclude_paths": {"DC10": [".console/backlog.md"]}}}
        assert detect_dc10(_ctx(tmp_path, cfg)).count == 0
