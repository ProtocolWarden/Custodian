# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""R-class detector tests — `.console/` reconciliation gate (Layer A, spec §2).

Covers AC1-AC4:

* AC1 — scrub-target set has ONE source of truth (the boundary artifact's
  ``forbidden_names`` list, with word-boundary abbreviations derived from it);
  changing it there changes R2 everywhere.
* AC2 — R1 fires once per over-budget `.console/*.md`, silent under budget,
  suppressed by config.
* AC3 — R2 fires on a scrub-target name in a public repo's `.console/`,
  does NOT fire on a non-scrub-target private name (e.g. PrivateGraphFixture),
  is clean with no scrub-target content, and exempts private repos.
* AC4 — R2 fires on a known-leaking public repo today and is silent once
  the leak is scrubbed.

Note (I2): scrub-target literals are assembled at runtime so this tracked
public test file never contains the banned strings verbatim. The fixture
private name used in tests is the synthetic ``AcmePrivate`` / ``AP``.
"""
from __future__ import annotations

import json
import subprocess
import textwrap
from hashlib import sha256
from pathlib import Path

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.boundary import load_scrub_targets
from custodian.audit_kit.detectors.reconcile import (
    build_reconcile_detectors, detect_r1, detect_r2,
)

# Synthetic scrub-target vocabulary used by the fixtures. Assembled so the
# real banned literals never appear in this tracked file (the "real" set
# lives only in the boundary artifact in production).
_FAKE_LONG = "Acme" + "Private"          # synthetic private-repo name
_FAKE_SHORT = "A" + "P"                  # its word-boundary abbreviation


def _ctx(repo_root: Path, config: dict, enforce: bool = True) -> AuditContext:
    src_root = repo_root / "src"
    tests_root = repo_root / "tests"
    src_root.mkdir(parents=True, exist_ok=True)
    tests_root.mkdir(parents=True, exist_ok=True)
    # R1/R2 are opt-in (audit.reconcile_enforce). These detection tests assert
    # the detector logic, so they run with enforcement ON by default; the
    # dormant-by-default behaviour is covered by TestReconcileOptIn below.
    if enforce:
        cfg = dict(config)
        audit = dict(cfg.get("audit") or {})
        audit.setdefault("reconcile_enforce", True)
        cfg["audit"] = audit
        config = cfg
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


def _write_artifact(path: Path, *, forbidden: list[str], scrub: list[str] | None) -> None:
    payload: dict = {
        "schema_kind": "boundary_artifact",
        "schema_version": "1.0.0",
        "artifact_kind": "boundary_disclosure_artifact",
        "source_graph_id": "PrivateGraphFixture",
        "source_ref_or_commit": "abc123",
        "generated_at": "2026-06-04T00:00:00Z",
        "forbidden_names": forbidden,
        "allowed_aliases": [],
        "redacted_entities": [],
        "redaction_rules_applied": [],
    }
    if scrub is not None:
        payload["scrub_targets"] = scrub
    payload["artifact_hash"] = sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    path.write_text(json.dumps(payload), encoding="utf-8")


# Minimal PlatformManifest listing one public repo (PublicRepo). The repo
# under test sets repo_key=PublicRepo to be "public"; PrivateRepo is absent.
_PM_YAML = textwrap.dedent("""\
    manifest_kind: platform
    manifest_version: "1.0.0"
    repos:
      public_repo:
        canonical_name: PublicRepo
        github_url: https://github.com/ProtocolWarden/PublicRepo
""")


def _write_pm(tmp_path: Path) -> None:
    pm_dir = tmp_path / "PlatformManifest" / "src" / "platform_manifest" / "data"
    pm_dir.mkdir(parents=True)
    (pm_dir / "platform_manifest.yaml").write_text(_PM_YAML, encoding="utf-8")


def _base_config(artifact: Path, *, repo_key: str | None) -> dict:
    cfg: dict = {
        "privacy": {"boundary_artifact_file": str(artifact)},
        "audit": {"cross_repo": {"platform_manifest_repo": "PlatformManifest"}},
    }
    if repo_key is not None:
        cfg["repo_key"] = repo_key
    return cfg


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def test_rc1_rc2_registered() -> None:
    """RC-, not R-: readme.py owns R1..R6 and these collided with R1/R2 there."""
    ids = {d.id for d in build_reconcile_detectors()}
    assert ids == {"RC1", "RC2"}


# ---------------------------------------------------------------------------
# AC1 — single source of truth for the scrub-target set
# ---------------------------------------------------------------------------

class TestAC1SingleSourceOfTruth:
    def test_scrub_targets_read_from_artifact(self, tmp_path: Path) -> None:
        artifact = tmp_path / "boundary.json"
        _write_artifact(artifact, forbidden=[_FAKE_LONG], scrub=[_FAKE_LONG, _FAKE_SHORT])
        cfg = {"privacy": {"boundary_artifact_file": str(artifact)}}
        assert load_scrub_targets(cfg) == [_FAKE_LONG, _FAKE_SHORT]

    def test_changing_artifact_changes_detection(self, tmp_path: Path) -> None:
        # One config location (the artifact) drives R2. Changing it there
        # changes whether R2 fires — no second hardcoded copy exists.
        artifact = tmp_path / "boundary.json"
        _write_pm(tmp_path)
        console = tmp_path / ".console"
        console.mkdir()
        (console / "log.md").write_text(f"worked on {_FAKE_LONG} today\n", encoding="utf-8")
        cfg = _base_config(artifact, repo_key="PublicRepo")
        _git_init(tmp_path)

        # Artifact WITHOUT the name in scrub_targets → R2 silent.
        _write_artifact(artifact, forbidden=[_FAKE_LONG], scrub=[])
        assert detect_r2(_ctx(tmp_path, cfg)).count == 0

        # Add the name to scrub_targets in that single location → R2 fires.
        _write_artifact(artifact, forbidden=[_FAKE_LONG], scrub=[_FAKE_LONG])
        assert detect_r2(_ctx(tmp_path, cfg)).count == 1

    def test_no_artifact_no_scrub_targets(self) -> None:
        assert load_scrub_targets({}) == []

    def test_missing_scrub_field_falls_back_to_forbidden_names(self, tmp_path: Path) -> None:
        # The real artifact ships only `forbidden_names` (no `scrub_targets`
        # key). When `scrub_targets` is absent the vocabulary is DERIVED from
        # `forbidden_names` — the one populated key — so the two detection
        # paths share a single source of truth (AC1) and R2 is not a no-op in
        # production. The CamelCase abbreviation is derived too (§1).
        artifact = tmp_path / "boundary.json"
        _write_artifact(artifact, forbidden=[_FAKE_LONG], scrub=None)
        targets = load_scrub_targets({"privacy": {"boundary_artifact_file": str(artifact)}})
        assert _FAKE_LONG in targets
        assert _FAKE_SHORT in targets  # derived from the CamelCase initials

    def test_scrub_targets_override_forbidden_names(self, tmp_path: Path) -> None:
        # An explicit `scrub_targets` list, when present, overrides the derived
        # set (used by tests / future tightening).
        artifact = tmp_path / "boundary.json"
        _write_artifact(artifact, forbidden=[_FAKE_LONG], scrub=[_FAKE_LONG])
        assert load_scrub_targets(
            {"privacy": {"boundary_artifact_file": str(artifact)}}
        ) == [_FAKE_LONG]


# ---------------------------------------------------------------------------
# AC2 — R1 line budget
# ---------------------------------------------------------------------------

class TestAC2R1LineBudget:
    def _repo_with_log(self, tmp_path: Path, n_lines: int) -> Path:
        console = tmp_path / ".console"
        console.mkdir()
        (console / "log.md").write_text("\n".join(f"line {i}" for i in range(n_lines)) + "\n",
                                        encoding="utf-8")
        _git_init(tmp_path)
        return tmp_path

    def test_over_budget_yields_one_finding(self, tmp_path: Path) -> None:
        self._repo_with_log(tmp_path, 500)
        result = detect_r1(_ctx(tmp_path, {}))
        assert result.count == 1
        assert ".console/log.md" in result.samples[0]
        assert "500" in result.samples[0]

    def test_under_budget_yields_none(self, tmp_path: Path) -> None:
        self._repo_with_log(tmp_path, 200)
        assert detect_r1(_ctx(tmp_path, {})).count == 0

    def test_disabled_via_config_suppresses(self, tmp_path: Path) -> None:
        self._repo_with_log(tmp_path, 500)
        cfg = {"audit": {"r1_enabled": False}}
        assert detect_r1(_ctx(tmp_path, cfg)).count == 0

    def test_custom_budget(self, tmp_path: Path) -> None:
        self._repo_with_log(tmp_path, 250)
        cfg = {"audit": {"r1_line_budget": 100}}
        assert detect_r1(_ctx(tmp_path, cfg)).count == 1

    def test_one_finding_per_file(self, tmp_path: Path) -> None:
        console = tmp_path / ".console"
        console.mkdir()
        big = "\n".join(f"l{i}" for i in range(500)) + "\n"
        (console / "log.md").write_text(big, encoding="utf-8")
        (console / "backlog.md").write_text(big, encoding="utf-8")
        (console / "task.md").write_text("short\n", encoding="utf-8")
        _git_init(tmp_path)
        result = detect_r1(_ctx(tmp_path, {}))
        assert result.count == 2  # log + backlog, not task

    def test_only_top_level_md(self, tmp_path: Path) -> None:
        # Nested .console/ files are not R1's scope (R1 == .console/*.md).
        console = tmp_path / ".console" / "sessions"
        console.mkdir(parents=True)
        (console / "deep.md").write_text("\n".join(str(i) for i in range(500)) + "\n",
                                         encoding="utf-8")
        _git_init(tmp_path)
        assert detect_r1(_ctx(tmp_path, {})).count == 0


# ---------------------------------------------------------------------------
# AC3 — R2 scrub-target leak in public .console/
# ---------------------------------------------------------------------------

class TestAC3R2ScrubLeak:
    def _setup(self, tmp_path: Path, log_text: str, *, repo_key: str | None,
               scrub: list[str] | None = None) -> dict:
        artifact = tmp_path / "boundary.json"
        _write_artifact(
            artifact,
            forbidden=["PrivateGraphFixture", _FAKE_LONG],
            scrub=[_FAKE_LONG, _FAKE_SHORT] if scrub is None else scrub,
        )
        _write_pm(tmp_path)
        console = tmp_path / ".console"
        console.mkdir()
        (console / "log.md").write_text(log_text, encoding="utf-8")
        _git_init(tmp_path)
        return _base_config(artifact, repo_key=repo_key)

    def test_scrub_target_in_public_console_fires(self, tmp_path: Path) -> None:
        cfg = self._setup(tmp_path, f"touched {_FAKE_LONG} again\n", repo_key="PublicRepo")
        result = detect_r2(_ctx(tmp_path, cfg))
        assert result.count == 1
        assert ".console/log.md:1" in result.samples[0]
        assert _FAKE_LONG in result.samples[0]

    def test_short_form_word_boundary_fires(self, tmp_path: Path) -> None:
        cfg = self._setup(tmp_path, f"ran {_FAKE_SHORT} pipeline\n", repo_key="PublicRepo")
        assert detect_r2(_ctx(tmp_path, cfg)).count == 1

    def test_short_form_inside_identifier_not_flagged(self, tmp_path: Path) -> None:
        # e.g. a detector ID that embeds the short token (like "VF2") must
        # NOT trip R2 — word-boundary match. _FAKE_SHORT + "2".
        cfg = self._setup(tmp_path, f"detector {_FAKE_SHORT}2 fired\n", repo_key="PublicRepo")
        assert detect_r2(_ctx(tmp_path, cfg)).count == 0

    def test_private_manifest_name_does_not_fire(self, tmp_path: Path) -> None:
        # PrivateGraphFixture is forbidden for B1 but NOT a scrub target → R2 silent.
        cfg = self._setup(tmp_path, "archived to PrivateGraphFixture/archive\n", repo_key="PublicRepo")
        assert detect_r2(_ctx(tmp_path, cfg)).count == 0

    def test_clean_console_no_scrub_names(self, tmp_path: Path) -> None:
        cfg = self._setup(tmp_path, "ordinary work, nothing private\n", repo_key="PublicRepo")
        assert detect_r2(_ctx(tmp_path, cfg)).count == 0

    def test_private_repo_is_exempt(self, tmp_path: Path) -> None:
        # repo_key not in the manifest → private → R2 never fires even with leak.
        cfg = self._setup(tmp_path, f"touched {_FAKE_LONG}\n", repo_key="PrivateRepo")
        assert detect_r2(_ctx(tmp_path, cfg)).count == 0

    def test_no_repo_key_is_exempt(self, tmp_path: Path) -> None:
        cfg = self._setup(tmp_path, f"touched {_FAKE_LONG}\n", repo_key=None)
        assert detect_r2(_ctx(tmp_path, cfg)).count == 0

    def test_nested_console_file_is_scanned(self, tmp_path: Path) -> None:
        # R2 scope is .console/** (recursive), unlike R1.
        artifact = tmp_path / "boundary.json"
        _write_artifact(artifact, forbidden=[_FAKE_LONG], scrub=[_FAKE_LONG])
        _write_pm(tmp_path)
        nested = tmp_path / ".console" / "sessions"
        nested.mkdir(parents=True)
        (nested / "s1.md").write_text(f"{_FAKE_LONG} ran here\n", encoding="utf-8")
        _git_init(tmp_path)
        cfg = _base_config(artifact, repo_key="PublicRepo")
        assert detect_r2(_ctx(tmp_path, cfg)).count == 1


# ---------------------------------------------------------------------------
# AC4 — fires on a known-leaking public repo, silent after scrub
# ---------------------------------------------------------------------------

class TestAC4LeakingThenScrubbed:
    def _make(self, tmp_path: Path, log_text: str) -> dict:
        artifact = tmp_path / "boundary.json"
        _write_artifact(artifact, forbidden=[_FAKE_LONG], scrub=[_FAKE_LONG, _FAKE_SHORT])
        _write_pm(tmp_path)
        console = tmp_path / ".console"
        console.mkdir()
        (console / "log.md").write_text(log_text, encoding="utf-8")
        _git_init(tmp_path)
        return _base_config(artifact, repo_key="PublicRepo")

    def test_fires_today_then_silent_after_scrub(self, tmp_path: Path) -> None:
        leaking = f"deployed {_FAKE_LONG} build\nran {_FAKE_SHORT} job\n"
        cfg = self._make(tmp_path, leaking)
        before = detect_r2(_ctx(tmp_path, cfg))
        assert before.count == 2  # two leaking lines

        # Scrub the source (genericize) → R2 clean.
        (tmp_path / ".console" / "log.md").write_text(
            "deployed a private downstream build\nran the job\n", encoding="utf-8"
        )
        subprocess.run(["git", "add", "-A"], cwd=tmp_path, check=True)
        after = detect_r2(_ctx(tmp_path, cfg))
        assert after.count == 0


# ---------------------------------------------------------------------------
# Opt-in: R1/R2 are dormant unless audit.reconcile_enforce is true
# ---------------------------------------------------------------------------

class TestReconcileOptIn:
    """R1/R2 ship dormant (default off) so they can land fleet-wide without
    breaking un-reconciled public repos' CI under --fail-on-findings. They
    fire only once a repo opts in via audit.reconcile_enforce: true."""

    def test_r1_dormant_without_enforce(self, tmp_path: Path) -> None:
        console = tmp_path / ".console"
        console.mkdir()
        (console / "log.md").write_text(
            "\n".join(f"line {i}" for i in range(500)) + "\n", encoding="utf-8"
        )
        _git_init(tmp_path)
        # enforce=False → no reconcile_enforce flag → silent despite over-budget
        assert detect_r1(_ctx(tmp_path, {}, enforce=False)).count == 0
        # explicit opt-in fires
        assert detect_r1(_ctx(tmp_path, {"audit": {"reconcile_enforce": True}},
                             enforce=False)).count == 1

    def test_r2_dormant_without_enforce(self, tmp_path: Path) -> None:
        artifact = tmp_path / "boundary.json"
        _write_artifact(artifact, forbidden=[_FAKE_LONG], scrub=[_FAKE_LONG, _FAKE_SHORT])
        _write_pm(tmp_path)
        console = tmp_path / ".console"
        console.mkdir()
        (console / "log.md").write_text(f"touched {_FAKE_LONG}\n", encoding="utf-8")
        _git_init(tmp_path)
        cfg = _base_config(artifact, repo_key="PublicRepo")
        # enforce=False → no flag → silent despite a real leak
        assert detect_r2(_ctx(tmp_path, cfg, enforce=False)).count == 0
        # explicit opt-in fires
        cfg_on = dict(cfg)
        cfg_on["audit"] = {**cfg["audit"], "reconcile_enforce": True}
        assert detect_r2(_ctx(tmp_path, cfg_on, enforce=False)).count == 1
