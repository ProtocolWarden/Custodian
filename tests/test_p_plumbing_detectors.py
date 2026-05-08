# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for P1/P2/P3 — artifact plumbing detectors."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from custodian.audit_kit.detector import AuditContext
from custodian.audit_kit.detectors.plumbing import detect_p1, detect_p2, detect_p3


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ctx(
    tmp_path: Path,
    *,
    writer_files: dict[str, str] | None = None,
    reader_files: dict[str, str] | None = None,
    plumbing_cfg: list[dict] | None = None,
) -> AuditContext:
    src_dir = tmp_path / "src"
    src_dir.mkdir(exist_ok=True)

    if writer_files:
        for relpath, body in writer_files.items():
            p = tmp_path / relpath
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)

    if reader_files:
        for relpath, body in reader_files.items():
            p = tmp_path / relpath
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)

    config: dict = {"repo_key": "MyService", "src_root": "src", "tests_root": "tests"}
    if plumbing_cfg is not None:
        config["audit"] = {"plumbing": plumbing_cfg}

    return AuditContext(
        repo_root=tmp_path,
        src_root=src_dir,
        tests_root=tmp_path / "tests",
        config=config,
        plugin_modules=[],
    )


# ---------------------------------------------------------------------------
# P1 — Writer key audit
# ---------------------------------------------------------------------------

class TestP1:
    def test_silent_when_no_plumbing_config(self, tmp_path):
        ctx = _ctx(tmp_path)
        r = detect_p1(ctx)
        assert r.count == 0

    def test_silent_when_plumbing_empty(self, tmp_path):
        ctx = _ctx(tmp_path, plumbing_cfg=[])
        r = detect_p1(ctx)
        assert r.count == 0

    def test_key_present_in_writer_no_finding(self, tmp_path):
        tmp_path.joinpath("src/writer.py").parent.mkdir(parents=True, exist_ok=True)
        ctx = _ctx(
            tmp_path,
            writer_files={"src/writer.py": 'json.dumps({"role": r, "at": t, "status": s})'},
            plumbing_cfg=[{
                "id": "hb",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["role", "at", "status"],
                "path_fragment": "heartbeat_",
            }],
        )
        r = detect_p1(ctx)
        assert r.count == 0

    def test_missing_key_flagged(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            writer_files={"src/writer.py": 'json.dumps({"role": r, "at": t})'},
            plumbing_cfg=[{
                "id": "hb",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["role", "at", "status"],
                "path_fragment": "heartbeat_",
            }],
        )
        r = detect_p1(ctx)
        assert r.count == 1
        assert "status" in r.samples[0]
        assert "[hb]" in r.samples[0]

    def test_multiple_missing_keys(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            writer_files={"src/writer.py": "# nothing here"},
            plumbing_cfg=[{
                "id": "usage",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["updated_at", "events", "hourly_exec_count"],
                "path_fragment": "usage.json",
            }],
        )
        r = detect_p1(ctx)
        assert r.count == 3

    def test_key_in_second_writer_file_no_finding(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            writer_files={
                "src/writer_a.py": "# role not here",
                "src/writer_b.py": 'data["role"] = x',
            },
            plumbing_cfg=[{
                "id": "hb",
                "writer_glob": "src/writer_*.py",
                "reader_path": "reader.py",
                "written_keys": ["role"],
                "path_fragment": "heartbeat_",
            }],
        )
        r = detect_p1(ctx)
        assert r.count == 0

    def test_skips_spec_with_no_writer_glob(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            plumbing_cfg=[{
                "id": "hb",
                "writer_glob": "",
                "reader_path": "reader.py",
                "written_keys": ["role"],
                "path_fragment": "heartbeat_",
            }],
        )
        r = detect_p1(ctx)
        assert r.count == 0

    def test_no_writer_files_matched_skips_silently(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            plumbing_cfg=[{
                "id": "hb",
                "writer_glob": "src/nonexistent_*.py",
                "reader_path": "reader.py",
                "written_keys": ["role"],
                "path_fragment": "heartbeat_",
            }],
        )
        r = detect_p1(ctx)
        # no files matched → skip the spec, no false positive
        assert r.count == 0

    def test_pydantic_field_name_found_via_word_boundary(self, tmp_path):
        """Pydantic field 'campaigns' is a word token even without quotes."""
        ctx = _ctx(
            tmp_path,
            writer_files={"src/models.py": textwrap.dedent("""\
                class ActiveCampaigns(BaseModel):
                    campaigns: list[str] = Field(default_factory=list)
            """)},
            plumbing_cfg=[{
                "id": "campaigns",
                "writer_glob": "src/models.py",
                "reader_path": "reader.py",
                "written_keys": ["campaigns"],
                "path_fragment": "active.json",
            }],
        )
        r = detect_p1(ctx)
        assert r.count == 0


# ---------------------------------------------------------------------------
# P2 — Reader key drift
# ---------------------------------------------------------------------------

class TestP2:
    def test_silent_when_no_plumbing_config(self, tmp_path):
        ctx = _ctx(tmp_path)
        r = detect_p2(ctx)
        assert r.count == 0

    def test_key_in_written_keys_no_finding(self, tmp_path):
        reader_code = textwrap.dedent("""\
            def load_usage(path):
                f = open("usage.json")
                data = json.load(f)
                return data.get("events", [])
        """)
        ctx = _ctx(
            tmp_path,
            reader_files={"reader.py": reader_code},
            plumbing_cfg=[{
                "id": "usage",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["events"],
                "path_fragment": "usage.json",
            }],
        )
        r = detect_p2(ctx)
        assert r.count == 0

    def test_undeclared_key_flagged(self, tmp_path):
        reader_code = textwrap.dedent("""\
            def load_usage(path):
                f = open("usage.json")
                data = json.load(f)
                return data.get("ghost_key", [])
        """)
        ctx = _ctx(
            tmp_path,
            reader_files={"reader.py": reader_code},
            plumbing_cfg=[{
                "id": "usage",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["events"],
                "path_fragment": "usage.json",
            }],
        )
        r = detect_p2(ctx)
        assert r.count == 1
        assert "ghost_key" in r.samples[0]
        assert "[usage]" in r.samples[0]

    def test_subscript_access_flagged(self, tmp_path):
        reader_code = textwrap.dedent("""\
            def render(path):
                with open("usage.json") as f:
                    data = json.load(f)
                return data["removed_key"]
        """)
        ctx = _ctx(
            tmp_path,
            reader_files={"reader.py": reader_code},
            plumbing_cfg=[{
                "id": "usage",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["events"],
                "path_fragment": "usage.json",
            }],
        )
        r = detect_p2(ctx)
        assert r.count == 1
        assert "removed_key" in r.samples[0]

    def test_function_without_fragment_ignored(self, tmp_path):
        """Keys in functions not referencing path_fragment are not flagged."""
        reader_code = textwrap.dedent("""\
            def unrelated():
                data = {}
                return data.get("ghost_key", None)

            def load_usage():
                with open("usage.json") as f:
                    data = json.load(f)
                return data.get("events", [])
        """)
        ctx = _ctx(
            tmp_path,
            reader_files={"reader.py": reader_code},
            plumbing_cfg=[{
                "id": "usage",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["events"],
                "path_fragment": "usage.json",
            }],
        )
        r = detect_p2(ctx)
        assert r.count == 0

    def test_silent_when_reader_not_found(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            plumbing_cfg=[{
                "id": "hb",
                "writer_glob": "src/writer.py",
                "reader_path": "nonexistent_reader.py",
                "written_keys": ["role"],
                "path_fragment": "heartbeat_",
            }],
        )
        r = detect_p2(ctx)
        assert r.count == 0

    def test_multiple_undeclared_keys(self, tmp_path):
        reader_code = textwrap.dedent("""\
            def show(path):
                with open("usage.json") as f:
                    data = json.load(f)
                a = data.get("old_key_1", 0)
                b = data["old_key_2"]
                return a + b
        """)
        ctx = _ctx(
            tmp_path,
            reader_files={"reader.py": reader_code},
            plumbing_cfg=[{
                "id": "usage",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["events"],
                "path_fragment": "usage.json",
            }],
        )
        r = detect_p2(ctx)
        assert r.count == 2

    def test_async_function_body_scanned(self, tmp_path):
        reader_code = textwrap.dedent("""\
            async def fetch():
                f = open("usage.json")
                data = json.load(f)
                return data.get("stale_async_key")
        """)
        ctx = _ctx(
            tmp_path,
            reader_files={"reader.py": reader_code},
            plumbing_cfg=[{
                "id": "usage",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["events"],
                "path_fragment": "usage.json",
            }],
        )
        r = detect_p2(ctx)
        assert r.count == 1
        assert "stale_async_key" in r.samples[0]

    def test_ignore_keys_suppresses_false_positives(self, tmp_path):
        reader_code = textwrap.dedent("""\
            def load_usage(path):
                with open("usage.json") as f:
                    data = json.load(f)
                # accesses TUI state dict key — not from JSON artifact
                res = data.get("resources", {})
                return data.get("events", [])
        """)
        ctx = _ctx(
            tmp_path,
            reader_files={"reader.py": reader_code},
            plumbing_cfg=[{
                "id": "usage",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["events"],
                "path_fragment": "usage.json",
                "ignore_keys": ["resources"],
            }],
        )
        r = detect_p2(ctx)
        assert r.count == 0

    def test_multiple_artifacts_independent(self, tmp_path):
        reader_code = textwrap.dedent("""\
            def usage_fn():
                with open("usage.json") as f:
                    d = json.load(f)
                return d.get("bad_usage_key")

            def campaigns_fn():
                with open("active.json") as f:
                    d = json.load(f)
                return d.get("bad_campaign_key")
        """)
        ctx = _ctx(
            tmp_path,
            reader_files={"reader.py": reader_code},
            plumbing_cfg=[
                {
                    "id": "usage",
                    "writer_glob": "src/writer.py",
                    "reader_path": "reader.py",
                    "written_keys": ["events"],
                    "path_fragment": "usage.json",
                },
                {
                    "id": "campaigns",
                    "writer_glob": "src/writer.py",
                    "reader_path": "reader.py",
                    "written_keys": ["campaigns"],
                    "path_fragment": "active.json",
                },
            ],
        )
        r = detect_p2(ctx)
        assert r.count == 2
        ids = {s.split("]")[0].lstrip("[") for s in r.samples}
        assert ids == {"usage", "campaigns"}


# ---------------------------------------------------------------------------
# P3 — Path coverage
# ---------------------------------------------------------------------------

class TestP3:
    def test_silent_when_no_plumbing_config(self, tmp_path):
        ctx = _ctx(tmp_path)
        r = detect_p3(ctx)
        assert r.count == 0

    def test_fragment_in_both_no_finding(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            writer_files={"src/writer.py": 'hb = status_dir / "heartbeat_intake.json"'},
            reader_files={"reader.py": 'hb = path / f"heartbeat_{role}.json"'},
            plumbing_cfg=[{
                "id": "hb",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["role"],
                "path_fragment": "heartbeat_",
            }],
        )
        r = detect_p3(ctx)
        assert r.count == 0

    def test_fragment_missing_from_writer_flagged(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            writer_files={"src/writer.py": "# nothing relevant here"},
            reader_files={"reader.py": 'open("heartbeat_intake.json")'},
            plumbing_cfg=[{
                "id": "hb",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["role"],
                "path_fragment": "heartbeat_",
            }],
        )
        r = detect_p3(ctx)
        assert r.count == 1
        assert "heartbeat_" in r.samples[0]
        assert "writer" in r.samples[0]

    def test_fragment_missing_from_reader_flagged(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            writer_files={"src/writer.py": 'hb = path / "heartbeat_intake.json"'},
            reader_files={"reader.py": "# nothing relevant here"},
            plumbing_cfg=[{
                "id": "hb",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["role"],
                "path_fragment": "heartbeat_",
            }],
        )
        r = detect_p3(ctx)
        assert r.count == 1
        assert "heartbeat_" in r.samples[0]
        assert "reader" in r.samples[0]

    def test_fragment_missing_from_both_two_findings(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            writer_files={"src/writer.py": "# unrelated"},
            reader_files={"reader.py": "# unrelated"},
            plumbing_cfg=[{
                "id": "usage",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": [],
                "path_fragment": "usage.json",
            }],
        )
        r = detect_p3(ctx)
        assert r.count == 2

    def test_reader_not_found_flagged(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            writer_files={"src/writer.py": 'open("usage.json")'},
            plumbing_cfg=[{
                "id": "usage",
                "writer_glob": "src/writer.py",
                "reader_path": "nonexistent_reader.py",
                "written_keys": [],
                "path_fragment": "usage.json",
            }],
        )
        r = detect_p3(ctx)
        assert r.count == 1
        assert "not found" in r.samples[0]

    def test_writer_glob_no_match_flagged(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            reader_files={"reader.py": 'open("usage.json")'},
            plumbing_cfg=[{
                "id": "usage",
                "writer_glob": "src/nonexistent_*.py",
                "reader_path": "reader.py",
                "written_keys": [],
                "path_fragment": "usage.json",
            }],
        )
        r = detect_p3(ctx)
        assert r.count == 1
        assert "no files" in r.samples[0]

    def test_fragment_found_in_second_writer_file(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            writer_files={
                "src/writer_a.py": "# unrelated",
                "src/writer_b.py": 'hb = path / "heartbeat_review.json"',
            },
            reader_files={"reader.py": 'glob("heartbeat_*.json")'},
            plumbing_cfg=[{
                "id": "hb",
                "writer_glob": "src/writer_*.py",
                "reader_path": "reader.py",
                "written_keys": [],
                "path_fragment": "heartbeat_",
            }],
        )
        r = detect_p3(ctx)
        assert r.count == 0

    def test_skips_when_no_path_fragment(self, tmp_path):
        ctx = _ctx(
            tmp_path,
            plumbing_cfg=[{
                "id": "hb",
                "writer_glob": "src/writer.py",
                "reader_path": "reader.py",
                "written_keys": ["role"],
                "path_fragment": "",
            }],
        )
        r = detect_p3(ctx)
        assert r.count == 0
