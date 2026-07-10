# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations


from custodian.audit_kit.code_health import (
    build_code_health_detectors,
    detect_c11,
    detect_c28,
    detect_c29,
    detect_c32,
    detect_c33,
)
from custodian.audit_kit.detector import AuditContext


def _ctx(tmp_path, src_text: str, *, config: dict | None = None) -> AuditContext:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "sample.py").write_text(src_text, encoding="utf-8")
    return AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
    )


def test_non_deprecated_detectors_on_fixture(tmp_path):
    src = tmp_path / "src"
    tests = tmp_path / "tests"
    src.mkdir()
    tests.mkdir()
    (src / "sample.py").write_text(
        "# TODO: fix\n# FIXME: also\nsubprocess.run(['ls'])\n",
        encoding="utf-8",
    )
    context = AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tests,
        config={"audit": {"stale_handlers": [], "common_words": []}},
        plugin_modules=[],
    )
    by_id = {det.id: det.detect(context).count for det in build_code_health_detectors()}
    assert by_id["C1"] == 1
    assert by_id["C6"] == 1
    assert by_id["C11"] == 1



def test_exclude_paths_skips_matched_files(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.py").write_text("x = 1\n", encoding="utf-8")
    (src / "cli.py").write_text("# TODO fix this\n# TODO and this\n", encoding="utf-8")

    context = AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path,
        config={"audit": {"exclude_paths": {"C1": ["src/cli.py"]}}},
        plugin_modules=[],
    )
    counts = {det.id: det.detect(context).count for det in build_code_health_detectors()}
    assert counts["C1"] == 0


def test_exclude_paths_supports_globs(tmp_path):
    src = tmp_path / "src"
    (src / "cli").mkdir(parents=True)
    (src / "lib.py").write_text("# TODO\n", encoding="utf-8")
    (src / "cli" / "a.py").write_text("# TODO\n# TODO\n", encoding="utf-8")

    context = AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path,
        config={"audit": {"exclude_paths": {"C1": ["src/cli/*.py"]}}},
        plugin_modules=[],
    )
    counts = {det.id: det.detect(context).count for det in build_code_health_detectors()}
    assert counts["C1"] == 1  # only lib.py's TODO


def test_exclude_paths_recursive_glob(tmp_path):
    src = tmp_path / "src"
    (src / "pkg" / "deep").mkdir(parents=True)
    (src / "outside.py").write_text("# TODO\n", encoding="utf-8")
    (src / "pkg" / "shallow.py").write_text("# TODO\n", encoding="utf-8")
    (src / "pkg" / "deep" / "leaf.py").write_text("# TODO\n", encoding="utf-8")

    context = AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path,
        config={"audit": {"exclude_paths": {"C1": ["src/pkg/**/*.py"]}}},
        plugin_modules=[],
    )
    counts = {det.id: det.detect(context).count for det in build_code_health_detectors()}
    assert counts["C1"] == 1  # only outside.py survives


def test_exclude_paths_only_applies_to_named_detector(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "noisy.py").write_text("# TODO\n# FIXME\n", encoding="utf-8")

    context = AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path,
        config={"audit": {"exclude_paths": {"C6": ["src/noisy.py"]}}},
        plugin_modules=[],
    )
    counts = {det.id: det.detect(context).count for det in build_code_health_detectors()}
    assert counts["C1"] == 1   # TODO still reported
    assert counts["C6"] == 0   # FIXME suppressed


# ── C11: subprocess without timeout ──────────────────────────────────────────

def test_c11_flags_run_without_timeout(tmp_path):
    ctx = _ctx(tmp_path, "import subprocess\nsubprocess.run(['ls'])\n")
    assert detect_c11(ctx).count == 1


def test_c11_skips_run_with_timeout(tmp_path):
    ctx = _ctx(tmp_path, "import subprocess\nsubprocess.run(['ls'], timeout=5)\n")
    assert detect_c11(ctx).count == 0


def test_c11_flags_check_output_without_timeout(tmp_path):
    ctx = _ctx(tmp_path, "import subprocess\nsubprocess.check_output(['git', 'log'])\n")
    assert detect_c11(ctx).count == 1


def test_c11_handles_multiline_call_with_timeout(tmp_path):
    ctx = _ctx(tmp_path, """\
import subprocess
subprocess.run(
    ['git', 'status'],
    capture_output=True,
    timeout=30,
)
""")
    assert detect_c11(ctx).count == 0


def test_c11_handles_multiline_call_without_timeout(tmp_path):
    ctx = _ctx(tmp_path, """\
import subprocess
subprocess.run(
    ['git', 'status'],
    capture_output=True,
    text=True,
)
""")
    assert detect_c11(ctx).count == 1


# ── C28: hardcoded IP address ─────────────────────────────────────────────────

def test_c28_flags_real_ip(tmp_path):
    ctx = _ctx(tmp_path, 'host = "192.168.1.1"\n')
    assert detect_c28(ctx).count == 1


def test_c28_skips_localhost(tmp_path):
    ctx = _ctx(tmp_path, 'host = "127.0.0.1"\n')
    assert detect_c28(ctx).count == 0


def test_c28_skips_any_bind(tmp_path):
    ctx = _ctx(tmp_path, 'bind = "0.0.0.0"\n')
    assert detect_c28(ctx).count == 0


def test_c28_skips_non_ip_string(tmp_path):
    ctx = _ctx(tmp_path, 'addr = "not.an.ip.address"\n')
    assert detect_c28(ctx).count == 0


# ── C29: file too long ────────────────────────────────────────────────────────

def test_c29_flags_file_over_threshold(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "big.py").write_text("\n" * 501, encoding="utf-8")
    ctx = AuditContext(
        repo_root=tmp_path, src_root=src, tests_root=tmp_path / "tests",
        config={}, plugin_modules=[],
    )
    assert detect_c29(ctx).count == 1


def test_c29_skips_file_at_threshold(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("\n" * 500, encoding="utf-8")
    ctx = AuditContext(
        repo_root=tmp_path, src_root=src, tests_root=tmp_path / "tests",
        config={}, plugin_modules=[],
    )
    assert detect_c29(ctx).count == 0


def test_c29_respects_custom_threshold(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "medium.py").write_text("\n" * 201, encoding="utf-8")
    ctx = AuditContext(
        repo_root=tmp_path, src_root=src, tests_root=tmp_path / "tests",
        config={"audit": {"c29_threshold": 200}}, plugin_modules=[],
    )
    assert detect_c29(ctx).count == 1


# ── C32: hardcoded credentials ────────────────────────────────────────────────

def test_c32_flags_password_assignment(tmp_path):
    ctx = _ctx(tmp_path, 'password = "supersecret"\n')
    assert detect_c32(ctx).count == 1


def test_c32_flags_api_key_assignment(tmp_path):
    ctx = _ctx(tmp_path, 'api_key = "sk-abc123def456"\n')
    assert detect_c32(ctx).count == 1


def test_c32_flags_dict_token_key(tmp_path):
    ctx = _ctx(tmp_path, 'cfg = {"token": "live-secret-value"}\n')
    assert detect_c32(ctx).count == 1


def test_c32_skips_placeholder_password(tmp_path):
    ctx = _ctx(tmp_path, 'password = "your-password-here"\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_example_token(tmp_path):
    ctx = _ctx(tmp_path, 'token = "example"\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_empty_password(tmp_path):
    ctx = _ctx(tmp_path, 'password = ""\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_non_credential_name(tmp_path):
    ctx = _ctx(tmp_path, 'username = "alice"\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_url_value(tmp_path):
    ctx = _ctx(tmp_path, 'TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_env_var_name_as_value(tmp_path):
    ctx = _ctx(tmp_path, '_SECRET_ENV = "OPERATIONS_CENTER_WEBHOOK_SECRET"\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_token_in_tokenizer_key(tmp_path):
    ctx = _ctx(tmp_path, 'cfg = {"word_tokenizer": "You are a script str"}\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_token_endpoint_name(tmp_path):
    ctx = _ctx(tmp_path, 'token_endpoint = "https://example.com/oauth"\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_punctuation_only_value(tmp_path):
    # A token-stripping charset: the name contains "token" but the value is
    # pure punctuation — no alphanumeric entropy, so it cannot be a secret.
    ctx = _ctx(tmp_path, "_TOKEN_STRIP = \".,!?;:'()-\"\n")
    assert detect_c32(ctx).count == 0


# ── C33: ghost-work comment density ──────────────────────────────────────────

class TestC33:
    def test_file_below_threshold_not_flagged(self, tmp_path):
        src = "# TODO: fix a\n# TODO: fix b\n# FIXME: c\n# HACK: d\nx = 1\n"
        ctx = _ctx(tmp_path, src)
        assert detect_c33(ctx).count == 0

    def test_file_at_threshold_flagged(self, tmp_path):
        src = "# TODO: a\n# TODO: b\n# FIXME: c\n# HACK: d\n# XXX: e\nx = 1\n"
        ctx = _ctx(tmp_path, src)
        assert detect_c33(ctx).count == 1

    def test_file_above_threshold_flagged(self, tmp_path):
        src = "# TODO: a\n# TODO: b\n# FIXME: c\n# HACK: d\n# XXX: e\n# TODO: f\nx = 1\n"
        ctx = _ctx(tmp_path, src)
        assert detect_c33(ctx).count == 1

    def test_custom_threshold_respected(self, tmp_path):
        src = "# TODO: a\n# FIXME: b\n# HACK: c\nx = 1\n"
        ctx = _ctx(tmp_path, src, config={"audit": {"c33_threshold": 2}})
        assert detect_c33(ctx).count == 1

    def test_custom_threshold_not_reached(self, tmp_path):
        src = "# TODO: a\n# FIXME: b\n# HACK: c\nx = 1\n"
        ctx = _ctx(tmp_path, src, config={"audit": {"c33_threshold": 10}})
        assert detect_c33(ctx).count == 0

    def test_sample_mentions_file_and_count(self, tmp_path):
        src = "# TODO: a\n# TODO: b\n# FIXME: c\n# HACK: d\n# XXX: e\nx = 1\n"
        ctx = _ctx(tmp_path, src)
        result = detect_c33(ctx)
        assert result.count == 1
        assert "5" in result.samples[0]
