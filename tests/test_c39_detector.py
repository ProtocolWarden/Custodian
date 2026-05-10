# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Tests for C39 detector: logger.exception() outside exception handler."""
from __future__ import annotations

import textwrap
from pathlib import Path

from custodian.audit_kit.code_health import detect_c39
from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.passes.ast_forest import AstForest


def _write(tmp_path: Path, rel: str, src: str) -> None:
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(src), encoding="utf-8")


def _ctx(tmp_path: Path, config: dict | None = None) -> AuditContext:
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=AstForest()),
    )


class TestC39:
    def test_no_logger_exception_is_clean(self, tmp_path):
        _write(tmp_path, "src/x.py", """\
            import logging
            logger = logging.getLogger(__name__)

            def f():
                logger.error("something failed")
        """)
        assert detect_c39(_ctx(tmp_path)).count == 0

    def test_inside_except_not_flagged(self, tmp_path):
        _write(tmp_path, "src/x.py", """\
            import logging
            logger = logging.getLogger(__name__)

            def f():
                try:
                    do_thing()
                except Exception:
                    logger.exception("it broke")
        """)
        assert detect_c39(_ctx(tmp_path)).count == 0

    def test_outside_except_flagged(self, tmp_path):
        _write(tmp_path, "src/x.py", """\
            import logging
            logger = logging.getLogger(__name__)

            def f(last_error):
                if last_error:
                    logger.exception("health check failed")
                raise RuntimeError("failed")
        """)
        result = detect_c39(_ctx(tmp_path))
        assert result.count == 1
        assert "logger.exception()" in result.samples[0]
        assert "logger.error()" in result.samples[0]

    def test_nested_except_inside_outer_try_not_flagged(self, tmp_path):
        _write(tmp_path, "src/x.py", """\
            import logging
            logger = logging.getLogger(__name__)

            def f():
                try:
                    inner()
                except ValueError:
                    try:
                        fallback()
                    except Exception:
                        logger.exception("fallback also failed")
        """)
        assert detect_c39(_ctx(tmp_path)).count == 0

    def test_module_level_outside_except_flagged(self, tmp_path):
        _write(tmp_path, "src/x.py", """\
            import logging
            logger = logging.getLogger(__name__)

            try:
                risky()
            except Exception:
                pass

            logger.exception("this is wrong")
        """)
        result = detect_c39(_ctx(tmp_path))
        assert result.count == 1

    def test_logger_error_inside_except_not_flagged(self, tmp_path):
        _write(tmp_path, "src/x.py", """\
            import logging
            logger = logging.getLogger(__name__)

            def f():
                try:
                    work()
                except Exception:
                    logger.error("use error not exception")
        """)
        assert detect_c39(_ctx(tmp_path)).count == 0

    def test_exception_inside_except_else_not_flagged(self, tmp_path):
        _write(tmp_path, "src/x.py", """\
            import logging
            logger = logging.getLogger(__name__)

            def f():
                try:
                    work()
                except ValueError:
                    logger.exception("value error")
                except Exception:
                    logger.exception("other error")
        """)
        assert detect_c39(_ctx(tmp_path)).count == 0

    def test_sample_includes_file_lineno_and_fix(self, tmp_path):
        _write(tmp_path, "src/client.py", """\
            import logging
            log = logging.getLogger(__name__)

            def check_health(last_err):
                log.exception("health_check_failed")
                raise RuntimeError("timed out")
        """)
        result = detect_c39(_ctx(tmp_path))
        assert result.count == 1
        assert "src/client.py" in result.samples[0]
        assert "log.exception()" in result.samples[0]

    def test_exclude_paths_suppresses_finding(self, tmp_path):
        _write(tmp_path, "src/legacy.py", """\
            import logging
            logger = logging.getLogger(__name__)

            def f():
                logger.exception("always wrong but excluded")
        """)
        config = {"audit": {"exclude_paths": {"C39": ["src/legacy.py"]}}}
        assert detect_c39(_ctx(tmp_path, config)).count == 0
