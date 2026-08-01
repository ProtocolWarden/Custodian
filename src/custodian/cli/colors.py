# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Minimal ANSI color helpers for terminal output.

Only applies colors when stdout is a TTY so piped/CI output stays clean.
"""
from __future__ import annotations

import os
import sys

_RESET  = "\033[0m"
_RED    = "\033[31m"
_YELLOW = "\033[33m"
_GREEN  = "\033[32m"


def ensure_printable_console() -> None:
    """Stop console encoding from crashing a completed audit.

    Windows consoles default to cp1252, which cannot encode the box-drawing
    and em-dash glyphs the verbose report uses. Printing them raised
    UnicodeEncodeError *after* the audit had finished, discarding the findings
    the operator asked for. Formatting must never be able to fail the run, so
    prefer UTF-8 and fall back to replacing unencodable characters.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # pragma: no cover - non-standard stream
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError, LookupError):  # pragma: no cover
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):
                pass


def _color_ok() -> bool:
    if not sys.stdout.isatty():
        return False
    return os.environ.get("NO_COLOR") is None and os.environ.get("TERM") != "dumb"


def red(text: str) -> str:
    return f"{_RED}{text}{_RESET}" if _color_ok() else text


def yellow(text: str) -> str:
    return f"{_YELLOW}{text}{_RESET}" if _color_ok() else text


def green(text: str) -> str:
    return f"{_GREEN}{text}{_RESET}" if _color_ok() else text


def severity_color(sev: str, text: str) -> str:
    if sev == "high":
        return red(text)
    if sev == "medium":
        return yellow(text)
    return text
