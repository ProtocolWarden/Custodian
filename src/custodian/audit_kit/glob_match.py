# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Recursive-glob matching for path patterns.

Drop-in replacement for ``fnmatch.fnmatch`` that handles ``**`` the way
operators expect: ``**`` matches zero or more path segments (including
the empty segment), and ``*`` only matches inside a segment (never
crosses ``/``).

Why this exists
───────────────
``fnmatch.fnmatch`` treats ``**`` as ``*`` repeated — i.e. one
"match-anything-including-slashes" star. That makes ``src/foo/**/*.py``
NOT match ``src/foo/bar.py`` (the ``**/*.py`` tail needs a leading
``/`` that isn't there). Operators routinely write ``**/*.py`` expecting
recursive descent and silently get no matches — a footgun.

Semantics
─────────
- ``**`` matches zero or more full path segments.
- ``*`` matches any chars except ``/`` (single-segment).
- ``?`` matches a single non-``/`` char.
- ``[abc]`` and ``[!abc]`` character classes work as in fnmatch.
- All other characters are literal.

Examples
────────
- ``glob_match("src/foo/bar.py", "src/foo/**")`` → True
- ``glob_match("src/foo/bar.py", "src/foo/**/*.py")`` → True (this is
  the case fnmatch gets wrong)
- ``glob_match("src/foo/a/b/c.py", "src/foo/**/*.py")`` → True
- ``glob_match("src/foo.py", "src/**/foo.py")`` → True (``**`` matches
  the empty segment)
- ``glob_match("src/foo/bar.py", "src/*.py")`` → False (``*`` doesn't
  cross ``/``)
"""
from __future__ import annotations

import re
from functools import lru_cache


def glob_match(path: str, pattern: str) -> bool:
    """Match a posix-style path against a recursive glob pattern."""
    return _compile(pattern).match(path) is not None


@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(_translate(pattern) + r"\Z")


def _translate(pattern: str) -> str:
    """Translate a glob pattern to an anchored regex source.

    Hand-rolled rather than using ``fnmatch.translate`` so we can give
    ``**`` proper "any number of path segments" semantics. Segment-by-
    segment translation: each segment converts independently, except
    ``**`` which absorbs an adjacent ``/`` so ``a/**/b`` matches both
    ``a/b`` and ``a/x/b``.
    """
    segments = pattern.split("/")
    out: list[str] = []
    i = 0
    while i < len(segments):
        seg = segments[i]
        if seg == "**":
            if i + 1 < len(segments):
                # `a/**/b` should match `a/b`, `a/x/b`, `a/x/y/b`, ...
                # The `/` before `**` is already in `out`. Emit
                # `(?:[^/]+/)*` so zero-or-more "<seg>/" runs follow.
                out.append("(?:[^/]+/)*")
                i += 1
                out.append(_translate_segment(segments[i]))
            else:
                # Trailing `**` → match anything else, including empty.
                # Convert the trailing `/` (if present) to `(?:/.*)?`
                # so `src/**` matches both `src` and `src/anything`.
                if out and out[-1] == "/":
                    out[-1] = "(?:/.*)?"
                else:
                    out.append(".*")
            i += 1
            continue
        out.append(_translate_segment(seg))
        if i + 1 < len(segments):
            out.append("/")
        i += 1
    return "".join(out)


def _translate_segment(seg: str) -> str:
    """Translate one path segment (no ``/``) to regex, using fnmatch
    semantics for ``*``/``?``/``[...]`` but with ``*`` confined to the
    segment (no slash-crossing).
    """
    out: list[str] = []
    i = 0
    while i < len(seg):
        c = seg[i]
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            # Character class — find the closing ']' and pass through.
            close = seg.find("]", i + 1)
            if close == -1:
                out.append(re.escape(c))
            else:
                cls = seg[i + 1 : close]
                if cls.startswith("!"):
                    cls = "^" + cls[1:]
                out.append(f"[{cls}]")
                i = close
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)
