# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""ToolAdapter abstract base — all external-tool adapters implement this."""
from __future__ import annotations

import os
import shutil
import sys
from abc import ABC, abstractmethod
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import ClassVar

from custodian.core.finding import Finding

# Repo currently being audited, set by the runner around the adapter loop.
# A ContextVar rather than an argument because ``is_available()`` takes no
# parameters, so the repo cannot be threaded through every adapter entry point.
_AUDIT_REPO: ContextVar[Path | None] = ContextVar("custodian_audit_repo", default=None)


@contextmanager
def audited_repo(repo_path: Path | None) -> Iterator[None]:
    """Scope ``find_tool`` lookups to ``repo_path``'s own virtualenv."""
    token = _AUDIT_REPO.set(Path(repo_path) if repo_path is not None else None)
    try:
        yield
    finally:
        _AUDIT_REPO.reset(token)


def _executable(path: Path) -> str | None:
    """Return ``path`` as a runnable file, trying Windows script suffixes.

    POSIX console scripts are extensionless; Windows spells the same entry point
    ``ruff.exe`` (or ``.bat``/``.cmd`` for shim-style installs). Without this the
    venv branch below can never fire on Windows.
    """
    suffixes = ("", ".exe", ".bat", ".cmd") if os.name == "nt" else ("",)
    for suffix in suffixes:
        candidate = path.with_name(path.name + suffix)
        if candidate.is_file():
            return str(candidate)
    return None


def _venv_script_dirs(venv_root: Path) -> Iterator[Path]:
    """Yield the script dirs of a virtualenv — ``bin`` on POSIX, ``Scripts`` on Windows."""
    yield venv_root / "bin"
    yield venv_root / "Scripts"


def find_tool(name: str) -> str | None:
    """Return the path to a tool binary, preferring the audited repo's venv.

    Resolution order:

    1. **The audited repo's own virtualenv.** Each repo pins its own toolchain
       (``ruff==0.15.13`` in one, something newer in the next), and the audit is
       only meaningful when it runs the versions that repo's config was written
       against. This must come first: Custodian is a *multi-repo* auditor, so the
       venv it happens to be installed in has no authority over the repo in front
       of it. Skipping this step is how a globally-installed ``custodian-multi``
       audited a repo pinned to ruff 0.15.13 using a system-wide ruff 0.16.1 and
       reported 1222 phantom findings against a tree its own ``ruff check`` calls
       clean.
    2. **Custodian's own virtualenv.** Correct when Custodian is installed into
       the repo it audits (the single-repo case) and a fallback otherwise;
       ``shutil.which`` alone misses it when the venv is not fully activated.
    3. **PATH.**
    """
    repo = _AUDIT_REPO.get()
    if repo is not None:
        for venv_root in (repo / ".venv", repo / "venv"):
            for script_dir in _venv_script_dirs(venv_root):
                found = _executable(script_dir / name)
                if found:
                    return found

    found = _executable(Path(sys.executable).parent / name)
    if found:
        return found

    return shutil.which(name)


class ToolAdapter(ABC):
    """Contract for every external-tool adapter.

    Subclasses MUST set the ``name`` class attribute and implement
    ``is_available`` and ``run``.

    The runner calls ``is_available`` first; if False it emits a
    TOOL_UNAVAILABLE finding and skips ``run`` entirely — so ``run``
    never has to handle a missing binary.
    """

    name: ClassVar[str]

    @abstractmethod
    def is_available(self) -> bool:
        """Return True iff the underlying tool is installed and executable."""

    @abstractmethod
    def run(self, repo_path: Path, config: dict) -> list[Finding]:
        """Run the tool against ``repo_path`` and return normalized findings.

        Args:
            repo_path: Root of the repository being audited.
            config:    Raw .custodian.yaml dict (old schema for now).

        Returns:
            Zero or more Finding objects.  Never raises — catch tool errors
            and return a TOOL_ERROR finding instead.
        """
