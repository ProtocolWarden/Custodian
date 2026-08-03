# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""ToolAdapter abstract base — all external-tool adapters implement this."""
from __future__ import annotations

import shutil
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

from custodian.core.finding import Finding


def find_tool(name: str) -> str | None:
    """Return the path to a tool binary, checking the current venv first.

    When Custodian runs inside a virtualenv, tools installed in that venv are
    preferred over system-wide installations so ``shutil.which`` (which only
    searches PATH) is not sufficient when the venv is not fully activated.

    The venv probe goes through ``shutil.which(path=...)`` rather than a bare
    ``Path.exists()`` on the plain name: on Windows a venv ships ``ruff.exe``
    (or ``.bat``/``.cmd``), never an extensionless ``ruff``, so the plain-name
    probe never matched and EVERY lookup silently fell through to PATH. That
    made venv-first preference a no-op on Windows — a venv pinned to
    ``ruff==0.15.13`` still resolved a newer global ruff, whose wider default
    rule set then emitted thousands of phantom findings. ``which`` consults
    PATHEXT, so it matches the real filename on every platform.
    """
    venv_bin = shutil.which(name, path=str(Path(sys.executable).parent))
    if venv_bin:
        return venv_bin
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
