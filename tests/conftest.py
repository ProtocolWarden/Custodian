# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent.resolve()
_EXPECTED_VENV = (_REPO_ROOT / ".venv").resolve()
_ACTIVE_PREFIX = Path(sys.prefix).resolve()
_IN_CI = os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")

if _EXPECTED_VENV.is_dir() and not _IN_CI and _ACTIVE_PREFIX != _EXPECTED_VENV:
    raise SystemExit(
        f"ERROR: Tests must be run inside this project's virtual environment.\n"
        f"Expected: {_EXPECTED_VENV}\n"
        f"Active:   {_ACTIVE_PREFIX}\n\n"
        f"Activate it first:\n"
        f"  source .venv/bin/activate\n"
        f"Or invoke pytest through the venv directly:\n"
        f"  .venv/bin/pytest"
    )
