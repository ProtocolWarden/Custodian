# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

from typing import Protocol


class LogScanner(Protocol):
    """Consumers implement this to teach Custodian their log format."""

    def parse_event(self, line: str) -> dict | None: ...


class StateScanner(Protocol):
    """Consumers implement this to teach Custodian where their per-task state files live and how to interpret them."""

    state_subdir: str

    def is_terminal(self, record: dict) -> bool: ...
