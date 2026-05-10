# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations


class OCLogScanner:
    def parse_event(self, line: str) -> dict | None:
        if "event=" not in line:
            return None
        return {"raw": line.strip()}
