# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Public surface catalog policy.

The browseable repository catalog is curated and only lists approved public
repo pages. It is separate from privacy detection and separate from the
architecture charter's mention of private-truth repos.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

PUBLIC_REPO_CATALOG = {
    "OperationsCenter": "operationscenter.md",
    "OperatorConsole": "operatorconsole.md",
    "PlatformManifest": "platformmanifest.md",
    "Custodian": "custodian.md",
    "CxRP": "cxrp.md",
    "RxP": "rxp.md",
    "ExecutorRuntime": "executorruntime.md",
    "SwitchBoard": "switchboard.md",
    "SourceRegistry": "sourceregistry.md",
    "PlatformDeployment": "platformdeployment.md",
    "Warehouse": "warehouse.md",
}

PUBLIC_REPO_PAGE_SLUGS = frozenset(PUBLIC_REPO_CATALOG.values())


@dataclass(frozen=True)
class RepoCatalogEntry:
    repo: str
    slug: str


def parse_canonical_repo_catalog(text: str) -> list[RepoCatalogEntry]:
    """Parse entries from the canonical repos table in docs/repos/index.md."""
    entries: list[RepoCatalogEntry] = []
    in_catalog = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## Canonical repos"):
            in_catalog = True
            continue
        if in_catalog and stripped.startswith("## "):
            break
        if not in_catalog:
            continue
        match = re.match(r"^\|\s*\[([^\]]+)\]\(([^)]+)\)\s*\|", stripped)
        if match:
            entries.append(RepoCatalogEntry(repo=match.group(1).strip(), slug=match.group(2).strip()))
    return entries


def allowed_repo_page(repo_name: str) -> str | None:
    """Return the approved page slug for a browseable public repo page."""
    return PUBLIC_REPO_CATALOG.get(repo_name)
