# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Architecture-split drift detectors.

These detectors enforce a few high-signal repo-boundary claims:

- Warehouse must remain a utility repo, not a platform authority.
- private topology repositories must not fork manifest language semantics.
- PlatformDeployment docs must present the repo as PlatformDeployment/topography,
  not as the canonical architecture authority.
- RepoGraph must remain the graph-language library; it must not claim to own
  graph instances, private truth, orchestration, or deployment execution.
"""
from __future__ import annotations

import re
from pathlib import Path

from custodian.audit_kit.detector import MEDIUM, AuditContext, Detector, DetectorResult


def build_architecture_split_detectors() -> list[Detector]:
    return [
        Detector(
            "ARCH1",
            "Warehouse is described as a platform authority or governance authority",
            "open",
            detect_arch1,
            MEDIUM,
            frozenset(),
        ),
        Detector(
            "ARCH2",
            "private topology repository defines competing manifest semantics instead of consuming PlatformManifest",
            "open",
            detect_arch2,
            MEDIUM,
            frozenset(),
        ),
        Detector(
            "ARCH3",
            "PlatformDeployment docs still claim canonical architecture ownership instead of PlatformDeployment/topography",
            "open",
            detect_arch3,
            MEDIUM,
            frozenset(),
        ),
        Detector(
            "ARCH4",
            "RepoGraph claims to own graph instances, private truth, or orchestration behavior",
            "open",
            detect_arch4,
            MEDIUM,
            frozenset(),
        ),
    ]


def detect_arch1(context: AuditContext) -> DetectorResult:
    if context.repo_root.name.lower() != "warehouse":
        return DetectorResult(count=0, samples=[])
    readme = _read(context.repo_root / "README.md")
    samples: list[str] = []
    if not readme:
        return DetectorResult(count=0, samples=[])
    lowered = readme.lower()
    if "context packaging" not in lowered and "context-packaging" not in lowered:
        samples.append("README.md: Warehouse should describe itself as a context packaging utility")
    for phrase in (
        "platform authority",
        "topology owner",
        "registry owner",
        "scheduler",
        "governance authority",
        "orchestration owner",
    ):
        if re.search(rf"\bis\s+(?:the\s+)?{re.escape(phrase)}\b", lowered):
            samples.append(f"README.md: Warehouse misclassified as {phrase}")
    return DetectorResult(count=len(samples), samples=samples[:8])


def detect_arch2(context: AuditContext) -> DetectorResult:
    if "private" not in context.repo_root.name.lower() or not (context.repo_root / "manifests").exists():
        return DetectorResult(count=0, samples=[])
    samples: list[str] = []
    for path in context.repo_root.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(context.repo_root)
        if any(part.startswith(".git") or part == ".venv" for part in rel.parts):
            continue
        if rel.parts[:1] == (".github",):
            continue
        if rel.parts[:1] == ("manifests",):
            continue
        if path.name == "README.md":
            continue
        if path.suffix == ".json" and path.name.endswith(".schema.json"):
            samples.append(f"{rel}: private topology repository should not define manifest schemas")
            continue
        if path.suffix == ".py":
            text = _read(path)
            if "Enum" in text or "RelationshipKind" in text or "ProjectionBehavior" in text:
                samples.append(f"{rel}: private topology repository appears to define manifest vocabulary")
    return DetectorResult(count=len(samples), samples=samples[:8])


def detect_arch3(context: AuditContext) -> DetectorResult:
    if context.repo_root.name.lower() != "platformdeployment":
        return DetectorResult(count=0, samples=[])
    samples: list[str] = []
    docs_readme = _read(context.repo_root / "docs" / "README.md")
    architecture = _read(context.repo_root / "docs" / "architecture.md")
    combined = "\n".join(part for part in (docs_readme, architecture) if part)
    lowered = combined.lower()
    for phrase in (
        "canonical platform architecture docs",
        "source of truth for cross-repo system design",
    ):
        if phrase in lowered:
            samples.append(f"docs: deprecated canonical-architecture claim still present: {phrase!r}")
    if combined and "PlatformDeployment" not in combined:
        samples.append("docs: PlatformDeployment should describe itself as the PlatformDeployment plane")
    for phrase in (
        "topology owner",
        "orchestration engine",
        "protocol contract owner",
    ):
        if re.search(rf"\bowns?:.*{re.escape(phrase)}\b", lowered):
            samples.append(f"docs: PlatformDeployment misclassified as {phrase}")
    return DetectorResult(count=len(samples), samples=samples[:8])


def detect_arch4(context: AuditContext) -> DetectorResult:
    if context.repo_root.name.lower() != "repograph":
        return DetectorResult(count=0, samples=[])
    readme = _read(context.repo_root / "README.md")
    samples: list[str] = []
    if not readme:
        return DetectorResult(count=0, samples=[])
    lowered = readme.lower()
    if "graph language" not in lowered and "graph-language" not in lowered and "graph semantics" not in lowered and "graph-semantics" not in lowered:
        samples.append("README.md: RepoGraph should describe itself as the graph-language/semantics library")
    for phrase in (
        "graph instance owner",
        "graph database",
        "private truth",
        "orchestration",
        "deployment execution",
        "public graph publication",
        "audit execution",
    ):
        for m in re.finditer(rf"\bown[s]?\b.{{0,120}}{re.escape(phrase)}", lowered):
            prefix = lowered[max(0, m.start() - 20):m.start()]
            if "not" in prefix or "never" in prefix or "no " in prefix:
                continue
            samples.append(f"README.md: RepoGraph claims to own '{phrase}' — language library only")
            break
    return DetectorResult(count=len(samples), samples=samples[:8])


def _read(path: Path) -> str:
    if not path.is_file():
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
