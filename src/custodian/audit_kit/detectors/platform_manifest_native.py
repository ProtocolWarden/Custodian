# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Thin loader for PlatformManifest-owned Custodian natives."""

from __future__ import annotations

from custodian.plugins.loader import load_detectors

_DEFAULT_TARGET = "platform_manifest.custodian_native:build_custodian_detectors"


def load_platform_manifest_native_detectors(config: dict) -> list:
    audit_cfg = config.get("audit") or {}
    pm_cfg = audit_cfg.get("platform_manifest")
    if not isinstance(pm_cfg, dict):
        return []
    target = pm_cfg.get("detector_contributor") or _DEFAULT_TARGET
    try:
        return load_detectors({"detectors": [target]})
    except Exception as exc:
        raise ImportError(
            "PlatformManifest PMV detectors are configured but the detector "
            f"contributor could not be loaded: {target}"
        ) from exc
