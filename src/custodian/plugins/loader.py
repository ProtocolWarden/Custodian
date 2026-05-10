# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
from __future__ import annotations

import importlib
import importlib.util
import sys
from pathlib import Path

from custodian.audit_kit.detector import Detector


def _import_target(target: str, repo_root: Path | None = None):
    """Resolve a plugin target string to the attribute object.

    Two formats are supported:

    * ``module.path:attr``       — old-style module import (``importlib.import_module``).
    * ``some/file.py:attr``      — new-style file-path import
      (``importlib.util.spec_from_file_location``).  Path is resolved relative
      to ``repo_root`` when it is relative.

    The new-style format is detected by the presence of ``.py`` in the
    module-path segment (i.e. before the ``:``).
    """
    if ":" not in target:
        raise ValueError(f"Invalid plugin target '{target}', expected module.path:attr")
    module_path, attr_name = target.split(":", 1)

    if module_path.endswith(".py"):
        # File-path import — resolve relative to repo_root.
        if repo_root is not None:
            file_path = (repo_root / module_path).resolve()
        else:
            file_path = Path(module_path).resolve()

        # Build a unique module name so different repos' files don't collide
        # in sys.modules.
        unique_name = "_custodian_file_" + str(file_path).replace("/", "_").replace(".", "_")

        spec = importlib.util.spec_from_file_location(unique_name, file_path)
        if spec is None or spec.loader is None:
            raise ImportError(
                f"Cannot create a module spec for '{file_path}' (target: '{target}')"
            )
        module = importlib.util.module_from_spec(spec)
        # Register temporarily so relative imports inside the file work.
        sys.modules[unique_name] = module
        try:
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except Exception as exc:
            sys.modules.pop(unique_name, None)
            raise ImportError(
                f"Failed to exec plugin file '{file_path}' from '{target}'"
            ) from exc
        try:
            return getattr(module, attr_name)
        except AttributeError as exc:
            raise ImportError(
                f"Plugin attribute '{attr_name}' not found in file '{file_path}'"
            ) from exc
    else:
        # Old-style module import.
        try:
            module = importlib.import_module(module_path)
        except Exception as exc:
            raise ImportError(
                f"Failed to import plugin module '{module_path}' from '{target}'"
            ) from exc
        try:
            return getattr(module, attr_name)
        except AttributeError as exc:
            raise ImportError(
                f"Plugin attribute '{attr_name}' not found in module '{module_path}'"
            ) from exc


def load_plugins(config: dict, repo_root: Path | None = None) -> list:
    """
    Load entries under config['plugins'] — protocol-style helpers
    (LogScanner, StateScanner, etc.) made available to detectors via
    AuditContext.plugin_modules.

    Each entry is either a string 'module.path:attr' or {'module': '...'}.
    """
    loaded = []
    for entry in config.get("plugins", []):
        target = entry["module"] if isinstance(entry, dict) else entry
        loaded.append(_import_target(target, repo_root))
    return loaded


def load_detectors(config: dict, repo_root: Path | None = None) -> list[Detector]:
    """
    Load entries under config['detectors'] — callables that return list[Detector].

    Each entry is either a string 'module.path:attr' or {'module': '...'}.
    Each resolved attribute must be a callable; calling it must return a
    list of Detector. This separation from plugins keeps detector
    contributions explicit and discoverable in the .custodian/config.yaml.
    """
    detectors: list[Detector] = []
    for entry in config.get("detectors", []):
        target = entry["module"] if isinstance(entry, dict) else entry
        contributor = _import_target(target, repo_root)
        if not callable(contributor):
            raise TypeError(f"Detector contributor '{target}' is not callable")
        produced = contributor()
        if not isinstance(produced, list) or not all(isinstance(d, Detector) for d in produced):
            raise TypeError(f"Detector contributor '{target}' must return list[Detector]")
        for d in produced:
            d.source = "custom"
        detectors.extend(produced)
    return detectors
