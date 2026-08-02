# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
# Vulture whitelist — symbols that are public API but not called within src/.
# Plugin-author Protocols: implemented by _custodian/ overlays in consumer repos.
from custodian.plugins.protocols import LogScanner, StateScanner

LogScanner.parse_event
StateScanner.state_subdir
StateScanner.is_terminal

# ImportGraph public helper — callable by plugin code outside Custodian itself.
from custodian.audit_kit.passes.import_graph import ImportGraph

ImportGraph.runtime_imports

# ── dataclass fields written at construction, read via serialisation ─────────
# Assigned by callers and emitted in JSON output rather than read back through
# attribute access, so vulture cannot see the use. Bare references below —
# an assignment here would itself read as an unused variable.
plugin_modules     # AuditContext (src/custodian/audit_kit/detector.py)
scanned_at         # AuditResult (src/custodian/audit_kit/result.py)
expected_boundary  # built by keyword at its call site (cli/repograph_governance_gate.py)

# Protocol method parameter: the body is `...`, so the argument is unused by
# definition. Implementers use it.
record             # StateScanner.is_terminal (src/custodian/plugins/protocols.py)

# ── test fixtures loaded dynamically by the plugin loader ────────────────────
# tests/fixtures/sample_consumer/ is a fake consumer repo whose detectors and
# scanners are imported by path at runtime, never referenced statically.
build_sample_detectors
OCLogScanner
