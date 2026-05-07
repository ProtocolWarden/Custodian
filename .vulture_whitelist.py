# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
# Vulture whitelist — symbols that are public API but not called within src/.
# Plugin-author Protocols: implemented by _custodian/ overlays in consumer repos.
from custodian.plugins.protocols import LogScanner, StateScanner

LogScanner.parse_event
StateScanner.state_subdir
StateScanner.is_terminal

# ImportGraph public helper — callable by plugin code outside Custodian itself.
from custodian.audit_kit.passes.import_graph import ImportGraph

ImportGraph.runtime_imports
