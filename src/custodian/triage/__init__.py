# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""Triage layer — joins per-detector findings into per-file verdicts.

Each Custodian detector flags one symptom in isolation. Triage answers the
next-action question: given a file flagged by N detectors, is it
DELETE / IMPLEMENT / WIRE / REDESIGN / CLEANUP?

See ``docs/usage/triage_signals.md`` for the full decision matrix.
"""
from custodian.triage.joiner import group_findings_by_file, parse_sample
from custodian.triage.matrix import FileVerdict, Verdict, triage_file, triage_result

__all__ = [
    "FileVerdict",
    "Verdict",
    "group_findings_by_file",
    "parse_sample",
    "triage_file",
    "triage_result",
]
