---
name: Feature Request
about: Suggest an improvement or new capability
labels: enhancement
assignees: ''
---

## Summary

A one-sentence description of the feature.

## Problem It Solves

What is currently difficult or impossible that this would fix?

## Proposed Solution

How you imagine it working. Include API, CLI examples, or `.custodian/config.yaml` keys if relevant.

## Affected Layer

Which part of Custodian does this touch?

- [ ] `audit_kit` — detector framework / generic detectors / result schema
- [ ] `maintenance_kit` — cross-cutting maintenance helpers
- [ ] `plugins` — plugin loader / consumer protocols
- [ ] `cli` — `custodian-audit` / `custodian-doctor`
- [ ] Documentation / `.custodian/config.yaml` schema
- [ ] CI / packaging

## Alternatives Considered

Other approaches and why you ruled them out — including whether this could live as a per-repo plugin instead of in Custodian itself.

## Cross-Repo Test

Does this remain useful if more than one consumer adopts it? (Custodian's value is reuse — features that only fit one repo should usually be plugins, not core.)

## Schema Impact

- [ ] No `AuditResult.schema_version` bump needed
- [ ] Minor schema addition (backward-compatible field)
- [ ] Major schema change (`schema_version` bump required)

## Additional Context

Related issues, design notes, or prior discussion.
