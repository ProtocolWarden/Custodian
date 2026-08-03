# Incomplete integration (D12)

D12 flags a public source symbol that **tests exercise but production never
calls**. That combination is the signature of a feature that was built and
tested, but whose consumer was never wired up — work that looks finished by
every other measure, including a green test suite.

It is **opt-in and off by default**. See [Enabling it](#enabling-it).

## The signal, and why it is narrow

The distinction D12 draws is between two different problems:

| Referenced by | Verdict | Detector |
|---|---|---|
| nowhere at all | dead code — delete it | D1 / D5 / Vulture |
| tests only | integration gap — wire it up | **D12** |
| production | fine | — |

Splitting the source forest from the tests forest is what keeps the false
positive rate down. A symbol nothing mentions is a deletion candidate and other
detectors already own it. A symbol *only* the tests mention is different in
kind: someone wrote it, proved it works, and never connected it. The tests pass,
coverage looks fine, and the feature does nothing in production.

The origin case was `get_extraction_health` in OperationsCenter#313 — defined,
tested, and the STEP-3 caller never written. It shipped green.

## What counts as a reference

Deliberately conservative. A symbol is considered referenced if its name appears
anywhere in an AST as either a `Name` load or an `Attribute` access — a call
`foo()`, an attribute call `x.foo()`, a bare mention `foo`, a callback passed by
name. Any mention at all clears it.

This over-clears rather than over-reports: D12 only fires on symbols production
never mentions *in any form*. Name-based matching also means a same-named symbol
in an unrelated module counts as a reference. That is the intended trade —
missing a real gap is cheaper than red-walling a repo on a false one.

## What is skipped

D12 never considers:

- **Private and dunder names** — anything starting with `_`
- **Test helpers** — anything starting with `test`
- **pytest plugin hooks** — anything starting with `pytest_`, since pytest
  invokes these by name and there is no in-repo caller by design
- **Decorated definitions** — any `def` with a decorator. CLI commands,
  `@property`, fixtures, routes, validators, `@abstractmethod`, `@overload` are
  all framework- or runtime-invoked, so an absent in-repo caller means nothing
- **`__all__` exports** — a symbol a module publicly exports is an API surface,
  and its consumer may be another repo
- **Entry-point names** in the detector's internal `_NEVER_DEAD` set

D12 also returns zero findings unless both the `ast_forest` and `tests_forest`
passes are available. A repo with no `tests_root` produces no D12 findings
rather than flagging its entire public surface.

## Enabling it

D12 is registered `deprecated=True`. That flag normally means "an external tool
replaced this", but here it is reused as the off-by-default lever: turning D12
on against a large existing backlog would red-wall consumers that audit against
`Custodian@main`. The detector is validated; it just must not break anyone on
day one.

```bash
custodian audit --only D12 --include-deprecated
```

## Adopting it on a repo with a backlog

Running D12 for the first time on a mature repo usually surfaces a pile of
pre-existing gaps. The baseline ratchet exists so you can gate on *regressions*
without first burning that pile down:

```yaml
# .custodian/config.yaml
audit:
  d12_baseline:
    - get_extraction_health
    - build_report_payload
```

Listed **symbol names** are skipped, so D12 fires only on newly-added
tested-but-unwired symbols. Burn the backlog down separately and delete names
from the baseline as you go — the list is a ratchet, and it should only shrink.

Note the baseline matches on bare symbol name, not path. Two unrelated functions
with the same name are both silenced by one entry.

To exclude whole files from *definition* scanning:

```yaml
audit:
  exclude_paths:
    D12:
      - "src/legacy/**"
```

One asymmetry worth knowing: excludes apply only to where D12 looks for
**definitions**. Production references and `__all__` exports are still collected
from every source file, including excluded ones — being called from an excluded
file still means the symbol is wired in, so it should not be flagged.

## Acting on a finding

```
src/health/probe.py:88: get_extraction_health() — tested but never called in production (incomplete integration)
```

Three outcomes are legitimate:

1. **Wire it up.** The usual answer — the caller was the missing work.
2. **Delete it.** If the feature was abandoned, the test is keeping dead code
   alive. Remove both.
3. **Export it.** If it is genuinely a public API for another repo, add it to
   `__all__`, which both silences D12 and documents the intent.

Adding it to `d12_baseline` is a fourth option, but it is a deferral, not a
resolution. Prefer one of the three above.

D12 feeds the triage layer's `WIRE` verdict — see
[triage_signals.md](triage_signals.md) if you consume `custodian-triage`.

## What this is not

- **Not** a coverage tool. D12 says nothing about whether a symbol is *well*
  tested, only about who references it. See
  [coverage_adapter.md](coverage_adapter.md) for execution coverage.
- **Not** a dead-code detector. A symbol nothing references is D1/D5/Vulture's
  job; D12 deliberately skips it.
- **Not** call-graph accurate. Matching is by name, not by resolved binding, so
  dynamic dispatch, `getattr`, and registry-driven invocation all read as
  references.
