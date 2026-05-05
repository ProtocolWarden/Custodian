# Triage Signals — From Detector Findings to Action

Each Custodian detector flags one symptom in isolation. The triage layer
joins those findings per file and answers the next-action question:
**delete, complete, wire, redesign, or clean up?**

Three ways to use it, lightest first:

1. **Read the matrix below** and apply it by hand from `custodian-audit` output.
2. **Run `custodian triage <audit.json>`** to get per-file verdicts.
3. **Set `audit.triage: true`** in `.custodian/config.yaml` to embed
   `TRIAGE_*` patterns in every audit run.

## The Decision Matrix

| Verdict      | Trigger (any detector ID in the bucket fires for the file)                                                                                                                                                                                       |
|--------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **DELETE**   | (`D1` ∪ `D5` ∪ `F1` ∪ `F2` ∪ `VULTURE`) **AND** (`U1` ∪ `U2` ∪ `U3` ∪ `D3`)<br>or any uncalled-symbol signal alone — code is dead, remove it.                                                                                                    |
| **IMPLEMENT**| (`U1` ∪ `U2` ∪ `U3` ∪ `D3`) **AND NOT** uncalled — stub body but reachable; finish the work.                                                                                                                                                     |
| **WIRE**     | `D6` ∪ `U4` ∪ `VF6` — implementation exists but isn't connected (class never constructed, Protocol contract not met, stage class not in pipeline registry).                                                                                      |
| **REDESIGN** | `C29` **AND** `C33` — file is over the size threshold *and* has high TODO/FIXME density. Bloat + debt = split or rewrite.                                                                                                                        |
| **CLEANUP**  | `C34` ∪ `G1` ∪ `C8` — commented-out def/class/@decorator, TODO references to ghost names, or stale handler refs.                                                                                                                                  |

Verdicts are not exclusive — a file can earn `WIRE + CLEANUP` for example.
The first verdict in the list is the strongest recommendation, sorted by
priority: DELETE > IMPLEMENT > WIRE > REDESIGN > CLEANUP.

## Why this exists

Custodian's individual detectors each produce one row of evidence. The
human reading the report still has to ask "what do I *do* with this
file?" — combining `U1` (it's a stub) with `D1` (nobody calls it) to
conclude "this should just be deleted." Triage encodes that combination
once so the answer arrives pre-baked.

## Tuning

The buckets live in `src/custodian/triage/matrix.py`. They are
intentionally conservative:

- `_UNCALLED` only includes detectors with low false-positive rates
  (Vulture confidence ≥ 80). If you turn Vulture down to 60 the
  IMPLEMENT/DELETE balance shifts.
- `_BLOAT` + `_NOISE` requires *both* to fire — bloated files with no
  ghost work are usually fine; noisy small files don't need a redesign.
- `_DEAD_TEXT` is its own verdict (CLEANUP) rather than a vote toward
  DELETE — commented-out code is cosmetic, not structural.

Update `docs/usage/triage_signals.md` whenever you change the matrix.

## Limitations

- **File-level only.** The triage layer does not split verdicts per
  symbol; a file with one dead function and one valid one is reported
  once. Per-symbol triage is plausible but requires structured findings
  (symbol name in addition to file:line) which the current samples
  don't carry.
- **Adapter findings count.** Vulture, Ruff, and ty findings flow
  through the same parser. A Vulture-only signal will tip a file into
  `DELETE` even if no native detector fires.
- **Order of inputs is the order of patterns in the audit JSON.** The
  joiner is deterministic given the same input.
