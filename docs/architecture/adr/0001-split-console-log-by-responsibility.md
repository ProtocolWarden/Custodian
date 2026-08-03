---
status: proposed
date: 2026-08-03
deciders: ContextLifecycle (spec owner), Custodian (proposer)
supersedes: none
---

# 0001 — Split `.console/log.md` by responsibility

## Status

**Proposed.** Custodian cannot adopt this unilaterally: `.console/` is defined by
the console-reconciliation spec, which ContextLifecycle owns (`cl reconcile`,
`context_lifecycle/reconcile/privacy.py`). Custodian implements two of the spec's
gates — RC1 (log line budget) and RC2 (scrub-target leak) — so a change here is a
change to what those gates enforce fleet-wide. This ADR is the request; the
decision is the spec owner's.

## Context

`.console/log.md` is a single append-at-top Markdown file, mandatory on every
source commit (pre-commit hook) and capped at 400 lines (RC1,
`_DEFAULT_R1_LINE_BUDGET`, glob `.console/*.md`).

Its own guidelines list four triggers for an entry:

> - A decision was made (chose approach A over B, deferred X, excluded Y)
> - A bug was fixed and the root cause is non-obvious
> - A detector, feature, or API was added or removed
> - Work is stopping and will resume next session (note where you left off)

The first three describe a **commit message**. Only the fourth is log-shaped.
That mismatch is the root of everything below.

### Measured, not asserted

- **13 of 19** entries in the current log have a matching commit subject on
  `main`. Roughly two-thirds of the file is prose that also exists in git,
  written twice by the same author in the same sitting.
- **Three consecutive PRs** (#66, #67, #69) each had to prune history to land.
  After #68, `main` sat at **399 of 400** lines — one line of headroom, so the
  next commit to touch source was guaranteed to pay the tax.
- **The file is a conflict magnet by construction.** Every branch appends to the
  same region, so the second of any two parallel PRs conflicts. #66 hit this.
- **Prose conflicts fail quietly.** Resolving #66's conflict silently stranded
  the file's tagline mid-document and dropped a section header's blank line.
  Neither broke a test, a lint, or a gate; both survived onto `main` and were
  found later by eye. A code conflict of the same shape would not have.
- **Pruning destroys the value that justifies the file.** The D12 entry
  ("ships OPT-IN — was red-walling consumers") directly shaped C16's
  default-off design in #69. Entries from that era are now pruned out of the
  working copy — the reasoning survives only in git, which is exactly where the
  duplicated two-thirds already lived.

### The structural problem

Two rules pull in opposite directions:

| Rule | Effect |
| --- | --- |
| Pre-commit hook | Log **must grow** on every source commit |
| RC1 line budget | Log **must not exceed** 400 lines |

Their intersection is "every contributor prunes history as a precondition for
committing." Reconciliation stops being a scheduled, deliberate pass and becomes
an unplanned tax on whoever commits when the file is near the cap. That is not a
discipline failure — it is what the two rules jointly specify.

## Decision drivers

1. Keep the content that is genuinely load-bearing. Cross-repo deferrals and
   design precedents were read and acted on repeatedly this session.
2. Stop paying for the same prose twice.
3. Remove the shared-file conflict surface.
4. Do not lose history as a side effect of routine work.
5. Stay inside the spec's shape where possible — RC2, privacy scrubbing, and
   Layer C archival to the private manifest are all worth keeping as-is.

## Options considered

### A. Do nothing

Zero migration cost. But the failure modes above are structural, so they recur
at the same rate, and the quiet-corruption one is unbounded: nobody notices a
mangled prose merge until they need the entry.

### B. Raise or remove the RC1 budget

One-line change. Removes the pruning tax, but keeps the duplication and the
conflict surface, and lets an unbounded file accumulate until it is too long to
be read — at which point its value is zero anyway.

### C. Shard by month — `.console/log/2026-08.md`

Cheap and squarely inside the spec's shape. Parallel branches in different
months stop colliding; each file carries its own budget; archival becomes
"the month rolled over" instead of "someone hit the cap." Requires widening
RC1's glob from `.console/*.md` to `.console/**/*.md`.

Does not address duplication, and same-month branches still collide — which is
most branches, most of the time.

### D. Split by responsibility (**recommended**)

Route each of the four jobs to the medium that already fits it:

| Job | Home | Why |
| --- | --- | --- |
| Change rationale | Commit message | Already written there. Per-commit, so it cannot conflict; never pruned. |
| Durable decisions | ADR (`docs/architecture/adr/`) | One file per decision — no shared region, no budget, linkable. DC1/DC3/DC7 already enforce front matter, naming and orphans. |
| Session continuity | `.console/log.md` | What the guidelines actually describe. Stays small on its own; RC1 stops binding. |
| Reconciliation ledger | `cl reconcile` / RC2 | Unchanged. |

The pre-commit hook changes from *"you also edited `log.md`"* to *"your commit
message is substantive."* This repo already writes commit messages that clear
that bar — #62's is a full essay, and it is what told a later contributor
exactly which adapters it had and had not covered.

## Recommendation

Adopt **D**, with **C** as the fallback if the spec owner wants to keep the
single-log shape. They compose: sharding is still worth doing to
`.console/log.md` under D if session-continuity notes ever grow.

## Consequences

**Gained.** Duplication ends. The conflict surface disappears for three of the
four jobs. History stops being deleted to make room. Decisions become linkable
and greppable instead of scrolling past in a chronological wall.

**Lost.** The single-file chronological narrative — "what happened in this repo,
newest first" — no longer exists as a file. If that view is wanted, generate it
from `git log` rather than hand-maintaining it; generated files can be
regenerated, so they never conflict and never need pruning.

**Cost.** Existing `log.md` entries worth keeping must be promoted to ADRs; the
rest stay in git history. The hook and RC1 need changing in whatever repo owns
them. Consumers with `reconcile_enforce: true` see RC1 stop firing, which is the
intended outcome, not a regression.

**Risk.** "Substantive commit message" is weaker to enforce mechanically than
"file was edited." A length floor is a poor proxy for quality. Mitigation: keep
the hook advisory for message quality and let review carry it — the current hook
does not check entry *quality* either, only that the file changed.

## The ask

For ContextLifecycle, as spec owner:

1. Should the per-commit `log.md` mandate be narrowed to session continuity,
   with change rationale delegated to commit messages? (Options D vs A.)
2. If the single-file shape is to be kept, may RC1's glob widen to
   `.console/**/*.md` so repos can shard by month? (Option C.)
3. Either way — should RC1's budget stay a *commit-blocking* gate, or become an
   advisory signal that a scheduled `cl reconcile` acts on? The pruning tax
   comes from the blocking behaviour, not from the budget itself.

Custodian will implement whichever shape is chosen and keep dogfooding it; the
detectors are cheap to adjust. What Custodian should not do is diverge from the
spec locally, which is why this is a question rather than a patch.

## References

- Console-reconciliation spec §3.3 / §6 (Layer A/B/C) — ContextLifecycle
- `context_lifecycle/reconcile/privacy.py` — Layer C archival destination
- `src/custodian/audit_kit/detectors/reconcile.py` — RC1/RC2 implementation
- `.hooks/pre-commit` — the per-commit log mandate
- Custodian #65 — pruned history belongs in the private manifest, not `.console/archive/`
- Custodian #66, #67, #69 — the three consecutive PRs that each pruned to land
