# Log

_Chronological continuity log. Decisions, stop points, what changed and why._

## 2026-08-04 — fix(tests): stop the suite reading ambient env config

`REPOGRAPH_BOUNDARY_ARTIFACT_FILE` leaked from the caller's shell into every test.
Two that assert the "no artifact configured" path were directly contradicted by it:

    test_reconcile.py::TestAC1SingleSourceOfTruth::test_no_artifact_no_scrub_targets
    test_boundary_detectors.py::TestB2Required::test_b2_flags_missing_required_boundary_source

The exposure was two modules, not the one reported — worth checking for, because
the second was in a file that already knows about the variable (it calls
`monkeypatch.setenv` at line 71) and still had a test that inherited it.

Backwards in the way that matters: the variable is legitimately exported by anyone
who runs the audit locally or pushes through `.hooks/pre-push`, and absent in CI. So
a developer with a *working* setup saw red while CI stayed green. That is the
failure mode that teaches people to ignore their own test results.

Fixed with an autouse fixture in `tests/conftest.py` that clears the variable for
every test, rather than a `delenv` at the two call sites. The defect is that the
suite reads ambient config at all; patching the two known victims leaves the next
artifact-sensitive test to rediscover it. Tests that *want* the variable still set it
explicitly with `monkeypatch.setenv`, which is unaffected.

New `tests/test_env_isolation.py` pins the fixture, because without it a later
refactor could drop the fixture and the only symptom would be a suite that passes in
CI and fails on the machines of the people most likely to run it. `conftest` builds
its list from `boundary._ARTIFACT_FILE_ENV` rather than a literal, so renaming the
variable in the detector cannot leave the isolation silently covering nothing.

Two self-inflicted detours worth recording, both caught by tooling rather than by
me:

- The first draft asserted only on `os.environ` and tripped our own **T8** — a test
  file importing nothing from any src package. Fair catch; it was testing Python, not
  Custodian.
- The second imported the list via `from tests.conftest import ...` and passed
  locally but **failed collection in CI**: `No module named 'tests'`. `tests/` has no
  `__init__.py`, so that name resolves only when the repo root is on `sys.path` —
  true under `python -m pytest`, which is what I verified with, and false under the
  bare `pytest` CI runs. The lesson is the same one this entry is about: verifying
  through a different entry point than CI uses hides exactly the class of bug being
  fixed. Resolved by inverting the dependency — conftest derives the name from the
  detector, and the test imports only from `custodian`, so no test→conftest import
  exists to be fragile.

Verified through the CI invocation this time — bare `pytest -q`, with the variable
set and unset, plus `python -m pytest`: 1241 passed, 5 skipped, identical across all
three. Pre-existing at origin/main; not caused by #72, which observed it and
deliberately left it alone to stay focused.

## 2026-08-04 — chore(config): raise our own r1_line_budget to 1000, and say why

`.console/log.md` sat at 396 against a 400 budget, so the next entry anyone wrote
red-failed our own audit. That is not hypothetical: it happened to #72 on
2026-08-03 (437 lines), and was cleared only by pruning the two oldest surviving
entries and condensing the new one — buying four lines. Three PRs before it (#66,
#67, #69) each pruned to land. The tax is structural, not a discipline problem: the
pre-commit hook requires log.md to grow on every source commit and RC1 caps it, so
their intersection is "delete history as a precondition for committing."

Considered and rejected two of the three obvious routes.

**Implement ADR 0001.** Not ours to do. The ADR says so in its own Status section:
`.console/` is defined by the console-reconciliation spec, ContextLifecycle owns it,
and RC1/RC2 are our implementation of the spec's gates — so adopting Option D here
changes what those gates enforce fleet-wide. The ADR is the ask; the decision is the
spec owner's. It is still `proposed`. Patching around an open question we ourselves
raised would be the worst of both.

**Add an archive file RC1 does not count.** #65 already reverted exactly this.
Pruned `.console/` history goes to
`<private-manifest>/archive/console/<repo>/<file>-<cutoff>.md` via `cl reconcile`
(spec §3.3 / Layer C); a second local archive is an orphan the tool never maintains.
Worse, RC1's glob is `.console/*.md` — top level only — so sharding into
`.console/log/2026-08.md` would not reduce the count, it would remove the file from
the gate's view entirely. Silently relocating content out of a control's reach is
not archiving; it is disabling the control and leaving it looking green. We removed
`|| true` from a consumer's audit install last week for being that same shape.

**Raise our own budget.** `audit.r1_line_budget` is a documented per-repo knob, read
by `detect_r1` and defaulted, not hardcoded — so this touches no detector, no spec,
and no other repo. It is also what the detector intends: its docstring calls R1
"LOW/advisory — a reconciliation due signal, no judgement about *what* to prune."
400 is right for an operator workspace whose log is session-continuity notes. Ours
is a different artifact — it documents detector semantics consumers depend on, which
is why entries run ~30 lines and why pruning has already cost us something real (the
D12 entry that shaped C16's default-off design is now only in git). 1000 gives about
20 entries of runway, which puts reconciliation back on a scheduled cadence instead
of every other commit. Still bounded, still gated, still archived by `cl reconcile`
when it fires.

Explicitly interim. The fix is ADR 0001 landing one way or the other; this stops the
bleeding without pre-empting it, and preserves the history that decision is about.
Sized so that writing this entry does not itself trip the gate — the failure mode
that prompted it.

## 2026-08-03 — fix(adapters): find_tool must prefer the AUDITED repo's venv

`find_tool()` resolved tools from the venv **Custodian itself** runs in, then PATH.
For a multi-repo auditor that is backwards: each repo pins the toolchain its config
was written against. A globally-installed `custodian-multi` therefore audited
OperationsCenter (pins `ruff==0.15.13`) with a system-wide ruff 0.16.1 and reported
**1222 phantom findings** against a tree OC's own `ruff check` calls clean. Right by
accident when Custodian is installed into the audited repo's venv, silently wrong
otherwise — and silent is the problem, since the output is a plausible wall of real
rule codes. Same three lines hid a second bug: that lookup can never match on
Windows, where scripts are `ruff.exe` under `Scripts/`, so the branch was dead code
there. Order is now audited repo's venv → Custodian's venv → PATH, with both
script-dir spellings and Windows suffixes handled. Scoped by a ContextVar +
`audited_repo()` rather than a parameter because `is_available()` takes no arguments
and must agree with `run()`. 1238 passed, 5 skipped; 6 new tests, including that the
ContextVar cannot leak across repos in a `--repos a b c` run. Details in PR #72.

Pre-existing, noted not fixed: `tests/test_reconcile.py` does not isolate
`$REPOGRAPH_BOUNDARY_ARTIFACT_FILE`, so two tests fail when it is set.

## 2026-08-03 — docs(adr): ask ContextLifecycle to split .console/log.md

ADR 0001, status proposed. Custodian implements RC1/RC2 but does not own the
console-reconciliation spec, so this is a request to the owner rather than a
patch — diverging locally would be worse than the problem.

The argument, measured rather than asserted: 13 of 19 entries in this file have
a matching commit subject on main, so two-thirds of it is prose written twice.
The pre-commit hook mandates growth and RC1 caps it at 400, and the
intersection of those two rules is "every contributor prunes history to be
allowed to commit" — #66, #67 and #69 each pruned to land, and main sat at
399/400 before this entry. Writing the ADR needed one more prune, which is the
cleanest evidence available that the tax is structural.

Two failure modes worth recording separately from the tax. A single
append-at-top file conflicts on every parallel branch by construction, and
prose conflicts fail *quietly* — resolving #66's stranded the file tagline
mid-document and dropped a header's blank line, and both reached main without
tripping a test, a lint or a gate. Second, pruning deletes exactly what earns
the file its keep: D12's "ships OPT-IN — was red-walling consumers" shaped
C16's default in #69, and entries from that era are now gone from the working
copy.

Recommends splitting by responsibility — rationale to commit messages (already
written there), durable decisions to ADRs (DC1/DC3/DC7 already police them),
continuity staying here, reconciliation unchanged — with month-sharding as the
fallback if the single-file shape is kept, which needs RC1's glob widened to
`.console/**/*.md`. Third question in the ADR is the load-bearing one: whether
RC1 should block commits at all, or be advisory input to a scheduled pass.

## 2026-08-03 — feat(C16): scan tests/ behind an opt-in, and clear our own backlog

C16 flags `read_text`/`write_text` without `encoding=`, and it never looked at
`tests/` — `_py_files` walks `src_root` only. That is precisely where the
defect hides: a fixture writing ASCII passes on every platform, and the day
someone adds a non-ASCII character it fails only where the locale cannot
encode it. #67 fixed three tests that broke on Windows exactly that way while
C16 reported clean. The detector for the bug could not see the bug.

Opt-in via `audit.c16_scan_tests`, default off, following D12's precedent:
any repo with an existing suite would light up on first upgrade, and
`--fail-on-findings` treats a LOW finding as a failure, so default-on would
red-wall every consumer. Flip it once the backlog is clear.

Custodian flips it, and the backlog is cleared rather than baselined — 149
sites across 17 files. A `d12_baseline`-style ratchet was the alternative, but
the fix here is mechanical and total (`encoding="utf-8"`), so a 149-entry
baseline would have been permanent clutter recording work that took one pass.
Applied by AST position, back-to-front per file so offsets stay valid, with
the separator chosen by looking back past whitespace so trailing-comma and
zero-arg call shapes stay syntactically valid; every file was re-parsed before
being written. Suite unchanged at 1222 passing, so nothing depended on the
platform default encoding.

`include_tests` lives on `_py_files` rather than in `detect_c16` so the
exclude-glob path stays shared — `exclude_paths.C16` applies to test files
too. It deduplicates by resolved path rather than testing "is tests_root under
src_root", which also covers symlinks and `./` spellings; the nested-layout
test fails without it.

Not made default and not extended to other C-class rules: most encode
production concerns (no `print()`, no bare `assert`) that are deliberately
fine in tests. Only rules whose defect is platform-portability should widen.

## 2026-08-03 — docs: write up the three opt-in detectors that had none

INJ1, DC10 and D12 shipped with zero documentation — 0 hits for each across
`docs/` and `README.md`. Surfaced by `cl reconcile check`, whose DOC GAP gate
refuses to archive a done item lacking a durable doc, leaving the whole 2026-06
log backlog unreconcilable. The gate was right; the docs were the debt.

Two usage pages (`prompt_injection_signatures.md`, `incomplete_integration.md`),
a DC10 section in `doc_conventions.md`, and a matrix table covering all three
under a new "opt-in detectors" heading — they share one property worth stating
once: `deprecated=True` here is the off-by-default lever, NOT tool replacement.
The flag reads as "superseded" and all three are current; worth a rename later.

Claims checked against source, not memory: INJ1's 16 codepoints diffed against
`_INVISIBLE` (exact, no drift), DC10's regexes exercised to confirm a bare
"done" does not fire and staged work does not either, and every D12 behaviour
written up has a named test — including the excludes asymmetry, where a
reference in an excluded file still clears a symbol.

Docs index updated, since an unindexed page under `docs/` trips its own
detector; it also claimed DC1-DC8 while the page covered DC1-DC5. Unblocks the
June reconciliation: those three items can now carry real `doc:` paths.

## 2026-08-03 — fix(samples): detector sample paths, the half #62 deferred

#62 fixed the adapter half and named what it left: "detector-side samples still
stringify natively (~50 sites), so on Windows triage still sees one file under
two keys." This is that half.

Triage groups per file by the raw path string parsed out of a sample, so one
file must have exactly one spelling across every producer. Detectors formatted
`path.relative_to(repo_root)` straight in, and `str(WindowsPath)` yields
backslashes. Fixed at ~50 sites across 14 modules, following the sites that
already called `.as_posix()`. Where `rel` is also needed as a Path (`.parts`,
glob matching) it stays a Path and the sample posix-ifies at the f-string,
rather than converting early and forcing the matcher to re-parse a string.

One adapter gap remains after #62, and it is the branch that matters most:
#62 changed the happy path, but `relative_to()` *raises* for ruff, mypy,
vulture and semgrep, because they run with `cwd=repo_path` and report
cwd-relative paths. The `except` clause decides the spelling for those tools
and it returned the string verbatim. Observed directly: with the happy path
already fixed, vulture still emitted `src\pkg\...` beside ruff's `src/pkg/...`.
ty has the same hole in its own fallback. Both branches normalise now.

Found while sweeping: C1, C6, C8, C13 and C28 interpolated the *absolute* path,
never relativising at all. Different failure — the joiner's regex breaks at the
drive-letter colon, so on Windows those findings were dropped from triage
entirely rather than misfiled, and on POSIX they formed a third key for the
same file. `_count_pattern` gains a required `repo_root` keyword.

Also `tests_rel` in C13, which built its allowlist globs with `str()`. Latent —
it only bites when `tests_root` is nested — but the same class as #55 and #62.

The regression test follows #62's rule, since `str()` and `as_posix()` are
indistinguishable on the only platform that gates merges: `PureWindowsPath`
drives real Windows semantics on any host for the detector helper and both
adapter branches, and the absolute-path assertions hold everywhere. Each fix
was reverted in turn to confirm the suite catches it. The detector-side
separator assertions stay Windows-only — closing that needs a static check over
sample construction, and a half-covering one buys false confidence — so the
module docstring names the limit rather than hiding it.

## 2026-08-03 — fix(tests): the seven failures that only ever appear off Linux CI

CI runs ubuntu-only, so seven tests were red on Windows and invisible to every
gate. They are two unrelated causes, and neither is really "a Windows bug".

Three are locale encoding. `write_text()` without `encoding=` uses the platform
default — cp1252 here — so `test_x_cross_repo` and `test_x1_cross_repo` raised
UnicodeEncodeError writing a `→`. D11's was the interesting one: its `_ctx`
helper wrote an em dash the same way, `build_ast_forest` read it back as utf-8,
the decode failed, and the file was *silently skipped* — so the detector
reported zero clones and the test failed on a count, giving no hint that an
encoding was involved. Fixed at the three sites that carry non-ASCII.

C16 already flags exactly this (`Path.read_text/write_text` without
`encoding=`), but `_py_files` only walks `src_root`, so the 189 occurrences
under `tests/` are invisible to it. Widening C16 to tests is a real change with
its own noise budget, so it is left alone here and noted instead.

The other four are not Windows at all: the repograph gate shells out to
ripgrep, CI installs it explicitly, and this machine has no `rg`. A missing
binary surfaced as a bare `FileNotFoundError` from Popen — WinError 2, no
mention of ripgrep — so `_rg` now checks first and says what to install.
Failing loudly stays right for a gate; returning `[]` would read as "no
violations" and let the boundary go unchecked. The tests skip when `rg` is
absent rather than reporting red for a missing tool.

Found while reading that code: `hit.split(":", 1)[0]` takes the drive letter on
Windows, so every gate finding reported `C` as its file and the `/report/` and
self-exclusion filters silently stopped matching — suppressed hits would have
been reported as violations. `_hit_path` handles the drive prefix, and its test
uses literal strings so POSIX CI catches a regression too. That defect is not
one of the seven; it never failed a test because the tests assert on `rule_id`.

## 2026-08-03 — revert(console): pruned history belongs in the private manifest

#64 un-ignored `.console/archive/` and committed the 2026-05 log sections there.
Wrong destination. Per console-reconciliation spec §3.3 / Layer C, `cl reconcile`
writes pruned `.console/` history to
`<private-manifest>/archive/console/<repo>/<file>-<cutoff>.md` — see
`context_lifecycle/reconcile/privacy.py`, which resolves that root via
`$PRIVATE_MANIFEST_DIR` or RepoGraph discovery (never a hardcoded repo name, per
boundary rule I2) and raises `PrivateArchiveUnavailable` rather than degrading to
any local path. This repo already has archives there from two prior passes:
`archive/console/Custodian/log-2026-06-04.md` and `log-2026-06-16.md`.

So `.console/archive/` was not untracked scaffolding that happened to be
convenient to reclaim — it is ignored *because* the destination is a private repo,
and nothing writes to it locally. #64 created a second archive location that
`cl reconcile` does not know about and will never maintain, and kept in a public
repo a class of content the design routes to a private one.

Nothing leaked: the content was already tracked and public in `log.md`, and RC2
reads it at 0 findings. The defect is process, not exposure — but an orphan archive
that diverges from the tool's destination is worth removing while it is one commit
old rather than after `cl reconcile` next runs and the two disagree.

Reverted to the prune-with-pointer form #62 and the 2026-08-02 pass both used;
history stays reachable via `git log -p`. The ignore line now carries the §3.3
citation and a pointer to `cl reconcile`, since the bare path with no rationale is
what made it look reclaimable. Note the misleading adjacency that started this: the
§3.1 comment at the top of that block governs `reconcile.yaml`, not `archive/`.

log.md 326 -> 357 lines, still inside the 400 budget but close enough that the next
entry likely needs a real `cl reconcile` pass.

## 2026-08-03 — fix(config): retire audit.ignore_paths rather than implement it

`audit.ignore_paths` was parsed into `policy` by both config-shape branches and
printed by `config_summary`, but nothing ever read it to filter a finding. A repo
writing `ignore_paths: ["src/legacy/**"]` saw the globs echoed back in the config
summary — which reads as confirmation the exemption landed — while every finding
under that path kept reporting. Parse-and-display with no application is worse
than an unknown key, which `doctor` at least warns about.

Removed rather than implemented, because detector findings carry no structured
path. `DetectorResult` is `(count, samples)` where samples are free-form strings
capped at 8 with inconsistent shapes — absolute paths, repo-relative paths, and
non-path prefixes like `docs:` / `README.md:`. A path filter could drop matching
samples but never correct `count`, so a detector with 500 findings all under an
ignored path would report `count=500, samples=[]` — a silent-green path of the
same family as the `--only` unknown-id guard and ty's docker exit-127 case.
Implementing it for adapters only (whose `Finding` does carry `.path`) would
reproduce the original bug: the key would work for RUFF and silently not for C1.

`audit.exclude_paths` is the real mechanism — per-detector, POSIX-normalized via
`_norm_rel`, validated by `doctor`. `config_summary` now warns instead of echoing,
and `custodian-config migrate` says so out loud since it rewrites the file. No
`.custodian/config.yaml` in any of the eight sibling repos sets `ignore_paths`,
so nothing changes behaviour anywhere; the key was dead on arrival fleet-wide.

Worth noting C37 (dead audit-config key) could not catch this: it greps source for
the key name as a string literal, and the dead parse site in `loader.py` supplied
one. Only Custodian's self-audit was fooled — consumer repos would have been flagged.

Reconciliation: `## Stop Points` and `## Recent Decisions` (all 2026-05 material)
moved to `.console/archive/log-2026-05.md`. log.md stood at 398/400 when this was
drafted; #62 pruned and re-grew it to 396, so an entry trips RC1 either way (396 +
39 = 435). The split takes the live log back to ~330 and buys real headroom instead
of shaving rows each time. Archived rather than pruned, unlike the 2026-08-02 and #62 passes:
`.console/archive/**` sits outside RC1's `.console/*.md` glob but still inside RC2's
`.console/**` leak scan, so the content keeps being scrubbed for private names
without consuming the budget. Required un-ignoring `.console/archive/`, which
`.gitignore` had untracked next to a console-reconciliation §3.1 citation —
untracked, the archive would be neither committed nor scanned.

## 2026-08-03 — fix(adapters): emit posix finding paths so globs match on Windows

Four adapters relativised with `str(Path(...).relative_to(repo_path))`, which
stringifies natively, so on Windows a finding named `src\foo\bar.py`. #61 fixed
ty this way while adding docker mode; this is the rest of them, plus coverage.

Checked first whether it actually voided exemptions, since PR #55 fixed that
exact bug on the detector side. For ruff/mypy/semgrep/vulture it does not:
`_run_adapters` formats findings into samples and a count, and no exclusion
filter ever runs on them. Two things fell out of that trace. `audit.ignore_paths`
is dead config — parsed into `policy`, echoed in the config summary, read by
nothing, on every platform. And the ~45 D11 entries a consumer repo carries are
`exclude_paths`, the detector path, which already calls `.as_posix()`.

The coverage adapter is the real break: `_is_excluded` glob-matches its own
`_rel_to_repo` output, and `glob_match` did not normalise separators — #55 added
`_norm_rel` to `code_health._matches_any`, a *different* matcher. So
`tools.coverage.exclude_paths` was a silent no-op on Windows. Fixed the adapter
and hardened `glob_match`, so the invariant holds for all ~27 call sites rather
than each caller remembering `.as_posix()`. Belt-and-braces on purpose: either
layer alone suffices, and the tests prove it by reverting one at a time.

Tests force the flavour to `PureWindowsPath` for the call under test so they
fail on POSIX too. Written the platform-conditional way they would be green on
Linux CI whether or not the fix is present, which is how this survived.

Detector samples still stringify natively (~50 sites), so on Windows triage now
sees one file under two keys — posix from adapters, native from detectors.
Filed separately; that sweep also fixes the c39/c41/t5/t7 failures.

Suite 1178 -> 1193 passed, failures 15 -> 11 on Windows; `ruff check src` clean.

## 2026-08-03 — feat(ty): docker mode, because a host run is unsound not just noisy

`TyAdapter()` took no arguments and shelled out to a host binary; semgrep was
the only adapter that could containerize. For a containerized repo a host run
cannot be correct — the venv is built `--system-site-packages` against the
image's interpreter, so the dependencies sit inside the image and `pyvenv.cfg`
points `home` at a path the host does not have.

Not merely a noisy count: an unresolved import infers as `Unknown`, which
invents attribute errors *and* suppresses real ones. Same tree, same config —
`unresolved-attribute` 303 host / 242 container (61 false positives), and
`invalid-assignment` 55 / 77 (22 real errors the host **misses**). Wrong in
both directions. Different rationale from semgrep's `docker: true` (a tool
that no-ops on Windows); this is a correctness requirement on any host OS.

Targets pass relative to the mount — ty echoes the form it was given, so
diagnostics arrive repo-relative. `mount` and `command` are configurable
because a venv with a hardcoded prefix only resolves at its own mount point.

Two defects found while adding it: `TimeoutExpired` was uncaught, so a slow
tool took down the whole audit instead of reporting one dead adapter; and
finding paths used `str()`, so one file had two spellings (`src/foo.py` from a
container, `src\foo.py` natively on Windows) despite being keyed and exempted
by path — that fixes `test_path_relativized`, already red on main. `mypy`,
`ruff`, `semgrep` and `vulture` share the separator bug, left for their own
change; worth checking whether posix-glob `ignore_paths` silently miss on
Windows, as PR #55 fixed a related glob bug the same way.

Also: `{"enabled": False}` is a truthy dict and the v1 schema spells every
tool that way, so the bare test enabled a disabled tool. Fixed for ty; the
other adapters have the same hole.

Docker mode introduced a fourth silent-green path, so it is guarded: a
non-existent entrypoint exits 127 with output the concise parser skips, which
would have reported a clean tree. ty exits 0 clean and 1 with diagnostics, so
`returncode != 0 and no findings` is unambiguously anomalous and now yields
TOOL_ERROR. This retired a test that asserted the old behaviour — output
claiming "Found 2 diagnostics" that parsed to zero was being swallowed.

## 2026-08-02 — fix(u4): count methods inherited from non-Protocol bases

U4 collected the implementing class's own body only, so the ordinary mixin
shape `class Impl(ConcreteBase, SomeProtocol)` was reported as a Protocol gap
even though Python resolves the method through the MRO. Any consumer using
inheritance to avoid duplicating a method body hit it.

Found from the other direction: a consumer removed a copy-pasted probe body by
inheriting from the class that already had it, D11 went down by one, and U4
went up by one for the same edit.

Two parts. Pass 1 now indexes every class's own methods and bases, and pass 2
walks the non-Protocol ancestor chain. Then, because the base was written
`from m import OpenCVResolutionProbe as _DomainProbe`, name-based lookup still
missed it — classes are indexed by real name, so aliased bases resolved to
nothing. `_import_aliases` maps local alias -> original per module.

Resolution stays name-based and best-effort: a base outside the scanned tree
contributes nothing, which under-reports inherited methods rather than
inventing them. A test covers that direction explicitly so the limitation is
not mistaken for a bug later.

6 new tests; suite 1153 -> 1159, failures unchanged at 16.

## 2026-08-02 — fix(ci): clear the 98 ruff findings that gated both CI jobs

`main` had been red since 2026-07-26 and both failures were one cause: the
`test` job failed on `ruff check src`, and the `audit` job failed because those
same 98 ruff findings are what `--fail-on-findings` counted. Two red jobs, one
fix.

Cleared by autofix where safe (38 I001, 30 SIM102/SIM103, ISC004, PIE810,
UP037) plus explicit `check=False` on the seven adapter `subprocess.run` calls,
which documents that adapters parse output regardless of exit status. RUF034
turned out to be a real bug rather than style: both arms of the markdownlint
`--config` ternary were identical.

12 SIM102 sites keep a `# noqa` carrying its reason — 8 verified per-site as
exceeding the 100-char limit when combined, 4 because a comment between the two
conditions documents the inner test. Reasons were checked programmatically, not
asserted.

The vulture fix (#57) then started surfacing this repo's own dead code, which
would have failed the audit in ruff's place. `_block_terminates` was genuinely
unused and was deleted rather than whitelisted — that is what the detector is
for. The other six are Protocol members, dataclass fields written at
construction and read via serialisation, and dynamically-loaded test fixtures;
they extend `.vulture_whitelist.py` with a reason each.

Note for future work: `--make-whitelist` emits bare *references*
(`plugin_modules`), not assignments. An assignment in a whitelist file is
itself flagged as an unused variable.

Verified: ruff clean, vulture clean, suite unchanged at 1153 passed / 16
pre-existing Windows-only failures, audit 0 findings under CI conditions.

<!-- Reconciled 2026-08-03 (RC1): `## Stop Points`, `## Recent Decisions`
     (2026-05 material) and entries through 2026-06-18 pruned to stay under
     the 400-line budget. Full history is in git — `git log -p .console/log.md`.
     See docs/architecture/adr/0001-split-console-log-by-responsibility.md.
     Second pass, same day: the 2026-06-20 (INJ1 detector) and 2026-07-10
     (C32 punctuation-only values) entries pruned as well — the first pass
     landed at 395/400, leaving no room for the next entry to be written. -->

## Archived

_Archived completed history → `<private-manifest>/archive/console/Custodian/log-2026-08-03.md`_

<!-- Path de-absolutised by hand; see the commit. Re-running prune leaves it. -->
