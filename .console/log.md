# Log

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

_Chronological continuity log. Decisions, stop points, what changed and why._

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

## 2026-07-10 — fix(c32): reject punctuation-only values as credentials

C32 (hardcoded credential) fired a HIGH false positive on a downstream repo's
`_TOKEN_STRIP = ".,!?;:\"'()—-"` — the name contains "token" so `_is_credential_name`
matched, and the punctuation value passed `_is_real_credential` (not a placeholder,
not a URL, not ALL_CAPS). A real secret carries alphanumeric entropy; a value with
zero alphanumeric characters can never be a credential. Added that guard to
`_is_real_credential` + a regression test (`test_c32_skips_punctuation_only_value`).
12 C32 tests pass.

## 2026-06-20 — feat: INJ1 prompt-injection signature detector

New audit_kit detector (HARNESS_TRUST_HARDENING §2.2.6, the outer INJ layer):
detect_inj1 scans tracked text for invisible/bidi control characters (the
unambiguous injection/homoglyph-smuggling signal). Mirrors the boundary-detector
shape; wired into the runner as deprecated=True so it is SKIPPED by the default
gate (opt-in via --only INJ1 --include-deprecated) — a repo's own injection-
handling code must not red the fleet-wide audit. Reports codepoint+position only
(never surrounding text, D-INJ-3); legitimate handlers opt out via a
custodian:allow-invisible-chars content marker; \u escapes so it never
self-triggers. 7 tests; full suite 1126 passed.

## 2026-06-18 — fix: pattern-collision masking + content-less B2 message

`run_audit`/`_run_adapters` did `result.patterns[id] = entry`, so when two
detector families ship the same ID (builtin readme R1/R2 vs reconcile R1/R2,
plus a repo's custom plugin R1/R2), a later count-0 instance silently
overwrote an earlier instance that *found something* — while `total_findings`
(summed separately) still counted it. Net: a "phantom" finding invisible in the
patterns map/`findings()`. It masked a real OC boundary-leak (R2 scrub-target).
Added `AuditResult.add_pattern()` that merges on collision (sum count, dedupe
samples, max severity, flag `collision`) and routed both registration sites
through it. Zero pass/fail blast radius: `total_findings` is computed identically
(pre-storage sum); only the visible patterns change — masked findings now show.
Also: `detect_b2` now distinguishes a *content-less* artifact (provided + parsed,
zero forbidden_names — a secret/data fix) from *not-provided* (a config fix).

## 2026-06-18 — cleanup: delete orphan Phase-1/5 scaffold modules

Ecosystem remediation. Removed never-wired scaffold: core/runner.py, policy/
filter.py, policy/architecture.py — zero src importers (cross-repo verified),
superseded by cli/runner.py + detectors/structure.py. Deleted their 4 coupled
test files; rewrote test_adapter_base.py to cover the LIVE ToolAdapter base +
find_tool directly (only test-referenced via orphan pipeline → would trip T1).
Also removed the now-stale audit.exclude_paths.D12 entries for the deleted files
(doctor flagged them as stale globs). 1119 tests green; doctor + audit clean.

## 2026-06-18 — fix(gate): refuse unknown --only ids (close the silent-skip)

`run_detectors` filtered `--only` ids with no validation: `--only D12,DC10`
naming a detector the install lacks (version skew, typo, removed) filtered to an
EMPTY set and passed green — indistinguishable from "ran clean". Exactly how a
stale install silently disarmed OC's #313 gate. runner.py now validates `only`
against built ids and raises on any unknown id; multi.py turns that into a
non-zero exit. Self-verifying. 2 tests updated (old "unknown→empty" was the bug) + 1 added.

## 2026-06-18 — feat(DC10): claims-integrated-while-deferring detector (opt-in)

The planner-level #313 catch: a doc claims a feature wired end-to-end / fully
integrated while the SAME doc defers the integration ("not yet wired", "update X
to call Y()", "integration deferred"). Narrow + low-FP (skips legit "stage N done,
stage N+1 next"): OC=3, Custodian=0. Opt-in (deprecated=True) + audit.dc10_baseline
ratchet; doctor knows dc10_baseline/dc10_scan_globs. 8 tests; suite 1162 green.

## 2026-06-18 — fix(doctor): register d12_baseline as a known audit key

Doctor --strict warned `unknown audit key 'd12_baseline'` (it was added in #44 but
not registered). Added it to `_KNOWN_AUDIT_KEYS`. 22 doctor tests; ruff clean.

## 2026-06-17 — feat(D12): baseline ratchet (audit.d12_baseline)

D12 reads `audit.d12_baseline` (accepted names) and skips them — a repo enables
D12 on a backlog with only NEW tested-but-unwired symbols firing. 10 D12 tests.

## 2026-06-17 — D12 ships OPT-IN (default-off) — was red-walling consumers

D12 (the new tested-but-never-wired detector) was default-ON. Consumers audit
against Custodian@main (e.g. OperationsCenter's custodian-audit.yml installs
`custodian @ ...@main`), so the moment D12 merged it ran on EVERY consumer and
failed their `custodian-multi --fail-on-findings` gate on their existing backlog
(OC: 161 tested-but-unwired public symbols — a mix of public API not in __all__
and genuine gaps). A mature repo can't be hard-gated on a 161-deep day-one
backlog. Flipped D12 to `deprecated=True` — reused purely as the "skipped by
default, opt-in via --include-deprecated" lever (NOT tool-deprecated; there is no
Vulture/ty equivalent). Consumers opt in (or this flips back to default-on) after
they've baselined / burned down the backlog. Detector unchanged + validated;
1153 tests green. Verified OC audit drops 161 → 0 (only the environmental B2
remains, which CI satisfies with its boundary artifact).

## 2026-06-17 — D12 precision: skip pytest_* plugin hooks (FP class)

D12 was flagging `pytest_addoption`/`pytest_configure` and other `pytest_*`
functions — pytest plugin hooks invoked by pytest's plugin system BY NAME, so
there is no in-repo caller by design (not an integration gap). Added a
`pytest_*` skip alongside the existing `test_*` skip. Found during the
OperationsCenter D12 triage (176 → 171 findings after the fix). 9 D12 tests
(added pytest-hook-skipped); ruff+ty clean.

<!-- Reconciled 2026-08-03 (RC1): `## Stop Points`, `## Recent Decisions`
     (2026-05 material) and entries through 2026-06-17 pruned to stay under the
     400-line budget. Full history is in git — `git log -p .console/log.md`. -->
