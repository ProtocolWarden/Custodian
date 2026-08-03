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

# Log

_Chronological continuity log. Decisions, stop points, what changed and why._

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

## 2026-06-17 — feat(D12): incomplete-integration detector (tested but never wired)

New `D12` in `dead_code.py`: a public src function/method REFERENCED BY TESTS but
NEVER by production code — the "built it + tested it but never wired it in"
signal. Uses the `ast_forest` (src) + `tests_forest` (tests) split: a symbol
referenced nowhere is dead code (D1/D5/Vulture); referenced *only by tests* is an
integration gap. Low-FP by construction — skips private/dunder, `test_*`,
decorated defs (CLI commands, @property, fixtures, routes, validators,
@abstractmethod — framework-invoked), `__all__` exports, entry-point names; a
production reference in ANY src file (even an excluded one) clears the symbol.
LOW severity, WIRE verdict (added to triage `_UNWIRED`), exclude via
`audit.exclude_paths.D12`. Motivated by OperationsCenter#313, which auto-merged
with `get_extraction_health()` defined + unit-tested but its STEP-3 caller never
wired — the self-review caught it but it shipped anyway; D12 makes that class of
gap a deterministic finding instead of an LLM-variable review concern. Self-audit
on Custodian found 6 true positives (tested-but-unwired core/policy functions,
0 FP in the sample). 8 tests; full suite 1152 green; ruff(src)+ty+doctor clean.
Those 6 are excluded in `.custodian/config.yaml` (audit.exclude_paths.D12 →
core/runner, core/finding, policy/filter, policy/architecture) — Custodian's own
public API surface, WIRE-verdict not bugs; excluded pending a deliberate
public-API-declaration (`__all__`) pass rather than blocking on the detector that
introduced them.
_Not a task tracker — that's backlog.md. Keep entries concise and dated._

## 2026-06-16 — feat(doctor): config-integrity checks (enforce can't silently vanish)

Two doctor `--strict` checks that catch a gate looking enforced but isn't, without
touching the audit/CI-red path. (1) **Duplicate-key detection** — `find_duplicate_keys`
(loader.py) walks the raw YAML node tree via `compose`, so a second `audit:`/
`capabilities:` block (which `safe_load` silently collapses to last-wins, dropping
an `enforce: true` or suppression — the PrivateManifest incident) is flagged. (2)
**enforce-without-locator** — `capabilities.enforce: true` with no `registry_path`/
`registry_repo`/`cross_repo` locator = enforce-theater (CAP1 can never find the
registry); flagged. NOT flagged: a sibling locator merely absent in single-repo CI
(that skip is by design — the capability-refs venue gate covers it; firing there
would red every owning repo). Verified: all 6 fleet repos still doctor-clean (no
false positives); negative controls fire. The detector-level "make CAP1 fire on
registry-not-found" alternative was rejected — it would red owning repos' single-repo
CI, which skips by design. Survivor #1 from the gate-integrity adversarial pass.

## 2026-06-06 — chore: engine refresh — injection telemetry (CL #26/#27)

`cl context init` refresh of .context/.engine/: route.py gains the injection
telemetry from CL #26 (one JSONL event per surfaced injection to
sessions/.telemetry/injection.jsonl — but note this repo's .context is
session-less, so the telemetry dir appears only if/when injections fire here;
covered by gitignore). cold.py picks up the CLOSED-superseded docstring (CL #27).
Part of the PM context-management completeness-audit train (PM #74).

<!-- Reconciled 2026-08-02 (RC1): entries older than 2026-05-16 pruned to stay
     under the 400-line budget. Full history is in git — `git log -p .console/log.md`. -->

## Stop Points

- Fix forbidden_import_prefix doubled config path (2026-05-07, on `main`): Earlier sed pass over usage docs accidentally rewrote `.custodian.yaml` → `.custodian/config.yaml` on both sides of the "preferred (or legacy fallback)" parenthetical, producing nonsensical `.custodian/config.yaml (or .custodian/config.yaml)`. Restored to single-line mentioning preferred form + legacy fallback.

- Config-path docs refreshed for .custodian/config.yaml (2026-05-07, on `main`): User reported the README and GitHub description still referenced the legacy `.custodian.yaml` single-file path. Updated GitHub description, README, CONTRIBUTING, SECURITY, all 3 ISSUE/PR templates, design/detector_disposition_matrix, and usage/forbidden_import_prefix to the preferred `.custodian/config.yaml` layout. README now explicitly documents the legacy form as a backwards-compat fallback (loader supports both).

- R6 — docs index detector (2026-05-07, on `main`): Added R6 to the readme detector class. R6 fires when `docs/` exists at repo root but `docs/README.md` does not — flagging unindexed doc trees. 3 new tests; full Custodian suite 815 ✓. Used to drive doc-index creation in 6 platform repos (OC, OperatorConsole, SwitchBoard, WorkStation, Custodian, CxRP) — a private platform repo already had one; RxP/ER/SR have no docs/ and are skipped silently. README's R-class count bumped 5 → 6.

- README opening standardized in own repo (2026-05-06, on `main`): Self-applied the new R3/R4 convention. Custodian's README now leads with `## What this repo is` (detector framework, adapters, plugin loader, CLI, schema-stable JSON) and `## What this repo is not` (not a linter, not a test runner, not repo-specific).

- R-class README detectors landed (2026-05-06, on `main`): New `audit_kit/detectors/readme.py` adds R1-R5 enforcing README structural conventions: file present, H1 matches repo name (allowing "RepoName — tagline" form), `## What X is` H2, `## What X is not` H2, non-empty intro paragraph (badges don't count). All LOW severity, no analysis pass needed. 22 unit tests + wired into runner.py and doctor.py registries. Bumped Custodian's own README to add the R class to the detector model table. Used the new detector to drive standardization of the 6 older READMEs across the platform — all 10 platform repos now pass R1-R5.

- README detector-count refresh (2026-05-06, on `main`): Detector class counts in README's "Detector model" table had drifted since the tool-first deprecation pass (C/D/F/U/T were all wrong). Recomputed from `build_*_detectors()` output (active=46 across 12 classes; 21 deprecated). Added a one-line note pointing readers at `docs/design/detector_disposition_matrix.md`.

- CI cleanup round 2 (2026-05-06, on `main`): re-added license headers (they got reverted) + per-file ruff ignores for `src/custodian/cli/**` (T201/BLE001/S603 OK in CLIs) and `src/custodian/adapters/**` (S603 — these adapters wrap external tools via subprocess by design). 790 tests pass; ruff src/ clean.
- CI cleanup: license headers + dead C7 exclude_paths (2026-05-06, on `main`): Custodian's CI was failing on (a) missing SPDX headers in 3 newly-added `__init__.py` files (`.vulture_whitelist.py`, `audit_kit/detectors/__init__.py`, `audit_kit/passes/__init__.py`) and (b) `custodian-doctor --strict` warning that `exclude_paths` referenced retired detector C7. Added the headers; removed the dead C7 block. CI now green.

- A1 `public_api_only` invariant (2026-05-06, on `feat/boundary-public-api-invariant`): New invariant for enforcing public-API discipline when a repo consumes an extracted library. Config: `public_api_only: {package, allowed_paths}`. Flags imports of `<package>.*` whose module path isn't in `allowed_paths` exactly. Driven by the runtime extraction (ER / RxP / SR are now independent repos consumed by OC; boundary discipline was relying on PR review only). 8 new tests pin allowed top-level + subpackage paths, deep-module rejection, unrelated-package ignore, empty-allowlist safe default, relative imports never flagged. 790 tests pass (+8).

- D3 honors `exclude_paths.D3` (2026-05-06, on `main`): D3 (NoReturn missing) was the only D-class detector that didn't read its `audit.exclude_paths.D3` config — every other detector with the `(audit_cfg.get('exclude_paths') or {}).get('<id>')` pattern did. Discovered when triaging OC's Typer entrypoints (which legitimately end in `raise typer.Exit(code)`) and a private downstream repo's NoopTraceSink (intentional no-op base methods). Added the standard fnmatch exclusion logic to `detect_d3` matching the existing pattern in D6/D9/D10/F1/F2. Consumers can now exclude per-file just like every other path-aware detector. 782 tests still pass.

- Triage layer landed (2026-05-05, on `main`): New module `src/custodian/triage/` joins per-detector findings into per-file action verdicts (DELETE / IMPLEMENT / WIRE / REDESIGN / CLEANUP), closing the "we have signals but no synthesis" gap. Three layers shipped together. (1) Docs — `docs/usage/triage_signals.md` documents the decision matrix. (2) CLI — `custodian triage <audit.json>` (and console script `custodian-triage`); supports `--json` and `--only VERDICT` filters; reads stdin via `-`. (3) Integrated pass — when `audit.triage: true` is set in `.custodian/config.yaml`, runs after detectors+adapters and appends `TRIAGE_<VERDICT>` patterns to the audit result with `source: "triage"`. Matrix buckets: `_UNCALLED` (D1/D5/F1/F2/VULTURE), `_STUB_BODY` (U1/U2/U3/D3), `_UNWIRED` (D6/U4/VF6), `_BLOAT` (C29), `_NOISE` (C33), `_DEAD_TEXT` (C34/G1/C8). DELETE = uncalled+stub; IMPLEMENT = stub alone; WIRE = unwired; REDESIGN = bloat+noise; CLEANUP = dead text. Verdicts not exclusive — file may earn multiple, sorted by priority. 21 new tests; full suite 782 pass. Smoke test on a private downstream repo produced 2 actionable verdicts (1 IMPLEMENT in trace_sink.py, 1 CLEANUP in script_enrichment.py); Custodian + OC produce 0 (correct — those repos have no triage-relevant detector hits).

- Tool-first enforcement round 2 (2026-05-05, on `main`): Continuation of the prior pass after deeper verification. **Deprecated 3 more natives**: N1 → Ruff N818 (exception class naming), D9 → Ruff TRY203 (useless try/except), C42 → Ruff B028 (warnings.warn missing stacklevel). **Investigated and kept** (no stable Ruff equivalent): C1/C6 (FIX001/002 not in default Ruff selection + C1 has `[deferred, reviewed]` suppression), C11 (no subprocess timeout rule), C28 (no hardcoded-IP rule), C34 (ERA001 misses def/class/@decorator forms), C41/C43 (no ensure_ascii rule), C33 (density check, not per-line), D3 (no Ruff/ty unreachable-code rule — confirmed by direct test), D10 (RUF029 still preview). **Closed the consumer-config gap**: every consumer's `pyproject.toml` previously left Ruff at default rules (E + F), so deprecated natives were silently going dark. Added `[tool.ruff.lint] extend-select` blocks across the platform repos pinning the exact Ruff rules that replace each deprecated native (T201, S101/S110/S324/S602/S603, BLE001, DTZ001/003/005/006/007, G004, B006/B028, PLC1802, TRY002/TRY203, PGH003, RET503, N818). **Un-deprecated** C16/C36 (PLW1514 preview-only) and C39 (LOG004 preview-only) since the Ruff equivalents aren't stable yet — keeps native coverage in place. **Side fixes**: enabled `tools.ty: true` in self-config (adapter was wired but flag was off — surfaces 10 real ty diagnostics); upgraded a downstream repo's Ruff 0.4.4 → 0.15.12; installed Ruff in WorkStation's venv (was missing). 761 tests pass.

- Tool-first enforcement pass (2026-05-05, on `main`): The Custodian Boundary Refinement spec's principle ("use the tools first, don't reimplement") was previously documented in the disposition matrix but not enforced — every native detector ran by default even when Ruff/Vulture/ty covered the same patterns. Closed the gap. **Marked deprecated** (16 C-class + 4 D/F-class duplicates of Ruff/Vulture rules): C2/C4/C9/C10/C15/C16/C17/C18/C20/C23/C31/C35/C36/C38/C39/C40 (→ Ruff), D1/D5/F1/F2 (→ Vulture), D8 (→ Ruff RET503). **Retired entirely** (no tool equivalent worth maintaining): C7 (assert True), D2 (else after terminal if), D7 (dead method param). **Kept active**: D3 (NoReturn check) — would have moved to ty/mypy, but those aren't broadly enabled across consumers, so leaving deprecated=False to avoid losing functionality. **Flipped the default**: `skip_deprecated=True` is now the default in `run_audit()`, `run_repo_audit()`, and the CLI. Added `--include-deprecated` opt-in flag (kept legacy `--skip-deprecated` as a no-op for backward compat). Detector class docstring updated to reflect the new convention. Multi-repo verification: Custodian-self / OC / a private downstream repo all show identical totals between default and `--include-deprecated` modes (deprecated detectors find 0 additional findings on those repos because Ruff already catches them). 25 detector-class tests removed (4 C7 + 9 D2 + 12 D7); 761 tests pass (was 786).

- Disposition matrix updated for Semgrep migration completion (2026-05-05, on `main`): The boundary-refinement spec called for stale TRANSITIONAL markers to be removed and the destination summary to reflect AI3/VF3 as `semgrep` (not `semgrep transitional`). Updated `docs/design/detector_disposition_matrix.md`: AI3 row now reads "DONE (2026-05-05). Python plugin detector removed; enforced by OC/.custodian/rules/semgrep/...". Destination summary now lists `semgrep | 5 | C28, C32, S3, AI3, VF3` (previously two rows: 3 stable + 2 transitional). New "a private downstream repo Plugin Detectors" section documents all 6 a private downstream repo detectors (VF1 → A2 declarative, VF2 → A1 forbidden_import, VF3 → semgrep, VF4 → A1 forbidden_import_prefix, VF5 → A1 class_field_count, VF6 → custom Python). No more TRANSITIONAL markers in the matrix; every detector has a definitive disposition.

- Boundary refinement: Semgrep adapter wiring + docs (2026-05-05, on `main`): Closes the "call-pattern checks → Semgrep" leg of the Custodian Boundary Refinement spec. (1) Adapter registry now honors `tools.semgrep.configs: [path, ...]` so consumer repos can keep rules under `.custodian/rules/semgrep/` instead of the legacy root-level `rules/semgrep/`. (2) `SemgrepAdapter.run()` falls back to `.custodian/rules/semgrep/` first, then `rules/semgrep/`; resolves relative configs against `repo_path`. (3) New docs page `docs/usage/forbidden_import_prefix.md` with the boundary-decision table and real-consumer examples (OC AI1, a private downstream repo VF2/VF4). All 786 tests still pass.

- T8 sample message truncated (2026-05-04, on `main`): The T8 detector's per-finding message was rendering the full sorted list of src packages, producing ~600-char strings on repos with many packages (OpsCenter has 39). Pulled per-finding noise down to a fixed-width tail: `"no imports from any src package (a, b, c (+36 more))"`. Surfaced during the multi-repo Custodian sweep where T8 dominated visually despite being a useful signal. Existing T6/T7/T8 tests unchanged; full Custodian suite 786 pass.

- CLI flags for orchestrator coverage opt-in (2026-05-04, on `main`): Added `--enable-coverage [--coverage-json PATH]` to `custodian-audit`. When set, shallow-merges a `tools.coverage` block (enabled=True, json_path=PATH) into the loaded config without modifying the repo's `.custodian.yaml`. Lets orchestrators (OperationsCenter dispatch) opt in coverage analysis at invocation time. Honors the existing adapter — no new code path. 1 new integration test (`test_runner_enable_coverage_override`); full Custodian suite 786 pass.

- Vulture soft-flip + coverage adapter (2026-05-04, on `main`): Two unrelated changes shipped together. (1) **Vulture default ON** with `min_confidence=80` (high-confidence dead code only) — flipped both v0-normalize and v1-migrate default blocks in `loader.py`. Aligns with the "use Custodian's tools by default unless covered by native or repo-specific" policy. Test fixture updated. (2) **Coverage adapter** `src/custodian/adapters/coverage.py` ingests externally-produced `coverage.json`, emits per-module / per-function findings: `CV1_MODULE_UNEXECUTED` (0/N statements run), `CV2_FUNCTION_UNEXECUTED` (function never executed), `CV3_MODULE_BELOW_MIN_COVERAGE` (under configurable threshold). Default OFF in `custodian` CLI — opt-in via `tools.coverage` block in `.custodian.yaml` or by registry callers. Adapter does NOT run coverage.py itself; consuming repos (e.g. a private downstream repo representative pipeline) produce the JSON and Custodian analyses it. Configurable: `json_path`, `min_coverage`, `exclude_paths`. 12 new tests; full Custodian suite 785 pass.

- T6/T7/T8 — test-presence detector trio (2026-05-04, on `main`): Three new T-class detectors complementing T1 (per-symbol coverage) at the file level. **T6** (untested module): walks src ast_forest, builds dotted module names (skipping `__init__.py` and dunders), collects every `import X` / `from X import y` reference from tests_forest with prefix expansion (`from foo.bar` → marks `foo`, `foo.bar`, `foo.bar.y` as imported), flags any src module whose dotted path is never imported. Excludes via `audit.exclude_paths.T6`. **T7** (parallel test file): for each `src/foo/bar.py`, accepts any of `tests/test_bar.py`, `tests/foo/test_bar.py`, `tests/{unit,integration,contract,regression}/[foo/]test_bar.py` (extensible via `audit.t7_test_dirs`). Skips `__init__.py` and dunders. Excludes via `audit.exclude_paths.T7`. **T8** (dangling test): derives src top-level package names from `src_root` children (dirs with `__init__.py` or top-level `.py` files), walks every `tests/test_*.py` AST, flags files whose imports include zero references to any src package. Skips `conftest.py` + `__init__.py`. Returns 0 if no src packages discoverable. Custom exempt globs via `audit.t8_exempt`. All three registered in `build_test_shape_detectors()`. 20 new tests; full Custodian suite 773 pass.

## Recent Decisions

| Decision | Rationale | Date |
| Vulture soft-flipped ON with min_confidence=80 | Aligns with "use Custodian's tools by default unless covered by native" policy. Confidence 80 = high-confidence dead code only (avoids the noisy 60% baseline). Repos can opt out via `tools.vulture.enabled: false` or lower the bar over time. | 2026-05-04 |
| Coverage adapter ingests coverage.json (does NOT run coverage.py) | Mirrors the ruff/mypy/semgrep pattern — adapters consume tool output, they don't run the tool. Running coverage means running the production pipeline, which is repo-specific. Custodian stays generic; consuming repos produce the JSON. | 2026-05-04 |
| Coverage adapter default OFF in custodian CLI | The on/off rationale differs from other adapters: vanilla `custodian audit` shouldn't trigger or expect a coverage.json. Only repos with an end-to-end pipeline that produces one (initially: a private downstream repo via OpsCenter dispatch) should opt in. | 2026-05-04 |
| T6 skips `__init__.py` (no separate package finding) | A package's `__init__.py` is implicitly exercised whenever any submodule is imported; flagging it separately would always duplicate findings against the submodule. T7 already skips `__init__.py` for the same reason. | 2026-05-04 |
| T7 default test-dir hints: unit, integration, contract, regression | Matches the dir layouts used in a private downstream repo + OpsCenter (the two largest consumers). Custom dirs configurable via `audit.t7_test_dirs`. | 2026-05-04 |
| T8 derives src packages from `src_root` rather than reading `pyproject.toml` | Repo-agnostic — works for any layout that follows the `src/<package>/__init__.py` convention without parsing per-repo packaging metadata. | 2026-05-04 |
| C43 detector added: json.dump() without ensure_ascii=False | LOW severity; 9 tests; file-write sibling of C41 (json.dumps); a private downstream repo runners/audio_enhance/pipeline.py fixed; 753 tests total | 2026-05-03 |
| C42 detector added: warnings.warn() without stacklevel= | LOW severity; 10 tests; catches calls where the warning points to the helper rather than the real caller; 744 tests total | 2026-05-03 |
| a private downstream repo C15 tech debt cleared: 163 logger f-strings migrated | AST-based auto-fixer with byte-offset-aware handling for emoji; all 52 a private downstream repo files fixed; blanket exclusion removed | 2026-05-03 |
| Custodian self-audit C41 clean | Applied ensure_ascii=False to 4 own json.dumps calls (result.py, multi.py, json_report.py, sarif_report.py) | 2026-05-03 |
| C41 detector added: json.dumps() without ensure_ascii=False | LOW severity; 13 tests; explicit ensure_ascii=True not flagged (deliberate choice); a private downstream repo: 26 auto-fixed (single-line) + 4 multi-line manual; SIM115 NamedTemporaryFile → mkstemp in 5 a private downstream repo files; 734 tests | 2026-05-03 |
| C40 detector added: assert statement in non-test production code (721 tests) | assert is disabled by python -O; production invariants must use explicit raise. Skips tests_root, `if __debug__:` blocks, `if __debug__ and ...:` guards, # noqa: C40. 12 tests. a private downstream repo: 19 findings fixed (remove redundant isinstance asserts; convert to if/raise for nlp/cairo/freetype/proc.stdin guards). 721 tests total. | 2026-05-03 |
| Custodian self-audit clean + ruff adapter fix; 709 tests | RUFF_NO_CACHE=1 was invalid for newer ruff (exit code 2, silent 0 findings); switched to --no-cache flag. D7 _is_stub_body() now recognizes `return None` and bare `return` as null-object stubs (was flagging NullEmitter implementations). Self-audit 3 ruff findings fixed: docs.py E402 (import order), naming.py F401 (_py_files unused), naming.py F841 (top_class_names dead variable). a private downstream repo ruff: 284 violations exposed, all resolved; 0 Custodian findings. | 2026-05-03 |
| C39 detector added: logger.exception() outside except handler | AST visitor-based; tracks except handler depth. logger.exception() without active exception logs NoneType:None traceback — fix is logger.error(). 9 tests; 707 total. a private downstream repo finding: speech/client.py after health check loop. | 2026-05-03 |
| T5 detector added: single-case pytest.mark.parametrize | Flags parametrize decorators with exactly one literal case — should be a plain test with inlined value. Skips variable/comprehension arg lists. 10 tests; 698 total. a private downstream repo finding fixed (test_script_output_contract.py). | 2026-05-03 |
| OC2/OC5/OC9 removed from OC plugin; OC3+OC8 kept | OC t3_env_gate_hints added to config (aider, switchboard, etc.); plugin now has only 2 detectors (OC3 orphaned entrypoints, OC8 K1 + field-def awareness). | 2026-05-03 |
| a private downstream repo plugin: VF3 dead code removed | _detect_vf3_config_access was unregistered dead code (VF3 already migrated to native C13). VF6 is now the only plugin detector. | 2026-05-03 |
| C38/D10 detectors added + tests | C38: mutable default argument (list/dict/set); D10: async def without await (skips framework decorators, async generators, stubs); a private downstream repo gpu release() fixed sync; 25 new tests; 688 total | 2026-05-02 |
| T4/U4/C37 detectors added + tests | T4: orphan pytest fixtures (9 tests); U4: Protocol implementation gaps (7 tests); C37: stale audit config keys (7 tests); 663 total tests. OC/a private downstream repo orphan fixtures deleted; anyio_backend false positive fixed with _PLUGIN_OVERRIDE_FIXTURES | 2026-05-02 |
| N2 detector added: invisible pytest test functions (in test files, not named test_) | Only scans tests_root; skips @pytest.fixture decorators, private helpers, conftest.py, setup/teardown hooks; found 14 in a private downstream repo + 23 in OC, all renamed with _ prefix; 10 tests; 639 total | 2026-05-02 |
| D9 detector added: no-op try/except handler (single handler + bare raise) | Only flags single-handler try blocks — multi-handler bare reraises are intentional exception filtering; found 2 in a private downstream repo (assembly.py, stage_driver.py) and fixed; 9 tests; 629 total | 2026-05-02 |
| K3 detector added: Google-style docstring Args section param drift | AST-based; parses Args: sections, compares against actual sig; false positives from Returns/Raises/Kwargs/ALL_CAPS fixed with _GOOGLE_SECTION_HEADERS set; found policy→_policy in OC explain.py; 10 tests; 620 total | 2026-05-02 |
| C36 detector added: built-in open() in text mode without encoding= | AST-based; only flags bare open() not attribute opens (wave/Image/etc); all repos already clean; 9 tests | 2026-05-02 |
| C35 detector added: bare type: ignore without error-code brackets | Uses tokenize for comment-only scanning (no string/docstring false positives); found 23 in a private downstream repo, all fixed; 8 tests | 2026-05-02 |
| C34 detector added: commented-out def/class/decorator definitions | Regex-based; flagged 2 commented-out functions in a private downstream repo filter_function.py; 9 tests | 2026-05-02 |
| D8 detector added: value return with implicit None fall-through | Uses _all_paths_terminate() helper; false positives fixed for with-blocks and while True loops; found _initial_authenticate() in a private downstream repo and fixed it explicitly; 10 tests | 2026-05-02 |
| Audit round 3 complete (2026-05-02) | All repos: Custodian=0, a private downstream repo=1(A1 advisory known), OConsole=0, CxRP=0, OC=0; 593 tests | 2026-05-02 |
| Audit round 2 complete (2026-05-02) | All repos: Custodian=0, a private downstream repo=1(A1 advisory), OConsole=0, CxRP=0, OC=155(T1 LOW domain gaps). Dead code removed, vulture FP rate reduced, D7/T1 glob fixed, 502 tests. | 2026-05-02 |
| Vulture adapter now includes tests_root in scan | False positives for public API functions only called from tests (run_adapters, filter_findings, apply_policy, etc.) — vulture couldn't see test callers; now passes tests_root as additional scan path | 2026-05-02 |
| D7 and T1 exclusions now use _glob_to_regex from code_health | PurePosixPath.match() doesn't handle src/**/*.py correctly (** needs ≥1 intermediate dir); switched to code_health._glob_to_regex which handles zero-or-more segments | 2026-05-02 |
| D7 exclude_paths support added | detect_d7() now reads audit.exclude_paths.D7; used for command-dispatch functions with interface-required params | 2026-05-02 |
| T1 broad exclusions added for a private downstream repo/OC | a private downstream repo: all production dirs excluded (integration-tested pipeline); OC: adapters/entrypoints/artifact_index/backends excluded (monkeypatch-tested) | 2026-05-02 |
| Dead code removed: _top_level_arg_count, _worst_severity, _SEV_ORDER, cmd_install, get_aider_command, spawn_update_clis_background, read_decision, queue.remove | a private downstream repo/OC/OConsole genuinely dead functions and variables cleaned up; protocols.py Protocol classes whitelisted as plugin author API | 2026-05-02 |
| A2 detector (directory structure invariants) | Generic version of VF1 capability DDD folder shape; uses PurePosixPath.match() (not fnmatch) so * = one path component; config: architecture.directory_structure with glob/required_files/required_dirs/exclude | 2026-05-02 |
| A1 extended with class_field_count rule type | Generic version of VF5 WorkflowContext god-object check; counts ast.AnnAssign fields in a named class, excludes InitVar; config: class_field_count: {class_name, max_fields} | 2026-05-02 |
| H1 detector (hexagonal architecture layer ordering) | Layers declared in architecture.hex in order from innermost to outermost; each layer may only import from layers with lower index; more concise than S1's explicit may_not_import lists | 2026-05-02 |
| VF1 and VF5 migrated to declarative config | VF1 now uses A2 (directory_structure in .custodian.yaml), VF5 now uses A1 class_field_count; custom _custodian/detectors.py only retains VF3 (TRANSITIONAL) and VF6 (cross-file) | 2026-05-02 |
| a private downstream repo A1 excludes extended for entrypoints/start | src/entrypoints/** and src/start/** excluded from A1 VF2 rule; these are composition roots legitimately importing get_default_mongo() from class_mongo_conn | 2026-05-02 |
| F1 inheritance check for serializable base classes | _dataclass_field_names() now does two passes: first collects which classes have serialization methods; second skips subclasses of those (handles BaseContract → subclass pattern in CxRP) | 2026-05-02 |
| T2 exclude_paths support added | detect_t2() now reads audit.exclude_paths.T2 to skip "should not raise" validation test files; consistent with T1/C-class exclusion pattern | 2026-05-02 |
| Multi-repo audit round complete (2026-05-02) | a private downstream repo: A1=1(advisory), VULTURE=342, T1=670. OC: T1=266, VULTURE=470. SB: VULTURE=64. OConsole: D1=5(dead funcs), D7=16, T1=75, VULTURE=11. CxRP: T1=1, VULTURE=66. Custodian: VULTURE=19. WorkStation: clean. All hard violations resolved. | 2026-05-02 |
| All 15 Custodian refactor phases complete | Phases 4-15 implemented in one session: Semgrep/ty/mypy/Vulture adapters, policy layer, codemod base, config migration, JSON/SARIF/Markdown reports, integration tests, deprecated detector cleanup, unified CLI, pre-commit hooks, multi-repo enhancements. 475 tests. | 2026-05-01 |
| S4 detector: missing venv guard in tests/conftest.py | Repeatedly having to add venv guard manually; made it a detector so Custodian flags repos that are missing it | 2026-05-01 |
| Deprecated detectors stubbed not deleted | 27 detect_* functions replaced with stubs returning (0,[]); Detector registrations kept for --list-detectors to show them with deprecated=True status | 2026-05-01 |
| F3 skips classes deserialized via model_validate*() | ClassName.model_validate*() calls mean all fields are part of the external schema; not dead even if not accessed as Python attributes | 2026-05-01 |
| F3 transitively expands model_validate_classes | Pydantic inflates nested models automatically during deserialization; a field typed as NestedModel in a deserialized class means NestedModel's fields are also schema fields | 2026-05-01 |
| align_text_to_scene restored + added to __all__ (a private downstream repo) | Function was deleted as D1 false positive; actually monkey-patched via module attribute access in tools/audit/adapters/runtime_hooks — D1 checks called_names not called_attrs | 2026-05-01 |
| D1 false positive: module attribute monkey-patching | `align_mod.align_text_to_scene = ...` is attribute access not a call; D1 misses these. Fix: add __all__ to suppress, or improve D1 to also check called_attrs (but that would suppress too many) | 2026-05-01 |
| D7 recognizes del var as param use | del stage_name, content_type is the Python idiom for intentionally discarding Protocol-required params; Del ctx added to used_names check | 2026-05-01 |
| D7 skips @override methods | Override implementations must match the parent signature; unused params are interface-required | 2026-05-01 |
| D7 treats raise NotImplementedError as stub body | Single-statement or docstring+raise NIE body = incomplete stub; params not flagged | 2026-05-01 |
| test_cli_doctor subprocess needs PYTHONPATH | Tests spawn python -m custodian.cli.doctor; without PYTHONPATH=src the module isn't found (custodian not pip-installed) | 2026-05-01 |
| Settings.policy_path accessed via getattr(self, attr) — F3 false positive | Dynamic string-based attribute access not captured by call_graph; added to known gap | 2026-05-01 |
| D6 added: class referenced but never constructed | D5 catches "never referenced"; D6 catches "referenced but constructor never called" — the partial-pipeline pattern where a DTO is wired into type annotations but the produce-side was never implemented | 2026-05-01 |
| constructed_names tracked separately in call_graph | ast.Call where func is ast.Name → constructor call; also: ClassName.method() attr access, ClassName[T]() generic subscript, keyword kwarg values, base class names — all treated as "class in active use" | 2026-05-01 |
| D5/D6 skip BaseModel/BaseSettings/TypedDict bases | Pydantic models deserialized via model_validate/parse_obj — not via direct constructor; static analysis can't see this | 2026-05-01 |
| D7 skips dunder methods | __exit__/__getitem__ etc. — params required by protocol even if unused | 2026-05-01 |
| F1/F3 skip kw_arg_names | Model(field=value) sets a field; track kwarg names in call_graph so fields used only via constructor aren't flagged as dead | 2026-05-01 |
| call_graph tracks getattr() strings | getattr(obj, "field") is a string-based attribute read; add to accessed_attrs so F1/F3 don't false-positive on these | 2026-05-01 |
| A1 uses declarative invariants YAML | architecture.invariants in .custodian.yaml; complements S1 (import layer rules) with structural constraints (max_lines, max_classes, max_functions, forbidden_import) | 2026-05-01 |
| C33 flags per-file ghost-work density | Unlike C1/C6 (per-occurrence), C33 flags a FILE when it accumulates ≥ threshold TODO/FIXME/HACK/XXX markers; threshold configurable via audit.c33_threshold | 2026-05-01 |
| D6 false positive: dict-registry factory pattern | "nltk": NLTKCheckStage → builders[name](cfg) is dynamic dispatch; can't trace statically. Known limitation; add to .custodian.yaml exclusions if needed | 2026-05-01 |
| OC deleted classes were partial-pipeline DTOs | ArchonFailureInfo, KodoFailureInfo, OpenClawFailureInfo, OpenClawEventDetailRef, ChildTaskSpec were referenced but not wired; restored all and added _extract_failure_info() adapter methods | 2026-05-01 |
| Policy: only delete truly orphaned/duplicated code | DTOs/structs that are partially wired should be completed (restore + wire), not deleted; safe deletions = exact duplication or zero references anywhere including type annotations | 2026-05-01 |
| D5 also checks called_attrs/accessed_attrs | Classes accessed as mod.ClassName are attribute loads, not Name Loads; D5 missed them without this check | 2026-05-01 |
| D5 skips Protocol/ABC base classes | Protocol subclasses are structural interfaces used only in type annotations; PEP 563 lazy eval means no Name Load → false positive | 2026-05-01 |
| C32 uses word-boundary + bigram matching | Substring match ("token" in "word_tokenizer") caused false positives; split on _/./- and check whole words and bigrams | 2026-05-01 |
| C32 skips URL values (http/https prefix) | TOKEN_ENDPOINT = "https://..." is a URL, not a credential value | 2026-05-01 |
| C32 skips ALL_CAPS values | _SECRET_ENV = "OPERATIONS_CENTER_WEBHOOK_SECRET" stores an env var NAME, not the secret itself | 2026-05-01 |
| C32 skips names ending in exclusion suffixes | endpoint/url/env/name/param/var suffixes indicate the var holds a URL or env var reference, not a secret | 2026-05-01 |
| C23 false positive in executor.py docstring | "Never uses shell=True." in a module docstring matched the regex; regex-based C23 doesn't distinguish string context | 2026-05-01 |
| C2 switched to AST-based detection | Regex matched print( inside string literals (docstrings, f-strings); AST walk on ast.Call(func=Name(id='print')) is accurate | 2026-05-01 |
| C16 skips write_text with 2+ positional args | Custom audit.write_text(filename, content) was false positive; Path.write_text takes 1 positional (text) so 2+ = custom method | 2026-05-01 |
| T2 recognizes assert_*() function calls | assert_no_mutation_fields(x) and similar custom helpers are assertion mechanisms; previously caused false positives | 2026-05-01 |
| call_graph tracks all Name Load nodes | Functions passed as values (target=fn, callbacks=[fn]) weren't counted as "used"; Name Load in AST covers all reference forms | 2026-05-01 |
| U1/U2/U3 skip except-handler fallback classes | try/except fallback stubs (import real lib, except: define stub) are intentional no-ops, not unfinished code | 2026-05-01 |
| D1 uses __all__ to mark intentional public APIs | exclude_paths doesn't work for D1 (call_graph has no file context); __all__ is the correct Python idiom for declaring public exports | 2026-05-01 |
| Cross-file detectors use lazy AnalysisGraph | File-local C-class detectors should not pay AST/graph cost | 2026-04-30 |
| U2 excludes Protocol/abstractmethod/overload | Correct Python idioms for ellipsis bodies | 2026-04-30 |
| S1 uses declarative YAML architecture.layers | Rules are explicit and auditable | 2026-04-30 |
| ArchonAdapter/OpenClawRunner converted to ABC | @abstractmethod alone doesn't enforce without ABC base | 2026-04-30 |
| doctor plugin_audit_keys escape hatch | Plugin audit config keys should not trigger unknown-key warnings | 2026-04-30 |
| D2: check else-body does NOT terminate | Symmetric if/else (both return) is intentional; only flag when if exits but else falls through | 2026-04-30 |
| D3 uses separate _all_paths_noreturn | return is not a NoReturn terminal; D3 only counts raise/exit | 2026-04-30 |
| T2 scans tests_root directly | ast_forest covers only src_root; T2 predated the tests_forest pass | 2026-04-30 |
| C19/C20/C22-C25 are regex | Patterns tight enough; consistent with C-class file-local pattern detectors | 2026-04-30 |
| C21 uses inline AST parse | Avoids needing ast_forest for a single C-class detector | 2026-04-30 |
| D1 conservative: module-level only | Methods need type info; false positive cost too high for method-level dead detection | 2026-04-30 |
| call_graph tracks decorated_names separately | A function used as @decorator is "used" even without direct foo() call | 2026-04-30 |
| F1 uses accessed_attrs from call_graph | Any obj.field attribute load marks field live; zero accesses = dead | 2026-04-30 |
| E1 exempts __init__/__new__/__del__ etc. | Convention is to omit -> None on these; flagging is noise | 2026-04-30 |
| G1 uses CamelCase only (not snake_case) | Common English words match snake_case patterns; CamelCase = class/type name, low false-positive rate | 2026-04-30 |
| symbol_index strips comments before tokenizing | A word that appears ONLY in a comment is not "in source" — must strip comments so G1 can detect it | 2026-04-30 |
| tests_forest is a separate pass | Mirrors ast_forest for tests_root; enables T1 without ad-hoc file reads | 2026-04-30 |
| X1 counts BoolOp values beyond first | `a and b and c` has 2 branches, not 1; each extra `and`/`or` value adds complexity | 2026-04-30 |
| x1_threshold/x2_threshold added to doctor known audit keys | Configurable thresholds need to be recognized to avoid false doctor warnings | 2026-04-30 |
| I1 excludes # noqa lines | `# noqa: F401` marks intentional re-exports; I1 must respect these | 2026-05-01 |
| T2 recognizes pytest.raises/warns and self.assertX | These are valid assertion mechanisms; not recognizing them caused 200+ false positives across OC+a private downstream repo | 2026-05-01 |
| D3 pre-checks _has_return_in_scope | Functions with any return path are NOT NoReturn — fix false positives like if/elif/.../raise at end | 2026-05-01 |
| S2 skips self-import pairs (mod_a == mod_b) | Relative imports in __init__.py resolve to the same module; self-loops are spurious | 2026-05-01 |
| C18 regex excludes -f"..." patterns | `-f", "null"` command-line flag list elements were incorrectly matching the f-string pattern | 2026-05-01 |
| D1 skips framework-decorated functions | @app.command(), @router.get(), @pytest.fixture etc. register via decoration not call-site; flagging them as dead is wrong | 2026-04-30 |
| call_graph scans tests_root as extra_roots | F1/D1 false positives for fields/functions used in tests but not in src; extra_roots contribute only usages, not definitions | 2026-04-30 |
| F1 skips dataclasses with serialization methods | to_dict/model_dump/asdict expose all fields indirectly; attribute-level analysis can't see this | 2026-04-30 |
| T2 recognizes mock assertions and raise AssertionError | mock.assert_called_once() / raise AssertionError(...) are legitimate test mechanisms | 2026-04-30 |

*(older entries archived for the R1 400-line budget)*
