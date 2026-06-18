# Log

_Chronological continuity log. Decisions, stop points, what changed and why._

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

## 2026-05-13 — WorkStation → PlatformDeployment hard cutover

- `detect_arch3` in `architecture_split.py`: repo root name check updated from `workstation` to `platformdeployment`.
- Corresponding test renamed to `test_arch3_flags_deprecated_canonical_claim`.

- 2026-05-13 — Cleared pre-existing audit debt (C11/C16/C29/C41/U5/T1/T6/T7/B1/TY/RUFF):
  code fixes in workspace.py (encoding, unused imports), repograph_governance_gate.py
  (timeout, ensure_ascii), boundary.py (BLE001, TY type guard), envvar.py (hasattr lineno);
  config exclusions for structural findings; B1 test-fixture exclusion under privacy.exclude_paths.

- 2026-05-13 — Removed hardcoded `PROHIBITED_PUBLIC_REPO_NAMES` / `PROHIBITED_PUBLIC_REPO_PAGE_SLUGS`
  constants. `_check_public_private_repo_names` now reads `forbidden_names` directly from the
  boundary artifact via `_load_forbidden_names`; page slugs are derived as `name.lower() + ".md"`.
  No hardcoded private repo names remain in the codebase.

- 2026-05-13 — Removed private-repo names and browseable pages from the public
  ProtocolWarden site, and added a governance-gate ban so `PrivateManifest` and
  `a private downstream repo` cannot reappear in public docs or the repo catalog.

- 2026-05-12 — Added semantic federation documentation for the cross-repo
  migration gate and kept the Warehouse wording aligned to utility-only
  boundaries.

- 2026-05-12 — RepoGraph hardening tranche: added explicit schema governance
  scaffolding, boundary artifact hash/provenance validation, projection profile
  awareness, diff/drift primitives, and migration-gate checks for schema version,
  provenance, hash validity, archival doc status, and public projection safety.

- 2026-05-12 — ProtocolWarden archival-doc labeling: added explicit
  CURRENT/HISTORICAL metadata guidance, marked the legacy PlatformDeployment
  repo page as historical, and taught the RepoGraph gate to require canonical
  status metadata for current docs plus archival status for the legacy page.

- 2026-05-12 — RepoGraph policy and explorer hardening: documented policy as
  adjacent to semantics, required the public explorer spec to remain
  projection-only, and added a federated semantic CI workflow that clones the
  public repo set and runs the RepoGraph migration gate across the workspace.

- 2026-05-13 — Public-surface catalog policy codified as a dedicated
  `custodian.policy.public_surface_catalog` helper and the RepoGraph governance
  gate was renamed from migration-era wording; current-only public docs now
  reject archival/catalog leftovers and keep private-truth repos out of the
  browseable repo index.

- 2026-05-12 — Cross-repo semantic CI hardening: added a dedicated
  `semantic-federation` workflow that clones the public repo set, materializes
  the RepoGraph boundary artifact, and runs the migration gate over the whole
  workspace on push and schedule.

- 2026-05-12 — RepoGraph boundary artifact wiring tightened to file-only: removed inline
  boundary-artifact fallback from B2, rewrote the boundary detector tests for file-only
  inputs, and updated the repo-local pre-push guard so it fails closed unless
  `REPOGRAPH_BOUNDARY_ARTIFACT_FILE` already points at a materialized artifact file.

- 2026-05-11 — PlatformManifest native PMV contributor loading: moved PlatformManifest-specific
  PMV detector loading behind a native contributor module so Custodian stays on generic detector
  runtime/plumbing only; documented the visibility workflow, registered the contributor in runner
  and doctor flows, and added relationship-aware detector coverage for public manifest policy
  enforcement without making Custodian the policy owner.

- W6 + E1 detectors (2026-05-08, on main): W6 flags managed repos (.console/ present) that have no .hooks/pre-commit — catches repos wired for session tracking but unprotected by hook (Warehouse, RxP, ExecutorRuntime, SourceRegistry). E1 (envvar.py) AST-scans src for os.environ.get/os.getenv/os.environ[...] key literals and diffs against .env.example documented keys; skips system vars + configurable envvar.skip_keys; silently skips repos with no .env.example (W5 already flags that). 16 new tests; 1078 total passing.

- W3/W4/W5 + U5 ID fix (2026-05-08, on main): Closed five enforcement gaps found during cross-repo hygiene audit. W3 checks `.hooks/pre-commit` content contains a `.console/log.md` guard (an unwired or empty hook silently fails its purpose). W4 checks every submodule in `.gitmodules` has a `branch =` line (without it, `git submodule update --remote` tracks remote HEAD, not the intended branch). W5 checks that if `.gitignore` excludes bare `.env`, a `.env.example` exists at root (env-var contracts must be documented). Also fixed ID collision: stubs.py `P1` ("hollow return body") renamed to `U5` — conflicted with plumbing.py `P1` ("writer key absent"). All 1062 tests pass.

- W-class workspace detectors (2026-05-08, on feat/workspace-detectors): W1 checks
  `.console/` has all four required files (task.md, guidelines.md, backlog.md, log.md);
  W2 checks that if `.hooks/pre-commit` exists, `core.hooksPath = .hooks` is set in
  `.git/config` — an unwired hook is silently ignored by git. Both registered in
  runner.py + doctor.py; 13 tests all pass; 1046 total passing.

- P-class plumbing detectors (2026-05-08, on feat/p-class-plumbing-detectors): P1 (writer key audit), P2 (reader key drift), P3 (path coverage) added to `audit_kit/detectors/plumbing.py`. Config-driven via `audit.plumbing[]` — each entry declares `writer_glob`, `reader_path`, `written_keys`, `path_fragment`, and optional `ignore_keys`. P1 word-boundary scans writer files for each declared key (handles Pydantic field names); P2 AST-scans reader for .get()/.subscript accesses in functions containing path_fragment, skips ALL_CAPS constants + configured ignore_keys to suppress TUI state dict noise; P3 checks fragment present as substring in both sides. Registered in runner.py + doctor.py; `plumbing` added to `_KNOWN_AUDIT_KEYS`. 28 tests (9 P1, 9+1 P2, 8 P3). OC `.custodian/config.yaml` wired with three artifacts: heartbeat (role/at/status), usage.json (top-level + event sub-keys), active.json (campaigns); all three P1/P2/P3 = 0 findings live. 1033 total passing.

- X-series complete (2026-05-08, on feature/x-series-detectors): X1 extended to scan `.yaml`/`.yml` files (config drift, CI files, etc.); sibling-manifest exclusion via `_extra_skip_roots` prevents the PlatformManifest YAML itself from being flagged. X2 added — undeclared cross-repo import detector; uses manifest `edges` as enforced architectural law, skips self-imports and non-platform packages, deduplicates by (file, target_canonical); requires `repo_key` in config. X3 added — stale GitHub URL detector; scans `.md` files for `github.com/ProtocolWarden/LegacyName` patterns derived from `github_url` + `legacy_names` in manifest; works with or without `https://` prefix. All three share a single `_load_manifest_info` pass. 26 new tests (10 X1 + 9 X2 + 9 X3 → `test_x_cross_repo.py`); 1005 total passing. Custodian self-audit: 0 findings on all three detectors. cross_repo config already present in OC/a private downstream repo/SB configs from prior session.

- X-series backlog + cross-repo config wired (2026-05-08, on chore/x-series-backlog-and-cross-repo-config): X1 live-run across OC/a private downstream repo/SB — all 0 findings (ControlPlane/FOB/ExecutionContractProtocol clean). Added `audit.cross_repo.platform_manifest_repo: ../PlatformManifest` to OC, a private downstream repo, SB `.custodian/config.yaml`. Backlogged X1 yaml-scan improvement, X2 (undeclared cross-repo import via manifest edges), and X3 (stale github_url in docs).

- DC8 + M5 + doctor dead-glob warning (2026-05-08, on feat/dc8-m5-and-doctor-dead-globs): Three additions. DC8 enforces conventional README section ordering (What X is → What X is not → Quick start → Architecture → middle sections → License); only sections present in the README are checked, missing ones are R/DC4 territory; operators override via doc_conventions.required_section_order. M5 validates CHANGELOG.md format when present (Keep a Changelog: # Changelog H1 + at least one ## [X.Y.Z] or ## [Unreleased] release section); silent when CHANGELOG absent (M1 covers). Doctor enhancement flags audit.exclude_paths.X globs that match zero files in the repo — stale exclusions left over after path renames. 13 new tests; full suite 916 passing.

- Markdownlint adapter (2026-05-08, on feat/markdownlint-adapter): Last of the four doc/convention enhancements. Wraps markdownlint-cli2 (preferred) or legacy markdownlint, normalizing both output shapes into Custodian Findings. Default scope: README.md + docs/**/*.md; configurable via tools.markdownlint.{globs, config, timeout}. Severity heuristic — MD025 (multiple H1) + MD040 (no fence language) HIGH; MD001/003/024/029/050/051 MEDIUM; rest LOW. Returns TOOL_UNAVAILABLE finding when neither binary is on PATH so consumers without npm see a clear hint instead of a hard fail. 12 new tests; full suite 902 passing.

- DC1 per-dir front matter schemas (2026-05-08, on feat/dc1-per-dir-front-matter-schemas): DC1 used to enforce only status: in docs/design/. Extended with doc_conventions.front_matter_schemas — operators map glob patterns to required-field lists, e.g. docs/architecture/adr/*.md: [date, status, deciders]. Files with no front matter at all report once (missing block) rather than once-per-field; template.md/README.md/index.md exempt. Default-design-dir status check still runs alongside. 6 new tests; full suite 890 passing.

- DC6/DC7 + M-class — taxonomy, orphans, repo-meta (2026-05-08, on feat/dc6-dc7-and-m-class): DC6 flags docs/ subdirs outside a configured allowlist (opt-in). DC7 flags markdown files under docs/ that no other tracked .md links to. M1-M4 check for CHANGELOG/CONTRIBUTING/SECURITY/LICENSE at repo root, each opt-out via repo_meta.skip. 29 new tests; full suite 884 passing. Baseline: DC6=0, DC7=10 (most OC), M1=10 (universal CHANGELOG gap), M2-M4=0.

- DC-class native — promote OC's doc_conventions plugin (2026-05-08, on `feat/dc-class-doc-conventions`): OC's `.custodian/doc_conventions.py` plugin had been carrying DC1-DC5 (design front matter, dead doc refs, ADR naming, README sections, bare-symbol citations) for the platform. Promoted the whole class to a Custodian native at `audit_kit/detectors/doc_conventions.py` with sensible defaults so all 10 public repos pick it up automatically. Each detector silently skips when its target directory doesn't exist (DC1 → docs/design, DC3 → docs/architecture/adr, DC5 → docs/{design,architecture}), and DC4 stays silent when the README is missing entirely (R1 already covers that). Configurable via a new `doc_conventions:` top-level key in `.custodian/config.yaml`. 25 unit tests; full suite 855 passing. Baseline scan across the platform: DC1=1 (Custodian self-finding), DC2=1 (OperatorConsole), DC3=0, DC4=12 (most repos missing one or both of Quick start / Architecture H2s), DC5=0.

- Self-wire B1 privacy block (2026-05-08, on `chore/self-wire-b1-privacy-block`): Custodian dogfoods B1. Top-level `privacy:` block added to its own `.custodian/config.yaml` listing `a private downstream repo` / `a private downstream repo`. B1 reports zero leaks (the only existing reference is in `.console/log.md` historical narration, which is default-excluded). The block guards against future references slipping into tracked files.

- B1 default-excludes its own config (2026-05-08, on `chore/b1-default-exclude-own-config`): When a consumer added `privacy.private_repo_names: [a private downstream repo]` to their `.custodian/config.yaml`, B1 immediately flagged the config file itself for "containing" the banned name. Now `.custodian/config.yaml` and the legacy `.custodian.yaml` are part of the default exclude tuple — operators don't have to add the exclude themselves. 15 boundary tests + 830 total still pass.

- B-class detector — private-repo-name leakage (2026-05-08, on `feat/p-class-private-repo-name-detector`): Public repos describe stable, reusable platform capabilities; private manifests bind those to specific private repos. Public-repo-shipped artifacts that name a private repo by string leak the boundary. Added `B1` (Boundary class — initial detector for the class) that scans tracked files (via `git ls-files`, with a recursive-walk fallback when git isn't available) for configured private-repo names. Configurable via a new `privacy:` top-level key in `.custodian/config.yaml` with `private_repo_names` (case-sensitive substring) and `exclude_paths` (additive over a sensible default set: `.console/**`, `config/managed_repos/local/**`, `docs/history/**`, `tools/audit/report/**`). Skips binary files via suffix list. MEDIUM severity. 14 new tests; full Custodian suite 829 passing. Doc page at `docs/usage/private_repo_names.md`. README class table bumped 12 → 13.

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
| C18 excludes f after quote chars | `"f", "h"` list elements matched `f", "` as f-string; add (?<!")(?<!') lookbehinds | 2026-04-30 |

## Stop Points

- Contract drift (docstring vs signature): needs docstring parser — complex, lower priority
- Duplicate code detection: needs hash/similarity pass — complex, likely out of scope
- D1 per-file context: module_functions is a flat set; exclude_paths can't target specific files; fix requires storing (file, name) pairs
- D1 module attribute monkey-patching: `mod.fn = wrapper` is attribute access, not call; D1 misses this pattern; workaround is __all__
- C23 regex false positive on docstrings: "shell=True" in docstring text matches; fix requires AST-based C23
- a private downstream repo D7 35 remaining: all keyword-only params — cannot rename with _ prefix without breaking callers; need to either wire them or accept as known

## Notes

**Detector class map (70 total: 57 core + 13 OC plugin [OC1–OC9, AI1–AI4]):**
- C (C1–C33): file-local code health — regex + inline AST; C33=ghost-work density (new)
- S (S1–S3): cross-file structure — import_graph (S1, S2) + ast_forest (S3)
- A (A1): architecture invariants — declarative YAML max_lines/max_classes/max_functions/forbidden_import (new)
- U (U1–U3): unimplemented stubs — ast_forest
- D (D1–D7): dead code — D7=dead method params (new); D5/D6=dead classes (ast_forest+call_graph)
- F (F1–F3): dead fields/constants — F3=Pydantic BaseModel field liveness (new)
- E (E1–E2): annotation gaps — ast_forest
- T (T1–T2): test shape — T1 uses ast_forest+tests_forest, T2 direct scan
- X (X1–X2): complexity — ast_forest
- G (G1): ghost work — symbol_index
- I (I1): import hygiene — ast_forest

**Analysis passes and what they enable:**
- import_graph → S1, S2
- ast_forest → U1-U3, D2-D4, F2, E1-E2, X1-X2, T1, I1, S3, D5 (class list), D6 (class list)
- call_graph → D1, F1, D5 (reference check), D6 (constructed_names check)
- symbol_index → G1
- tests_forest → T1

**D6 constructed_names tracking covers:**
- `ClassName(...)` — direct constructor call
- `ClassName[T](...)` — generic parameterized constructor
- `ClassName.method(...)` — classmethod/factory dispatch
- `EnumClass.MEMBER` — enum member access (any Attribute node)
- `default_factory=ClassName` — keyword argument factory reference
- `class Child(ClassName):` — base class inheritance

**False-positive risk guide:**
- LOW: file-local AST (D2, D3, D4, F2, E1, E2, X1, X2, C21, I1)
- MEDIUM: call_graph (D1, F1, D5, D6) — dynamic dispatch/string-based factories not captured; G1 — CamelCase heuristic
- HIGHER: T1 — indirect testing via integration tests produces false positives

**Test counts as of 2026-05-01 (round 9):**
Custodian 393 tests (committed 55282f8). OC 3037 tests. SB 287 tests. a private downstream repo 1660 tests (7 pre-existing failures unchanged).

**Audit totals as of 2026-05-01 (round 9, post-fixes):**
a private downstream repo ~2024 (estimate), OC 460, SB 41. Total ~2525 (was 2674 round 8 end, -149 this round).
Round 9 new fixes: a private downstream repo D1 -42 (bulk dead function removal), a private downstream repo D5 -1 (VideoPerformance), a private downstream repo F2 -1 (_BRANDING_MAP), a private downstream repo I1 -1 (contextlib), a private downstream repo D1 -2 files deleted (audit_summary.py, validation.py).
Custodian improvements this round: F3 model_validate_classes tracking + transitive expansion for nested Pydantic models.

**Native tool migration — completed 2026-05-01 (this session):**
- OC `tools/audit/architecture_invariants/` — all 4 rule files (import_rules, layer_rules, mutation_rules, scanning_rules) inlined directly into `_custodian/architecture.py` (AI1–AI4). No more try/import wrappers. Directory deleted.
- a private downstream repo `tools/audit/architecture_invariants/` — all 4 rule files (capability_rules, singleton_rules, config_rules, audit_policy_rules) inlined into `_custodian/detectors.py` (VF1–VF4). import_rules covered by S1 config. Added VF5 (WorkflowContext field count advisory ≥ 20 fields). Directory deleted.
- a private downstream repo workflow context guardrails (`workflow_context_guardrails.py`, `check_workflow_context_guardrails.py`, `workflow_context_ownership.json`) moved to `tools/audit/workflow_context/` — still needed as a standalone tool that requires a pre-generated context map.
- Custodian self-audit: 64 → 0 findings (C11: timeout= on all 5 adapters; F2: 8 dead regex constants deleted; D1: maintenance_kit/ deleted; F1: replaces field removed; D7: unused context param removed; C29/C1/C6/T1: config exclusions with rationale).
- SB T1: 3 → 0 (DecisionSink, AdjustmentStoreState, SummaryStats excluded — tested via containing services).
- a private downstream repo C1: 23 → 0 (per-file exclusions added; all 23 TODOs tracked in .console/backlog.md).

**Current findings (post this session):** Custodian 0, SwitchBoard 0, a private downstream repo 671 (T1=670, VF5=1, VF6=0), OC 266 (T1=266). All HIGH/MED findings are zero across all repos.

**VF6 added (2026-05-01):** Detects stage classes (have `run(self, context)` method) under `stages/` that are not referenced in any of the three pipeline wiring files (orchestration/api.py, core/manager.py, stages/system/preflight_bundle.py). Currently returns 0 — all stages correctly wired. Will fire if a new stage file is added but not wired in.

- DC1+DC4 self-fix (2026-05-08, on `fix/dc-class-self-findings`): Added YAML front matter to docs/design/detector_disposition_matrix.md (DC1) and an Architecture section to README.md describing the three-layer runner (native detectors / adapter pass / plugin detectors). DC count goes 2 → 0.

## Archived

_Archived completed history → `/home/dev/Documents/GitHub/PrivateManifest/archive/console/Custodian/log-2026-06-04.md`_


## 2026-06-07 — fix(doctor): add r1_enabled / r1_line_budget to known audit keys

r1_enabled and r1_line_budget are valid reconcile-detector overrides (reconcile.py)
but were absent from _KNOWN_AUDIT_KEYS in doctor.py, causing --strict to exit 1 when
a repo sets r1_enabled: false. Added both keys alongside reconcile_enforce.
