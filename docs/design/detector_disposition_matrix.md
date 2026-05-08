# Custodian Phase 0 — Detector Disposition Matrix

**Status:** Complete  
**Date:** 2026-05-01  
**Scope:** All 70 detectors (57 core + 13 OC plugin). No code has been deleted.

---

## Disposition Categories

| Category | Meaning |
|---|---|
| `ruff` | Delegate to Ruff; remove Custodian detector after parity confirmed |
| `semgrep` | Delegate to Semgrep (custom rule or registry rule) |
| `ty` | Delegate to ty (preferred) |
| `mypy_fallback` | Delegate to mypy when ty unavailable |
| `vulture_advisory` | Delegate to Vulture; non-blocking advisory signal |
| `custodian_policy` | Custodian owns permanently — repo-aware or cross-repo logic |
| `custodian_hygiene` | Custodian owns as non-blocking hygiene signal |
| `retire` | Remove with no replacement; value insufficient or noise too high |
| `undecided` | Documented rationale required inline |

---

## C-class — File-local Code Health (32 detectors)

| Code | Description | Severity | Module | Destination | Blocking | Replacement Rule | FP Risk | Migration Notes |
|---|---|---|---|---|---|---|---|---|
| C1 | TODO markers in source | LOW | code_health.py | `custodian_hygiene` | No | Ruff `TD002`/`FIX002` (overlaps but doesn't replace — Custodian's density+threshold logic in C33 is the real value) | LOW | Keep as advisory; C33 captures the density signal that matters |
| C2 | `print()` statements | MEDIUM | code_health.py | `ruff` | Yes (MEDIUM) | Ruff `T201` | LOW | Exact match; retire Custodian detector after Phase 3 parity check |
| C3 | Bare `except:` | HIGH | code_health.py | `ruff` | Yes (HIGH) | Ruff `E722` | LOW | Exact match |
| C4 | `pass` in exception handler | MEDIUM | code_health.py | `ruff` | Yes (MEDIUM) | Ruff `S110` | LOW | Ruff S110 is `try-except-pass`; verify OC exclusion paths still apply via Ruff config |
| C5 | Debugger breakpoints | HIGH | code_health.py | `ruff` | Yes (HIGH) | Ruff `T100` | LOW | Covers `breakpoint()` and `pdb.set_trace` |
| C6 | FIXME markers | LOW | code_health.py | `custodian_hygiene` | No | Ruff `FIX001` (overlaps) | LOW | Same rationale as C1; keep for deferred-aware OC2 relationship |
| C7 | `assert True` usage | LOW | code_health.py | `retire` | — | — | LOW | Already deferred. `B011` covers `assert False`; `assert True` is low value. Remove. |
| C8 | Stale handler references | MEDIUM | code_health.py | `custodian_policy` | No | None | MEDIUM | OC-specific; references `stale_handlers` config key. Keep but make non-blocking. |
| C9 | Broad `except Exception` without logger | HIGH | code_health.py | `ruff` + `custodian_hygiene` | Partial | Ruff `BLE001` | LOW | Ruff `BLE001` catches blind Exception but not the "without logger" nuance. Phase 3: delegate the catch, drop the logger-nuance requirement (too fragile anyway). |
| C10 | Naive `datetime.now()`/`utcnow()` | MEDIUM | code_health.py | `ruff` | Yes (MEDIUM) | Ruff `DTZ001`, `DTZ003` | LOW | Exact match |
| C11 | `subprocess` without `timeout=` | MEDIUM | code_health.py | `custodian_hygiene` | No | No Ruff equivalent for timeout specifically | MEDIUM | Ruff covers shell injection (`S60x`) but not missing timeout. Keep as advisory; high exclusion list in OC is a smell that this check is noisy. |
| C12 | Bare `# type: ignore` without code | LOW | code_health.py | `ruff` | Yes (LOW) | Ruff `PGH003` | LOW | Exact match |
| C13 | `assert` for runtime validation | MEDIUM | code_health.py | `ruff` | Yes (MEDIUM) | Ruff `S101` | LOW | Exact match |
| C14 | `open()` without `encoding=` | MEDIUM | code_health.py | `ruff` | Yes (MEDIUM) | Ruff `PLW1514` | LOW | Verify Ruff covers `open()` call sites identical to Custodian's current regex |
| C15 | f-string passed directly to logger | LOW | code_health.py | `ruff` | Yes (LOW) | Ruff `G004` | LOW | Exact match |
| C16 | `Path.read_text`/`write_text` without `encoding=` | LOW | code_health.py | `ruff` | Yes (LOW) | Ruff `PLW1514` (verify Path.* coverage) | LOW | `PLW1514` covers `open()`; verify it also catches `Path.read_text`. If not, keep C16 or write Semgrep rule. |
| C17 | `len(x) == 0` / `len(x) > 0` | LOW | code_health.py | `ruff` | Yes (LOW) | Ruff `PLC1802` (verify rule ID) | LOW | Rule ID uncertain — verify against Ruff docs before retiring |
| C18 | f-string with no interpolation | LOW | code_health.py | `ruff` | Yes (LOW) | Ruff `F541` | LOW | Exact match |
| C19 | `global` statement in function | MEDIUM | code_health.py | `ruff` | Yes (MEDIUM) | Ruff `PLW0603` | LOW | Exact match |
| C20 | `eval()` or `exec()` | HIGH | code_health.py | `ruff` | Yes (HIGH) | Ruff `S307` (eval), `S102` (exec) | LOW | Exact match |
| C21 | Mutable default argument | HIGH | code_health.py | `ruff` | Yes (HIGH) | Ruff `B006` | LOW | Exact match |
| C22 | `time.sleep()` busy-wait | LOW | code_health.py | `retire` | — | No Ruff equivalent | LOW | Low value, high noise (many legitimate uses). Remove. |
| C23 | `subprocess` with `shell=True` | HIGH | code_health.py | `ruff` + `semgrep` | Yes (HIGH) | Ruff `S602`/`S603`; Semgrep for nuanced architectural rules | MEDIUM | Ruff covers the pattern; Semgrep for trusted-config exceptions via rule-level `nosemgrep`. Current OC exclusion list becomes Semgrep `paths.exclude`. |
| C24 | `pickle.load`/`loads` | HIGH | code_health.py | `ruff` | Yes (HIGH) | Ruff `S301` | LOW | Exact match |
| C25 | `raise ... from None` | LOW | code_health.py | `retire` | — | No Ruff equivalent (Ruff `B904` is opposite: enforces `from`) | LOW | Low value; `from None` is sometimes intentional. Remove. |
| C26 | `os.system()` | MEDIUM | code_health.py | `ruff` | Yes (MEDIUM) | Ruff `S605` | LOW | Verify Ruff covers `os.system` specifically |
| C27 | `assert False`/`assert 0` | LOW | code_health.py | `ruff` | Yes (LOW) | Ruff `B011` | LOW | Exact match |
| C28 | Hardcoded IP address | LOW | code_health.py | `semgrep` | No | Semgrep `python.lang.security.audit.hardcoded-ip` or custom | MEDIUM | Ruff's `S104` covers bind-all only; Semgrep handles general hardcoded IPs better |
| C29 | File exceeds line-count threshold | LOW | code_health.py | `custodian_hygiene` | No | No tool equivalent | LOW | Keep; pair with A1 `max_lines` invariant. Non-blocking. |
| C31 | Weak hash without `usedforsecurity=False` | HIGH | code_health.py | `ruff` | Yes (HIGH) | Ruff `S324` | LOW | Exact match |
| C32 | Hardcoded credential in assignment | HIGH | code_health.py | `semgrep` | Yes (HIGH) | Semgrep `python.lang.security.audit.hardcoded-*` suite | MEDIUM | Semgrep's credential detection is more accurate than word-boundary regex; current FP rate in Custodian's C32 is moderate |
| C33 | Ghost-work comment density | LOW | code_health.py | `custodian_hygiene` | No | No tool equivalent | LOW | Permanently Custodian-owned; threshold config stays in `.custodian/config.yaml` |

**C-class summary:** 17 → `ruff`, 3 → `semgrep`, 6 → `custodian_hygiene`/`custodian_policy`, 4 → `retire`  
**Not built (C30):** `random` outside tests — if implemented, destination would be `ruff` (Ruff `S311`) or `semgrep`.

---

## D-class — Dead Code (7 detectors)

| Code | Description | Severity | Module | Destination | Blocking | Replacement | FP Risk | Migration Notes |
|---|---|---|---|---|---|---|---|---|
| D1 | Dead module-level function | MEDIUM | dead_code.py | `vulture_advisory` | No | Vulture (advisory) | MEDIUM | Vulture catches this pattern. Non-blocking by design — dynamic dispatch and `__all__` patterns produce false positives. Current false-positive mitigations (`__all__`, `framework_decorated`) become Vulture whitelist entries. |
| D2 | Dead branch (if exits, else falls through) | MEDIUM | dead_code.py | `retire` | — | Partial Ruff `RET` rules | MEDIUM | Ruff `RET501`–`RET506` cover some return-path patterns but not this exact shape. High FP risk from legitimate asymmetric branches. Remove. |
| D3 | Missing `NoReturn` annotation | MEDIUM | dead_code.py | `ty` | No (advisory) | ty / mypy | MEDIUM | Type checkers detect this correctly. Non-blocking until type coverage improves across repos. |
| D4 | Unreachable code after unconditional return/raise | MEDIUM | dead_code.py | `ruff` | Yes (MEDIUM) | Ruff `RET508` / `F811` area — verify exact rule | LOW | Ruff has dead-code detection rules; verify coverage of all D4 patterns before retiring |
| D5 | Dead class (never referenced) | MEDIUM | dead_code.py | `vulture_advisory` | No | Vulture | MEDIUM | Vulture detects unused classes. Non-blocking; string-based factory pattern is a known false positive. |
| D6 | Class referenced in annotations but never constructed | MEDIUM | dead_code.py | `custodian_policy` (advisory) | No | None | MEDIUM | **No tool equivalent.** Captures partial-pipeline pattern where a DTO is wired into type signatures but the produce-side was never implemented. Retain as advisory — useful for architectural cleanup. See mandatory decision below. |
| D7 | Dead method parameter | LOW | dead_code.py | `retire` | — | None | HIGH | **Retire.** High noise (keyword-only params cannot be renamed without breaking callers), limited architectural value, and the 35 remaining VF findings are all in this category. Type checkers and normal code review handle this better. See mandatory decision below. |

---

## F-class — Dead Fields / Constants (3 detectors)

| Code | Description | Severity | Module | Destination | Blocking | Replacement | FP Risk | Migration Notes |
|---|---|---|---|---|---|---|---|---|
| F1 | Dead dataclass field | MEDIUM | dead_code.py | `vulture_advisory` | No | Vulture | MEDIUM | Vulture can detect unused attributes. Custodian's current skip for serialization-method classes becomes a Vulture whitelist. |
| F2 | Dead module-level constant | LOW | dead_code.py | `vulture_advisory` | No | Vulture | LOW | Straightforward; Vulture handles unused module-level names well. |
| F3 | Dead Pydantic BaseModel/BaseSettings field | MEDIUM | dead_code.py | `custodian_policy` (advisory) | No | None | MEDIUM | **No tool equivalent.** Pydantic's runtime deserialization is invisible to Vulture. Retain permanently. `model_validate_classes` + transitive expansion logic is Custodian-specific domain knowledge. See mandatory decision below. |

---

## U-class — Unimplemented Stubs (3 detectors)

| Code | Description | Severity | Module | Destination | Blocking | Replacement | FP Risk | Migration Notes |
|---|---|---|---|---|---|---|---|---|
| U1 | Function body is `pass` or `...` | MEDIUM | stubs.py | `custodian_policy` | No (advisory) | Semgrep custom rule possible | LOW | Could be Semgrep pattern, but Protocol/ABC/except-handler exclusions are Custodian-specific. Retain initially; evaluate Semgrep migration in Phase 4. |
| U2 | Function body is ellipsis only (non-Protocol) | MEDIUM | stubs.py | `custodian_policy` | No (advisory) | Semgrep custom rule possible | LOW | Same as U1 |
| U3 | Function body raises `NotImplementedError` | MEDIUM | stubs.py | `custodian_policy` | No (advisory) | Semgrep custom rule possible | LOW | Same as U1 |

---

## S-class — Structure (3 detectors)

| Code | Description | Severity | Module | Destination | Blocking | Replacement | FP Risk | Migration Notes |
|---|---|---|---|---|---|---|---|---|
| S1 | Import layer violation | HIGH | structure.py | `custodian_policy` | Yes (HIGH) | Semgrep `python.lang.imports` (partial); `import-linter` (alternative) | LOW | Custodian's declarative YAML config for S1 is clean and repo-specific. Stays here. Semgrep could assist with pattern matching but Custodian owns the rule definitions. |
| S2 | Circular import | HIGH | structure.py | `custodian_policy` | Yes (HIGH) | `import-linter` or `flake8-bugbear` (partial) | LOW | Custodian's import_graph is accurate. No external tool handles this as cleanly for repo-aware circular detection. Stays. |
| S3 | Production code imports test modules | HIGH | structure.py | `semgrep` | Yes (HIGH) | Semgrep custom rule: `import tests.*` in `src/**` | LOW | Simple structural pattern; ideal Semgrep rule. Migrate in Phase 4. |

---

## A-class — Architecture Invariants (1 detector)

| Code | Description | Severity | Module | Destination | Blocking | Replacement | FP Risk | Migration Notes |
|---|---|---|---|---|---|---|---|---|
| A1 | Declarative YAML invariant (max_lines, max_classes, max_functions, forbidden_import, forbidden_import_prefix) | HIGH | structure.py | `custodian_policy` | Yes (HIGH) | `max_*` metrics Custodian-owned; `forbidden_import*` keys are the canonical import-policy layer (replaced custom plugin AST walkers) | LOW | Permanently Custodian-owned. `forbidden_import_prefix` (added) catches both `import foo.bar` and `from foo.bar import x` with one rule — used by OC AI1 and VF VF2/VF4 invariants. |

---

## G-class — Ghost Work (1 detector)

| Code | Description | Severity | Module | Destination | Blocking | Replacement | FP Risk | Migration Notes |
|---|---|---|---|---|---|---|---|---|
| G1 | CamelCase type name appears only in comments | LOW | ghost.py | `custodian_hygiene` | No | None | MEDIUM | No tool equivalent. Heuristic value is moderate — catches references to deleted/renamed types left in docstrings. Keep as advisory; low implementation cost to maintain. |

---

## T-class — Test Shape (2 detectors)

| Code | Description | Severity | Module | Destination | Blocking | Replacement | FP Risk | Migration Notes |
|---|---|---|---|---|---|---|---|---|
| T1 | Source module has no test file | MEDIUM | test_shape.py | `custodian_policy` | No (advisory) | None | HIGHER | Repo-aware check; integration tests produce false positives. Stays as advisory. |
| T2 | Test function has no assertions | HIGH | test_shape.py | `custodian_policy` | Yes (HIGH) | Ruff `PT` rules cover some pytest assertion patterns; not the "no assertions" case | MEDIUM | No Ruff rule for "test function contains zero assertions." Stays in Custodian. |

---

## E-class — Annotations (2 detectors)

| Code | Description | Severity | Module | Destination | Blocking | Replacement | FP Risk | Migration Notes |
|---|---|---|---|---|---|---|---|---|
| E1 | Missing return type annotation | LOW | annotations.py | `ruff` (then `ty`) | No (advisory) | Ruff `ANN201`/`ANN202`; ty validates correctness not just presence | LOW | Phase 3: Ruff for presence check. Phase 6: ty for correctness. Non-blocking during transition. |
| E2 | Missing parameter type annotation | LOW | annotations.py | `ruff` (then `ty`) | No (advisory) | Ruff `ANN001`/`ANN002`/`ANN003` | LOW | Same as E1 |

---

## I-class — Imports (1 detector)

| Code | Description | Severity | Module | Destination | Blocking | Replacement | FP Risk | Migration Notes |
|---|---|---|---|---|---|---|---|---|
| I1 | Unused import | MEDIUM | imports.py | `ruff` | Yes (MEDIUM) | Ruff `F401` | LOW | Exact match. `# noqa: F401` re-export convention preserved. |

---

## X-class — Complexity (2 detectors)

| Code | Description | Severity | Module | Destination | Blocking | Replacement | FP Risk | Migration Notes |
|---|---|---|---|---|---|---|---|---|
| X1 | Cyclomatic complexity exceeds threshold | MEDIUM | complexity.py | `ruff` | Yes (MEDIUM) | Ruff `C901` (McCabe) | LOW | Exact match. Ruff `mccabe.max-complexity` config replaces `x1_threshold`. |
| X2 | Too many parameters | LOW | complexity.py | `ruff` | Yes (LOW) | Ruff `PLR0913` | LOW | Exact match. Ruff `pylint.max-args` config replaces `x2_threshold`. |

---

## OC Plugin Detectors — detectors.py (9 detectors)

| Code | Description | Status | Destination | Blocking | Replacement | Migration Notes |
|---|---|---|---|---|---|---|
| OC1 | Scaffolded-but-unimplemented backends | deferred | `retire` | — | Superseded by U1–U3 | Remove from plugin; U1–U3 via Ruff/Semgrep handle this generically |
| OC2 | Untagged TODO/FIXME debt (deferred-aware) | open | `custodian_policy` | No | None | Permanently Custodian-owned; understands `[deferred]`/`[reviewed]` tag semantics that Ruff/Semgrep don't |
| OC3 | Orphaned entrypoints | open | `custodian_policy` | No | None | Repo-aware; requires entrypoint registry knowledge. Stays. |
| OC4 | Ruff lint findings | fixed | `retire` | — | Superseded by direct Ruff adapter (Phase 2) | Remove; adapter replaces this entirely |
| OC5 | Unconditional `@pytest.mark.skip` | open | `ruff` | Yes | Ruff `PT021` (verify) | Migrate to Ruff PT rules; verify exact rule covers unconditional case |
| OC6 | Modules called only from tests | deferred | `retire` | — | None | High false-positive risk; deferred indefinitely. Remove. |
| OC7 | Dead settings fields | deferred | `retire` | — | Superseded by F3 | F3 handles Pydantic/BaseSettings fields. Remove. |
| OC8 | Docs reference a symbol that doesn't exist | open | `custodian_policy` | No | None | Repo-aware doc↔code consistency. Permanently Custodian-owned. |
| OC9 | Docs cite a value not present in src | open | `custodian_policy` | No | None | Same as OC8 |

---

## OC Plugin Detectors — architecture.py (4 detectors)

| Code | Description | Status | Destination | Blocking | Replacement | Migration Notes |
|---|---|---|---|---|---|---|
| AI1 | Managed-repo imports inside `src/operations_center/` | fixed | `custodian_policy` (A1 declarative) | Yes | `architecture.invariants[forbidden_import_prefix]` in `.custodian/config.yaml` | **DONE.** Python plugin detector removed; now enforced via A1 `forbidden_import_prefix` rule (one rule per managed-repo binding plus `tools.audit` / `managed_repo`). No semgrep needed. |
| AI2 | Layer-direction violations (fast-feedback ladder) | fixed | `custodian_policy` (S1 declarative) | Yes | `architecture.layers` in `.custodian/config.yaml` | **DONE.** Python plugin detector removed; now enforced via S1 declarative layer rules (slice_replay, mini_regression, fixture_harvesting, audit_governance). |
| AI3 | Directory-scanning in `artifact_index` | fixed | `semgrep` | Yes | Semgrep pattern: `glob`/`rglob`/`scandir`/`walk` in `artifact_index/**` | **DONE (2026-05-05).** Python plugin detector removed; enforced by `OC/.custodian/rules/semgrep/ai3_no_directory_scanning.yaml` with `multi_run.py` + `cli.py` exempted. |
| AI4 | Anti-collapse guardrail structurally present | fixed | `custodian_policy` | Yes | None | Structural invariant that requires runtime knowledge of OC's architecture. Keep in Custodian permanently. |

---

## Managed-Repo Plugin Detectors — example migration (6 detectors)

A worked example of how a managed repo's `.custodian/detectors.py` plugin
gets rewritten as declarative `custodian_policy` config + Semgrep rules.
The IDs `M1`–`M6` are placeholders for the managed repo's own detector
class; real bindings live in that repo's private config, not here.

| Code | Description | Status | Destination | Blocking | Replacement | Migration Notes |
|---|---|---|---|---|---|---|
| M1 | Capability DDD folder shape | fixed | `custodian_policy` (A2 declarative) | Yes | `architecture.directory_structure` in `.custodian/config.yaml` | **DONE.** Python detector replaced by A2 declarative directory-shape rule. |
| M2 | Singleton-DB direct import outside the canonical adapter | fixed | `custodian_policy` (A1 declarative) | Yes | `architecture.invariants[forbidden_import]` in `.custodian/config.yaml` | **DONE.** Migrated to A1 `forbidden_import` rule. |
| M3 | Raw `os.environ` / `os.getenv` outside config/setup paths | fixed | `semgrep` | Yes | `<managed-repo>/.custodian/rules/semgrep/m3_no_raw_os_environ.yaml` | **DONE (2026-05-05).** Path scope mirrors `audit.c13_allowed_paths`. C13 native detector kept as a generic baseline. |
| M4 | Runtime `src/**` imports `tools.audit` / `tools.reports` | fixed | `custodian_policy` (A1 declarative) | Yes | `architecture.layers[forbidden_import_prefix]` in `.custodian/config.yaml` | **DONE.** Two `forbidden_import_prefix` rules (tools.audit, tools.reports). |
| M5 | God-object field-count guard for a context dataclass | fixed | `custodian_policy` (A1 declarative) | No (advisory) | `architecture.invariants[class_field_count]` in `.custodian/config.yaml` | **DONE.** Migrated to declarative class-field-count check. |
| M6 | Stage class exists but is not wired into pipeline | open | `custodian_policy` | Yes | None | Cross-file wiring check — requires reading multiple wiring files and matching against stage class definitions. Custom Python remains the right home (no declarative or Semgrep equivalent). Permanently a managed-repo concern. |

---

## Mandatory Decisions

### D6 — Class Referenced in Annotations but Never Constructed

**Decision: `custodian_policy` (advisory, non-blocking)**

Rationale: This detector catches a real architectural pattern — DTOs wired into type signatures on the consumer side but never produced. No static analysis tool (Ruff, Semgrep, Vulture, mypy, ty) detects this because it requires correlating type annotations with constructor call sites across the entire call graph, which is precisely what Custodian's `call_graph` pass does.

The high false-positive rate (dict-registry factories, string-based dispatch) makes this unsuitable as a CI blocker. Advisory signal is the correct use.

**Keep permanently as advisory.**

---

### D7 — Dead Method Parameter

**Decision: `retire`**

Rationale:
1. The 35 remaining VF findings are all keyword-only params (after `*`) that cannot be renamed to `_param` without breaking every call site. The detector correctly identifies them but they are unfixable without an API change.
2. The signal-to-noise ratio is poor: Protocol implementations, framework callbacks, and interface-required params all trigger false positives that require per-function suppression logic.
3. Type checkers (`ty`/`mypy`) surface unused params through different mechanisms with better context.
4. Maintenance cost: the `del param` idiom, `@override` skip, `raise NIE` stub skip, and dunder skip all add complexity that will not exist in the new architecture.

**Retire. Do not replace.**

---

### F3 — Dead Pydantic BaseModel/BaseSettings Field

**Decision: `custodian_policy` (advisory, non-blocking)**

Rationale: Vulture cannot see Pydantic's runtime deserialization. `model_validate()`, `parse_obj()`, and `BaseSettings` environ loading are invisible to static analysis. Custodian's `model_validate_classes` tracking plus transitive expansion across nested models is domain-specific knowledge that belongs here permanently.

The MongoDB fields currently flagged (VF F3=11) are genuine schema fields whose liveness cannot be verified statically — this is an acceptable known gap.

**Keep permanently as advisory.**

---

### ty / mypy Strategy

**Primary:** `ty` (Astral's type checker, fast-path adapter)  
**Fallback:** `mypy` (stable, well-understood)

| Question | Answer |
|---|---|
| When is ty used? | When `ty` binary is available on PATH and `tools.ty.enabled: true` in config |
| When is mypy used? | When ty is unavailable or `tools.mypy.enabled: true` explicitly; adapter tries ty first, falls back to mypy |
| Can both run? | Yes, if both are enabled — findings are deduplicated by (path, line, rule) before normalization |
| How do findings normalize? | Both adapters emit `Finding(tool="ty"\|"mypy", rule=<rule_code>, severity=<mapped>, ...)` — identical shape |
| Do type failures block CI? | Repo-configurable via `policy.fail_on`; default: non-blocking during Phase 6 transition, blocking once type coverage is proven |

**ty is currently pre-release / experimental.** The mypy fallback is not optional — the adapter must implement it. Phase 6 should gate on ty stability before making it the default.

---

## Config Migration Plan

### Current Schema (all repos)

```yaml
repo_key: <str>          # required
src_root: <str>          # required
tests_root: <str>        # required

audit:                   # optional
  exclude_paths:
    <CODE>:
      - <glob>
  stale_handlers: [...]  # OC-specific
  common_words: [...]    # OC-specific
  plugin_audit_keys: [...] # OC-specific
  known_values: [...]    # OC-specific
  oc1_exempt: [...]
  oc7_exempt: [...]

architecture:            # optional
  layers:
    - name: <str>
      glob: <str>
      may_not_import: [...]
  invariants:            # optional
    - glob: <str>
      max_lines: <int>
      max_classes: <int>
      max_functions: <int>
      forbidden_import: <str>

detectors:               # optional
  - module: <module:function>

plugins:                 # optional
  - module: <module:class>

maintenance:             # optional
  stale_pr_days: <int>
  stale_state_days: <int>
```

### Target Schema (new design)

```yaml
version: 1

repo:
  name: <str>
  type: python

tools:
  semgrep:
    enabled: <bool>
    configs: [...]
  ruff:
    enabled: <bool>
  ty:
    enabled: <bool>
  mypy:
    enabled: <bool>
  pytest:
    enabled: <bool>
    command: [...]
  vulture:
    enabled: <bool>
  pip_audit:
    enabled: <bool>

policy:
  fail_on: [HIGH, CRITICAL]
  ignore: [...]

architecture:
  layers: [...]          # same shape as current
  invariants: [...]      # same shape as current

reports:
  json: <bool>
  sarif: <bool>
  markdown: <bool>
```

### Compatibility Strategy

**Phase 9 implements this. Phases 1–8 use old schema only.**

1. **Support both schemas simultaneously** — the internal `Config` model is the single source of truth; both old and new schema load into it.
2. **Auto-normalize old schema** — `repo_key` → `repo.name`, `audit.exclude_paths` → tool-specific `exclude` blocks, `architecture` → unchanged (same shape).
3. **Warn on old keys, do not fail** — loading an old-schema file emits deprecation warnings to stderr; audit still runs. The `doctor` command surfaces these warnings.
4. **New key `tools:` is additive** — old configs without `tools:` get Custodian's defaults (all tools disabled until explicitly enabled).
5. **Future migration command** — `custodian config migrate` (Phase 9) rewrites `.custodian/config.yaml` in place to new schema with a backup.

### Keys that survive unchanged

`architecture.layers`, `architecture.invariants` — identical in both schemas, no migration needed.

### Keys that are deprecated (warn, don't fail)

`repo_key` → `repo.name`  
`audit.exclude_paths` → per-tool `exclude` configuration  
`audit.stale_handlers`, `audit.common_words`, `audit.plugin_audit_keys`, `audit.known_values` → plugin config block (TBD)  
`detectors`, `plugins` → plugin system preserved but renamed  
`maintenance` → separate `maintenance:` top-level block (same shape)

---

## Test Migration Plan

### Current test suite (393 tests)

Tests fall into four categories:

| Category | Count (approx) | Disposition |
|---|---|---|
| AST detector unit tests (`test_code_health_detectors.py`, `test_dead_code_detectors.py`, etc.) | ~300 | **Delete after Phase 12** (detector deletion); keep until then |
| Config/doctor tests (`test_cli_doctor.py`, `test_config.py`) | ~30 | **Rewrite** around new config model in Phase 9 |
| Call graph / analysis pass tests | ~40 | **Partial keep** — call_graph is retained for D6/F3/S2; tests remain |
| Integration / multi-repo tests | ~20 | **Rewrite** around adapter outputs in Phase 11 |

### New tests to add (by phase)

| Phase | New Tests |
|---|---|
| Phase 1 | `test_finding_model.py` — Finding construction, equality, serialization |
| Phase 1 | `test_adapter_interface.py` — ToolAdapter contract (is_available, run, error handling) |
| Phase 2 | `test_ruff_adapter.py` — JSON parsing, Finding normalization, tool-unavailable behavior |
| Phase 3 | `test_ruff_parity.py` — old C-class detector vs Ruff adapter on known inputs |
| Phase 4 | `test_semgrep_adapter.py` — SARIF parsing, Finding normalization |
| Phase 5 | `test_policy_layer.py` — fail_on severity filtering, ignore glob matching |
| Phase 6 | `test_ty_adapter.py`, `test_mypy_adapter.py`, `test_type_adapter_fallback.py` |
| Phase 7 | `test_vulture_adapter.py` |
| Phase 9 | `test_config_old_schema.py` — old keys load without error, deprecation warnings emitted |
| Phase 9 | `test_config_new_schema.py` — new schema loads cleanly |
| Phase 10 | `test_json_report.py`, `test_sarif_report.py`, `test_markdown_report.py` |
| Phase 11 | Replace old detector tests with adapter + policy tests |

### Test deletion policy

**Do not delete any existing tests until the corresponding detector is deleted (Phase 12).**  
Add new tests first. Old tests serve as regression guards during the migration.  
Exception: `test_ruff_parity.py` in Phase 3 explicitly compares old vs new — once parity is confirmed, old detector test can be removed.

### Tool-unavailable behavior (must be tested in every adapter)

Every adapter must handle the case where the external tool is not installed:
- `is_available()` returns `False`
- `run()` returns empty list (not an error)
- Runner emits a warning finding: `Finding(tool=<name>, rule="TOOL_UNAVAILABLE", severity="LOW", ...)`
- CI does not fail on tool-unavailable unless `policy.require_tools: true`

---

## Phase 1 Readiness Checklist

```
[x] Every detector has a final destination
[x] D6 decision recorded — custodian_policy advisory (permanent)
[x] D7 decision recorded — retire
[x] F3 decision recorded — custodian_policy advisory (permanent)
[x] ty/mypy strategy recorded — ty primary, mypy fallback, both adapters required
[x] Old config compatibility strategy recorded — warn-don't-fail, auto-normalize in Phase 9
[x] Test migration strategy recorded — keep existing until Phase 12, add new first
[x] No detector deletion performed
[x] No existing .custodian/config.yaml broken
```

**Phase 0 is complete. Phase 1 may begin.**

---

## Destination Summary

| Destination | Count | Detectors |
|---|---|---|
| `ruff` | 17 | C2, C3, C4, C5, C10, C12, C13, C14, C15, C18, C19, C20, C21, C23*, C24, C26, C27, C31, D4*, E1, E2, I1, X1, X2 |
| `semgrep` | 5 | C28, C32, S3, AI3, VF3 |
| `ty` / `mypy_fallback` | 1 | D3 |
| `vulture_advisory` | 4 | D1, D5, F1, F2 |
| `custodian_policy` | 20 | C8, C11*, D6, F3, S1, S2, A1, T1, T2, U1, U2, U3, OC2, OC3, OC8, OC9, AI1 (→A1), AI2 (→S1), AI4, VF2 (→A1), VF4 (→A1) |
| `custodian_hygiene` | 8 | C1, C6, C9*, C29, C33, G1, OC5* |
| `retire` | 7 | C7, C22, C25, D2, D7, OC1, OC4, OC6, OC7 |

*C9: delegate catch to Ruff `BLE001`, drop logger-nuance requirement  
*C11: no Ruff equivalent, keep as advisory  
*C23: Ruff for pattern, Semgrep for architectural exclusions

---

## Post-Phase 0 Detectors (added in sessions 4–5, 2026-05-02)

These detectors were built natively after Phase 0 was complete. All are `custodian_policy` (no external tool equivalent).

### C-class additions

| Code | Description | Severity | Module | Destination | FP Risk | Notes |
|---|---|---|---|---|---|---|
| C34 | Commented-out `def`/`class`/decorator definition | LOW | code_health.py | `custodian_policy` | LOW | Regex-based; these patterns are almost never English prose. Found dead commented-out code in VF filter_function.py on first run. |
| C35 | Bare `# type: ignore` without error-code brackets | LOW | code_health.py | `custodian_policy` | LOW | tokenize-based to avoid string/docstring false positives. Found 23 in VF on first run, all fixed. |
| C36 | Built-in `open()` in text mode without `encoding=` | LOW | code_health.py | `custodian_policy` | LOW | AST-based; only flags `ast.Name(id="open")` — not `wave.open`, `Image.open`, etc. All repos already clean on first run. |

### D-class additions

| Code | Description | Severity | Module | Destination | FP Risk | Notes |
|---|---|---|---|---|---|---|
| D8 | Function returns value on some paths, implicit-None on others | LOW | dead_code.py | `custodian_policy` | LOW | AST-based with `_all_paths_terminate()` helper. Handles `with`-blocks and `while True:` correctly. Found `_initial_authenticate()` fall-through in VF. |
| D9 | `try/except` handler whose sole statement is a bare `raise` (no-op) | LOW | dead_code.py | `custodian_policy` | LOW | Only flags single-handler try blocks — multi-handler bare reraises are intentional filtering. Found 2 in VF on first run, both removed. |

### K-class (new class — documentation consistency)

| Code | Description | Severity | Module | Destination | FP Risk | Notes |
|---|---|---|---|---|---|---|
| K1 | Backtick symbol in docs with no matching `def`/`class` in src | LOW | docs.py | `custodian_policy` | MEDIUM | Skips deferred/deprecated/historical sections. `audit.common_words` and `audit.stale_handlers` suppress known vocabulary. |
| K2 | Backtick value on a status/state line not present as string literal in src | LOW | docs.py | `custodian_policy` | MEDIUM | `audit.known_values` suppresses common English words that aren't project-specific enum values. |
| K3 | Google-style docstring `Args:` section names a parameter not in the function signature | LOW | docs.py | `custodian_policy` | LOW | AST-based. `_GOOGLE_SECTION_HEADERS` prevents `Returns`, `Raises`, `Kwargs`, etc. from being treated as parameter names. Found `policy` → `_policy` drift in OC `explain.py` on first run. |

### Other class additions

| Code | Description | Severity | Module | Destination | FP Risk | Notes |
|---|---|---|---|---|---|---|
| A2 | Directory structure invariant violation (declarative YAML) | MEDIUM | structure.py | `custodian_policy` | LOW | Generic version of VF's DDD folder-shape check. Config: `architecture.directory_structure` with glob/required_files/required_dirs/exclude. |
| H1 | Hexagonal architecture layer ordering violation | MEDIUM | structure.py | `custodian_policy` | LOW | Layers declared in `architecture.hex` in order from innermost to outermost; each layer may only import from layers with lower index. More concise than S1's explicit `may_not_import` lists. |
| N1 | Exception class name does not follow Error/Exception/Warning convention | LOW | naming.py | `custodian_policy` | LOW | AST-based. Flags classes that inherit from `Exception`/`BaseException` but don't end in `Error`, `Exception`, or `Warning`. |
| T3 | Unconditional `pytest.skip()` without environment gate | LOW | test_shape.py | `custodian_policy` | LOW | Absorbed OC5. Configurable env-gate hints via `audit.t3_env_gate_hints`. |
| S4 | `tests/conftest.py` missing venv guard | MEDIUM | structure.py | `custodian_policy` | LOW | Detects missing `if not os.environ.get("VIRTUAL_ENV"): pytest.exit(...)` guard. |
| P1 | Hollow return body (returns only empty collection/None) | LOW | stubs.py | `custodian_policy` | LOW | Absorbed partial-implementation detection alongside U1-U3. |  
*OC5: pending Ruff PT rule verification
