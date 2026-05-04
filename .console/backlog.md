# Backlog

## In Progress

_(none)_

## Recent

- [x] **T6/T7/T8 — test-presence detector trio (2026-05-04, on main)**: Three new T-class detectors. T6 = src module never imported by any test (file-level companion to T1's symbol-level coverage). T7 = src module has no parallel `test_<name>.py` (convention enforcement; accepts `tests/{unit,integration,contract,regression}/[mirror/]test_<name>.py`). T8 = test file imports nothing from any src package (dangling test detection). All three configurable via `audit.exclude_paths.T6/T7/T8`, `audit.t7_test_dirs`, `audit.t8_exempt`. 20 new tests; full Custodian suite 773 pass.

## Refactor — Master Phase List ✅ ALL 15 PHASES COMPLETE

**Phase 0** ✅ Detector disposition matrix (984c000)
**Phase 1** ✅ Finding model, ToolAdapter ABC, runner.py, package stubs (caadf29)
**Phase 2** ✅ Ruff adapter — JSON parsing, severity prefix map, 23 tests (b5794a0)
**Phase 3** ✅ Deprecated detector flags, --skip-deprecated CLI flag (b5794a0)
**Phase 4** ✅ Semgrep adapter — JSON output parsing, 23 tests (3d8a3cb)
**Phase 5** ✅ Policy layer — apply_policy(), architecture boundary checks (f69db99)
**Phase 6** ✅ ty adapter (concise format) + mypy adapter (fallback), 28 tests (541e374)
**Phase 7** ✅ Vulture adapter — advisory dead-code, confidence threshold, 18 tests (7187d04)
**Phase 8** ✅ Codemod base — Codemod ABC, run_codemods(), custodian-fix CLI (ebcd026)
**Phase 9** ✅ Config migration — dual-schema loader, DeprecationWarning, custodian-config CLI (0de95cf)
**Phase 10** ✅ Reports — JSON/SARIF/Markdown builders, 25 tests (36230ee)
**Phase 11** ✅ Integration tests — adapter→filter→report pipeline (ed7719a)
**Phase 12** ✅ Deprecated detector cleanup — 27 stub replacements, 325 lines deleted (f287d93)
**Phase 13** ✅ CLI finalization — custodian-report + unified custodian dispatcher (9ec3ea9)
**Phase 14** ✅ Pre-commit integration — .pre-commit-hooks.yaml + local config (05f6336)
**Phase 15** ✅ Multi-repo enhancements — --skip-deprecated, --report-dir (432a58d)

**S4 detector** ✅ tests/conftest.py venv guard check + Custodian's own conftest guard (80b6ea6)

**Repo-level issues remaining**
- VF: C9=289 (broad except), D1=~0 (bulk cleared round 9), D3=~40 missing NoReturn, D5=0 (resolved), D6=3 (DeliveryDTO/OutlineSection/NLTKCheckStage — false positives), D7=35 (keyword-only params, can't rename), F3=11 (MongoDB fields)
- OC: F3=6 (schema/contract fields — mostly false positives), F1=10 dead dataclass fields, C29=6 (long files)
- SB: C19=1 (global _ in logging.py — i18n gettext pattern, acceptable), D5=1 (DecisionSink port class)

## Done (this session — round 9, committed)

**VF (committed 66689c01/dev):**
- [x] D1: 42 dead functions removed in bulk across 30+ files; align_text_to_scene false positive already resolved in round 8
- [x] D5: VideoPerformance class deleted (orphaned after get_video_performance deleted)
- [x] F2: _BRANDING_MAP + _BRANDING_DIR + _BRANDING_HEADER_RE + Template import removed from dynamic_loader.py (orphaned after branding functions deleted)
- [x] I1: contextlib import removed from voice.py (orphaned)
- [x] D1: audit_summary.py deleted (build_request_audit_summary + build_segment_diagnostics dead, no importers)
- [x] D1: validation.py deleted (validate_model dead, no callers)
- [x] VF audit: 2173→~2024 (-149 this round, estimate; actual total TBD)
- [x] 1660 tests passing; 7 pre-existing failures unchanged

## Done (this session — round 8, committed)

**Custodian (committed 55282f8/main):**
- [x] F3: model_validate_classes — classes deserialized via ClassName.model_validate*() have all fields treated as live
- [x] F3: transitive expansion — nested Pydantic models under deserialized classes also treated as schema fields
- [x] 393 tests passing (+2 new F3 tests)

**VF (committed daa84710 + d0e73ef4 + next/dev):**
- [x] D5: 7 dead classes removed (AudioAdder, StableDiffusionManager, StringEnumBase, LineMetadataDTO, StepTrace, ScriptOutline, PipelineDispatchPolicyImpl)
- [x] D7: 2 positional params renamed with _ prefix (abstract, background_video)
- [x] D1: 6 dead functions removed (apply_old/new_installer_defaults, apply_parallax, bad_request, bring_down, build_chunk_plan_rows); align_text_to_scene restored + __all__ (monkey-patched by runtime_hooks — D1 false positive)
- [x] VF audit: 2208→2173 (-35 this round)

**OC: F3: 24→6 (-18 from model_validate fix)**

## Done (this session — rounds 6–7, committed)

**Custodian (committed 0efa644/main):**
- [x] D7: del var = use, @override skip, raise NIE = stub; F3: dynamic_getattr_classes
- [x] test_cli_doctor PYTHONPATH subprocess fix; 391 tests passing

**OC (committed 4fda3ce + 5635b6a/main):**
- [x] D7: 46 findings → 0 (44 _-prefix renames, 2 wired); F1: 2 dead fields removed; C7: assert True fixed
- [x] multi_step_planning: repo_key wired into step titles/goals; usage_store: del now marker
- [x] OC1/OC7 plugins retired (→ deferred); superseded by U1-U3 and F3

**VF (committed 6e21593d/dev):**
- [x] D7: 11 params renamed; F3: BreathGroup class + cadence field removed; T2: 22→0 assertions

**SB (committed 33bedcc/main):**
- [x] D7: _build_factors params renamed; F3: 5 dead CapabilityModel fields removed; policy_path false positive fixed

**Audit totals committed: VF 2208, OC 478, SB 41. Total 2727 (was 2852, -125 this session)**

## Done (this session — round 5)

- [x] C33: ghost-work comment density detector (per-file TODO/FIXME/HACK/XXX count ≥ threshold; configurable via audit.c33_threshold, default 5)
- [x] D7: dead method parameter detector (param never referenced in function body; skips self/cls/_, **kwargs, @abstractmethod, stub bodies, dunder methods)
- [x] F3: Pydantic BaseModel field liveness (fields never accessed as attributes or set via constructor kwarg)
- [x] A1: architecture invariant checker (declarative YAML: max_lines, max_classes, max_functions, forbidden_import per glob)
- [x] call_graph improvements: kw_arg_names tracking (Model(field=value) records kwarg names), getattr() string tracking (getattr(obj, "field") records "field" as accessed_attr)
- [x] D7 false positive fix: skip dunder methods (__exit__, __getitem__ etc. — protocol-required params)
- [x] Custodian 351→378 tests (+27); 62 detectors live
- [x] Audit round 5: VF 2267 (D7=66, F3=20), OC 535 (D7=54, F3=24), SB 50 (D7=3, F3=6); total 2852

## Done (this session — round 3)

- [x] D5: dead class detector (module-level classes never referenced via Name Load or attr access)
- [x] C31: weak hash detector (hashlib.md5/sha1 without usedforsecurity=False)
- [x] C32: hardcoded credential detector (word-boundary matching, URL/env-var-name exclusions)
- [x] S3: test import in src detector (production code importing from tests.* or test_*)
- [x] D5 false positive fixes: skip Protocol/ABC bases; check called_attrs+accessed_attrs for module-aliased refs
- [x] C32 false positive fixes: bigram matching, URL value exclusion, ALL_CAPS env-var-name exclusion, suffix exclusions
- [x] VF C31: sha1() → sha1(..., usedforsecurity=False) in topic_selection.py and outline_planning.py
- [x] OC C31: sha1() → sha1(..., usedforsecurity=False) in proposal_builder.py
- [x] OC D5: deleted ArchonFailureInfo, KodoFailureInfo, OpenClawFailureInfo, OpenClawEventDetailRef, ChildTaskSpec → REVERSED: these were partial-pipeline DTOs, not dead code
- [x] OC classes restored + wired: ArchonFailureInfo/KodoFailureInfo/OpenClawFailureInfo → _extract_failure_info() in normalize.py; OpenClawEventDetailRef → build_backend_detail_refs(); ChildTaskSpec → _create_child_task()
- [x] D6: class-referenced-but-never-instantiated detector (constructed_names tracks: direct calls, ClassName.method(), ClassName[T]() generics, default_factory= kwargs, base class inheritance, enum member access)
- [x] D6 false positives resolved: Pydantic BaseModel/BaseSettings/TypedDict skipped; Enum/StrEnum fixed via attr access tracking; ChannelFactory/OpenClawBridge fixed via attr access; Batcher generic constructor fixed; PromptBookDataStructure base class fixed
- [x] OC C23: excluded orchestration files from C23 (shell=True from trusted YAML config is intentional)
- [x] VF CoquiTTS: marked __all__ (loaded via factory string registry)
- [x] Custodian 309→351 tests (+42); 57 detectors live
- [x] OC 3019 tests passing after class restores
- [x] Audit: VF 2226→2207, OC 483→456, SB 42→41; total 2751→2704; OC HIGH=0

## Done (round 2 — earlier in session)

- [x] C2: AST-based print() detection (skips string literals/docstrings)
- [x] C16: skip write_text with 2+ positional args (custom method heuristic via _top_level_arg_count)
- [x] C-class: skip_comment_lines flag for C2-C5, C18-C26 (commented-out code no longer triggers)
- [x] T2: recognize assert_*() module-level function calls as assertions
- [x] call_graph: track all Name Load nodes (target=func_name patterns no longer D1 false positives)
- [x] U1/U2/U3: skip functions inside except-handler fallback stubs
- [x] VF C20: eval(frame_rate) → float(Fraction()) in ffprobe.py
- [x] OC: 22+ T2 test stubs fixed (explicit assertions across 5 test files)
- [x] OC: prompt_repo deleted; detect_config_drift/run_pipeline/https_remote_to_ssh marked __all__
- [x] SB: errors.py + tracing.py marked __all__; obsolete C2 planner.py exclusion removed
- [x] Audit progress: VF 2253→2199, OC 495→475, SB 48→41

## Done (round 1 — previous session)

- [x] C26–C29 security/quality detectors (os.system, assert False, hardcoded IP, file too long)
- [x] I1 unused imports detector
- [x] T2: pytest.raises/warns, self.assertX/failX, mock.assert_*(), raise AssertionError
- [x] D3 bug fix: _has_return_in_scope pre-check
- [x] D1: framework_decorated skips @app.command, @router.get, @pytest.fixture
- [x] C18 regex fix: -f"..." flags and "f","h" list elements
- [x] F1: skip serialization-method dataclasses; scan tests_root as extra_roots
- [x] OC/VF: D4/D3/F2/E1/E2/I1/C16-C18 fixed across 30 files
- [x] Custodian 303→309 tests; C1–C29, S1–S2, U1–U3, D1–D4, F1–F2, E1–E2, T1–T2, X1–X2, G1, I1 all live
