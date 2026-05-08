# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""T-class detectors — test coverage shape.

Detectors
─────────
T1  Public src functions and classes with zero name references in tests.
    Uses the tests_forest pass to collect all ast.Name occurrences in
    test files, then flags public src symbols whose name never appears.
    Conservative: only checks module-level definitions, excludes private

T3  Unconditional pytest.skip() call or @pytest.mark.skip decorator with
    no environment-gate context in the surrounding lines. A skip that is
    not conditioned on a missing tool, platform, or env var silently
    drops test coverage permanently. Configure extra gate hints via
    ``audit.t3_env_gate_hints`` in ``.custodian.yaml``.

T4  Orphan pytest fixture — a function decorated with ``@pytest.fixture``
    that is never requested by any test function or other fixture.  An
    orphan fixture adds setup cost (import, potential side effects) but
    provides no coverage value.  Fixtures with ``autouse=True`` are
    excluded (they apply implicitly).  Built-in fixtures (``tmp_path``,
    ``capsys``, etc.) are not flagged because they are not defined in the
    codebase.  Fixtures defined in ``conftest.py`` are included in the
    search but so are their callers across the whole tests tree.
    names and dunder names.  LOW severity — indirect testing via wrappers
    and integration tests will produce false positives.

T2  Test functions with no assertion — a function whose name starts with
    ``test_`` and whose body contains no assertion mechanism.  Recognized
    assertion forms: ``assert`` statements, ``pytest.raises/warns/
    deprecated_call`` context managers, unittest-style ``self.assertX``
    / ``self.failX`` calls, and Mock-style ``mock.assert_called_once()``
    / ``mock.assert_not_called()`` / ``mock.assert_any_call()`` etc.

T5  ``@pytest.mark.parametrize`` with exactly one test case — when a
    parametrize decorator supplies only a single literal value (or tuple),
    the parametrize wrapper adds indirection with no benefit; the test
    should be a regular function with the value inlined.  Only flags
    literal lists; variable-length argument lists (``[*cases]``) are skipped.

T6  Src module is never imported by any test file. Module-level companion
    to T1 (which works at the symbol level). Builds the dotted name of
    every src module (e.g. ``foo.bar``), collects every ``import X`` /
    ``from X import y`` reference from tests with prefix expansion, flags
    any module whose dotted path is never seen. Skips ``__init__.py`` and
    dunder files. Excludes via ``audit.exclude_paths.T6``.

T7  Src module has no parallel test file. For ``src/foo/bar.py``, accepts
    ``tests/test_bar.py``, ``tests/foo/test_bar.py``, or any of the same
    under ``tests/{unit,integration,contract,regression}/``. Skips
    ``__init__.py`` and dunders. Custom test sub-dirs via
    ``audit.t7_test_dirs``. Excludes via ``audit.exclude_paths.T7``.

T8  Test file imports nothing from any src package. Derives src package
    names from ``src_root`` direct children, then flags ``test_*.py`` files
    whose imports never reach any of those packages — they're dangling
    tests that don't exercise the codebase under audit. Skips
    ``conftest.py`` and ``__init__.py``. Custom exempt files via
    ``audit.t8_exempt``.
"""
from __future__ import annotations

import ast
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)
from custodian.audit_kit.glob_match import glob_match

_MAX_SAMPLES = 8
_NEEDS_TF = frozenset({"ast_forest", "tests_forest"})


def build_test_shape_detectors() -> list[Detector]:
    return [
        Detector("T1", "public src symbol with no reference in tests", "open",
                 detect_t1, LOW, _NEEDS_TF),
        Detector("T2", "test function with no assert statement", "open",
                 detect_t2, LOW),
        Detector("T3", "unconditional pytest.skip without environment gate", "open",
                 detect_t3, LOW),
        Detector("T4", "pytest fixture defined but never requested by any test or fixture", "open",
                 detect_t4, LOW),
        Detector("T5", "pytest.mark.parametrize with a single test case — should be a plain test", "open",
                 detect_t5, LOW),
        Detector("T6", "src module is never imported by any test file", "open",
                 detect_t6, LOW, _NEEDS_TF),
        Detector("T7", "src module has no parallel test file under tests/", "open",
                 detect_t7, LOW),
        Detector("T8", "test file imports nothing from any src package", "open",
                 detect_t8, LOW),
    ]


# ── helpers ───────────────────────────────────────────────────────────────────

_PYTEST_ASSERTION_ATTRS = frozenset({
    "raises", "warns", "deprecated_call", "approx", "fail",
})

_MOCK_ASSERT_PREFIXES = ("assert_called", "assert_any_call", "assert_has_calls", "assert_not_called")


def _has_assertion_mechanism(node: ast.AST) -> bool:
    """True if the subtree contains any recognized assertion mechanism.

    Recognized forms:
    - ast.Assert (``assert x``)
    - pytest.raises / pytest.warns / etc. (``with pytest.raises(...):`` or call)
    - self.assertX / self.failX (unittest-style)
    - mock.assert_called_once() / mock.assert_not_called() / etc. (Mock-style)
    - raise AssertionError(...) — explicit assertion failure
    """
    for child in ast.walk(node):
        if isinstance(child, ast.Assert):
            return True
        # raise AssertionError(...) — explicit fail as assertion
        if isinstance(child, ast.Raise) and child.exc is not None:
            exc = child.exc
            if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
                if exc.func.id == "AssertionError":
                    return True
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        if not isinstance(func, ast.Attribute):
            continue
        attr = func.attr
        value = func.value
        # pytest.raises / pytest.warns / pytest.deprecated_call
        if isinstance(value, ast.Name) and value.id == "pytest":
            if attr in _PYTEST_ASSERTION_ATTRS:
                return True
        # self.assertX / self.failX (unittest)
        if isinstance(value, ast.Name) and value.id == "self":
            if attr.startswith("assert") or attr.startswith("fail"):
                return True
        # mock.assert_called_once() / mock.assert_not_called() / etc.
        if any(attr.startswith(p) for p in _MOCK_ASSERT_PREFIXES):
            return True
    # assert_*() module-level function calls (e.g. assert_no_mutation_fields(x))
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id.startswith("assert_")
        ):
            return True
    return False


def _parse_test_files(tests_root: Path) -> list[tuple[Path, ast.Module]]:
    results: list[tuple[Path, ast.Module]] = []
    if not tests_root.is_dir():
        return results
    for path in sorted(tests_root.rglob("*.py")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        results.append((path, tree))
    return results


# ── T1 ────────────────────────────────────────────────────────────────────────

def _t1_excluded_paths(context: AuditContext) -> set[str]:
    """Repo-relative path strings excluded from T1 via audit.exclude_paths.T1."""
    from custodian.audit_kit.code_health import _glob_to_regex
    audit_cfg = context.config.get("audit") or {}
    globs: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("T1") or [])
    if not globs:
        return set()
    patterns = [_glob_to_regex(g) for g in globs]
    excluded: set[str] = set()
    for path in context.src_root.rglob("*.py"):
        if not path.is_file():
            continue
        rel = path.relative_to(context.repo_root).as_posix()
        if any(p.match(rel) for p in patterns):
            excluded.add(str(path))
    return excluded


def detect_t1(context: AuditContext) -> DetectorResult:
    """Flag public src functions/classes whose name never appears in any test file."""
    if (context.graph is None
            or context.graph.ast_forest is None
            or context.graph.tests_forest is None):
        return DetectorResult(count=0, samples=[])

    # Collect every ast.Name id that appears anywhere in tests
    test_name_refs: set[str] = set()
    for _path, tree, _src in context.graph.tests_forest.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                test_name_refs.add(node.id)
            elif isinstance(node, ast.Attribute):
                test_name_refs.add(node.attr)

    excluded_paths = _t1_excluded_paths(context)
    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        if str(path) in excluded_paths:
            continue
        rel = path.relative_to(context.repo_root)
        for stmt in tree.body:  # module-level only
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            name = stmt.name
            if name.startswith("_"):
                continue
            if name in test_name_refs:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                kind = "class" if isinstance(stmt, ast.ClassDef) else "def"
                samples.append(f"{rel}:{stmt.lineno}: {kind} {name} — no test reference")

    return DetectorResult(count=count, samples=samples)


# ── T2 ────────────────────────────────────────────────────────────────────────

def detect_t2(context: AuditContext) -> DetectorResult:
    """Flag test_ functions whose body contains no assert statement."""
    audit_cfg: dict = context.config.get("audit") or {}
    t2_excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("T2") or [])

    samples: list[str] = []
    count = 0

    for path, tree in _parse_test_files(context.tests_root):
        rel = path.relative_to(context.repo_root)
        rel_posix = rel.as_posix()
        if t2_excludes and any(glob_match(rel_posix, excl) for excl in t2_excludes):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            if not _has_assertion_mechanism(node):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(f"{rel}:{node.lineno}: {node.name}() — no assert")

    return DetectorResult(count=count, samples=samples)


# ── T3 ────────────────────────────────────────────────────────────────────────

_DEFAULT_ENV_GATE_HINTS = (
    "os.environ", "os.getenv", "pytest.importorskip", "shutil.which",
    "sys.platform", "sys.version", "importlib", "skipif", "reason=",
    "not in fixture", "no records", "not present", "fixture",
)


def detect_t3(context: AuditContext) -> DetectorResult:
    """Flag pytest.skip() / @pytest.mark.skip without an environment-gate hint nearby.

    Scans a 7-line window (6 lines before the skip + the skip line itself) for
    any env-gate hint. Configurable extra hints via ``audit.t3_env_gate_hints``
    in ``.custodian.yaml``. Unconditional skips silently drop coverage; they
    should be guarded by an env/tool check or replaced with pytest.mark.xfail.
    """
    audit_cfg = context.config.get("audit") or {}
    extra_hints: list[str] = list(audit_cfg.get("t3_env_gate_hints") or [])
    hints = _DEFAULT_ENV_GATE_HINTS + tuple(extra_hints)

    samples: list[str] = []
    count = 0
    for path, _tree in _parse_test_files(context.tests_root):
        rel = path.relative_to(context.repo_root)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            is_call = "pytest.skip(" in line
            is_decorator = stripped.startswith("@pytest.mark.skip")
            if not is_call and not is_decorator:
                continue
            window = "\n".join(lines[max(0, i - 7): i])
            if any(h.lower() in window.lower() for h in hints):
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{rel}:{i}: {line.strip()[:80]}")
    return DetectorResult(count=count, samples=samples)


# ── T4 ────────────────────────────────────────────────────────────────────────

def _is_fixture_decorator(dec: ast.expr) -> bool:
    """Return True if the decorator is @pytest.fixture or @fixture (with or without args)."""
    if isinstance(dec, ast.Attribute) and dec.attr == "fixture":
        return True
    if isinstance(dec, ast.Name) and dec.id == "fixture":
        return True
    if isinstance(dec, ast.Call):
        return _is_fixture_decorator(dec.func)
    return False


def _fixture_is_autouse(dec: ast.expr) -> bool:
    """Return True if @pytest.fixture(autouse=True) is set."""
    if not isinstance(dec, ast.Call):
        return False
    for kw in dec.keywords:
        if kw.arg == "autouse" and isinstance(kw.value, ast.Constant) and kw.value.value:
            return True
    return False


def detect_t4(context: AuditContext) -> DetectorResult:
    """Flag pytest fixtures that are never requested by any test or other fixture.

    Collects all fixture names across the tests tree (including conftest.py),
    then collects all parameter names from test functions (``test_*``) and
    from other fixture functions.  A fixture whose name never appears in any
    parameter list is an orphan — it adds overhead but provides no coverage.

    Fixtures with ``autouse=True`` are skipped (they apply without being named).
    Exclude paths via ``audit.exclude_paths.T4``.
    """
    if not context.tests_root.is_dir():
        return DetectorResult(count=0, samples=[])

    audit_cfg = context.config.get("audit") or {}
    globs: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("T4") or [])

    from pathlib import PurePosixPath

    # Pass 1: collect fixture definitions {name → (path, lineno)}
    fixture_defs: dict[str, tuple[Path, int]] = {}
    # Pass 2: collect all parameter names across test functions and fixtures
    requested_names: set[str] = set()

    all_files: list[tuple[Path, ast.Module]] = _parse_test_files(context.tests_root)

    for path, tree in all_files:
        rel_str = str(path.relative_to(context.repo_root))
        if globs and any(PurePosixPath(rel_str).match(g) for g in globs):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            name = node.name

            # Collect parameter names from test functions and fixture functions
            is_test = name.startswith("test_")
            is_fix = any(_is_fixture_decorator(d) for d in node.decorator_list)

            if is_test or is_fix:
                for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                    if arg.arg not in ("self", "cls"):
                        requested_names.add(arg.arg)

            # Register fixture definition
            if is_fix:
                if any(_fixture_is_autouse(d) for d in node.decorator_list):
                    continue  # autouse — doesn't need to be requested
                if name not in fixture_defs:
                    fixture_defs[name] = (path, node.lineno)

    # Plugin-consumed override fixtures that are implicitly used by third-party plugins
    # (anyio, asyncio, trio, pytest-asyncio) and never explicitly requested by tests.
    _PLUGIN_OVERRIDE_FIXTURES = frozenset({
        "anyio_backend", "event_loop", "event_loop_policy", "asyncio_mode",
    })

    # Orphans: defined fixtures never appearing in any parameter list
    orphans = {
        name: loc for name, loc in fixture_defs.items()
        if name not in requested_names and name not in _PLUGIN_OVERRIDE_FIXTURES
    }

    samples = [
        f"{loc[0].relative_to(context.repo_root)}:{loc[1]}: fixture {name}() — never requested"
        for name, loc in sorted(orphans.items(), key=lambda x: (str(x[1][0]), x[1][1]))
    ]
    return DetectorResult(count=len(orphans), samples=samples[:_MAX_SAMPLES])


# ── T5 ────────────────────────────────────────────────────────────────────────

def _is_parametrize_decorator(node: ast.expr) -> bool:
    """Return True if node is pytest.mark.parametrize(...) or mark.parametrize(...)."""
    if isinstance(node, ast.Call):
        fn = node.func
        if isinstance(fn, ast.Attribute) and fn.attr == "parametrize":
            return True
    return False


def _parametrize_case_count(call: ast.Call) -> int | None:
    """Return the number of cases in the parametrize call, or None if not determinable."""
    if len(call.args) < 2:
        return None
    cases_arg = call.args[1]
    if not isinstance(cases_arg, ast.List):
        return None  # variable reference or comprehension — skip
    return len(cases_arg.elts)


def detect_t5(context: AuditContext) -> DetectorResult:
    """Flag @pytest.mark.parametrize decorators that supply exactly one test case.

    A single-case parametrize adds parametrize overhead (indirection, generated
    test ID suffix) with no benefit — the value should be inlined into a plain test.
    Only flagged when the case list is a literal ``[...]`` with one element; variable
    and comprehension arguments are skipped to avoid false positives.
    """
    if not context.tests_root.is_dir():
        return DetectorResult(count=0, samples=[])

    count = 0
    samples: list[str] = []

    for path, tree in _parse_test_files(context.tests_root):
        rel = str(path.relative_to(context.repo_root))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                if not _is_parametrize_decorator(dec):
                    continue
                # _is_parametrize_decorator() already verified Call shape.
                assert isinstance(dec, ast.Call)  # noqa: S101
                n = _parametrize_case_count(dec)
                if n != 1:
                    continue
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"{rel}:{dec.lineno}: {node.name} — parametrize with 1 case; inline the value"
                    )

    return DetectorResult(count=count, samples=samples)


# ── T6 ────────────────────────────────────────────────────────────────────────


def _module_dotted_name(path: Path, src_root: Path) -> str | None:
    """Convert ``src/foo/bar.py`` to its importable dotted name.

    Two conventions:
      1. ``src_root`` itself is a package (has ``__init__.py``): include
         the src_root basename — ``src/foo/bar.py`` → ``foo.bar``.
      2. ``src_root`` is a flat parent of packages: drop it —
         ``src/`` containing ``foo/bar.py`` → ``foo.bar``.

    Returns None for ``__init__.py`` and dunder files. ``__init__.py`` is
    excluded from T6 because the package is implicitly exercised whenever
    any submodule is imported by tests — flagging it separately produces
    noisy duplicate findings alongside its submodules.
    """
    try:
        rel = path.relative_to(src_root)
    except ValueError:
        return None
    if rel.name == "__init__.py":
        return None
    if rel.name.startswith("__") and rel.name.endswith("__.py"):
        return None
    parts = list(rel.parts[:-1]) + [rel.stem]
    if (src_root / "__init__.py").is_file():
        parts = [src_root.name] + parts
    return ".".join(parts)


def _collect_test_imports(tests_forest) -> set[str]:
    """Every dotted module name referenced via import/from-import in tests.

    For ``import a.b.c`` → emits ``a``, ``a.b``, ``a.b.c``.
    For ``from a.b import x`` → emits ``a``, ``a.b``, ``a.b.x``.
    Relative imports are resolved best-effort (skipped — they can't reach src).
    """
    imported: set[str] = set()

    def _add_with_prefixes(dotted: str) -> None:
        parts = dotted.split(".")
        for i in range(1, len(parts) + 1):
            imported.add(".".join(parts[:i]))

    for _path, tree, _src in tests_forest.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name:
                        _add_with_prefixes(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.level and node.level > 0:
                    continue  # relative import — ignore for src reachability
                if not node.module:
                    continue
                _add_with_prefixes(node.module)
                for alias in node.names:
                    if alias.name and alias.name != "*":
                        _add_with_prefixes(f"{node.module}.{alias.name}")
    return imported


def detect_t6(context: AuditContext) -> DetectorResult:
    """Flag src modules whose dotted name is never imported by any test file.

    Complements T1 (per-symbol coverage) at the file level. A module with rich
    re-exports may pass T1 (every symbol name appears somewhere) yet be an
    import-time blind spot — T6 catches that.

    Skips ``__init__.py``, dunder files, and paths matched by
    ``audit.exclude_paths.T6`` globs.
    """
    if (context.graph is None
            or context.graph.ast_forest is None
            or context.graph.tests_forest is None):
        return DetectorResult(count=0, samples=[])

    audit_cfg = context.config.get("audit") or {}
    excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("T6") or [])

    imported = _collect_test_imports(context.graph.tests_forest)

    samples: list[str] = []
    count = 0
    for path, _tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        rel_posix = rel.as_posix()
        if excludes and any(glob_match(rel_posix, g) for g in excludes):
            continue
        dotted = _module_dotted_name(path, context.src_root)
        if dotted is None:
            continue
        if dotted in imported:
            continue
        count += 1
        if len(samples) < _MAX_SAMPLES:
            samples.append(f"{rel}: module {dotted!r} not imported by any test file")
    return DetectorResult(count=count, samples=samples)


# ── T7 ────────────────────────────────────────────────────────────────────────


_DEFAULT_T7_TEST_DIR_HINTS = ("", "unit", "integration", "contract", "regression")


def _t7_candidate_paths(rel_src: Path, tests_root: Path, hints: tuple[str, ...]) -> list[Path]:
    """Build the list of acceptable parallel test file locations for one src file.

    For ``foo/bar.py`` → ``tests/test_bar.py``, ``tests/foo/test_bar.py``,
    ``tests/unit/test_bar.py``, ``tests/unit/foo/test_bar.py``, etc.
    """
    test_name = f"test_{rel_src.stem}.py"
    sub_dirs = list(rel_src.parts[:-1])  # everything except the file itself
    candidates: list[Path] = []
    for hint in hints:
        base = tests_root if not hint else tests_root / hint
        # Flat: tests/[hint]/test_bar.py
        candidates.append(base / test_name)
        # Mirrored: tests/[hint]/foo/test_bar.py
        if sub_dirs:
            candidates.append(base.joinpath(*sub_dirs) / test_name)
    return candidates


def detect_t7(context: AuditContext) -> DetectorResult:
    """Flag src modules with no parallel ``test_<name>.py`` under ``tests/``.

    Convention check. For ``src/foo/bar.py``, accepts any of:
        ``tests/test_bar.py``                ``tests/foo/test_bar.py``
        ``tests/unit/test_bar.py``           ``tests/unit/foo/test_bar.py``
        ``tests/integration/test_bar.py``    ``tests/integration/foo/test_bar.py``
        (etc., per ``audit.t7_test_dirs``)

    Skips ``__init__.py`` and dunder files. Excludes via
    ``audit.exclude_paths.T7``. Custom test sub-dirs via ``audit.t7_test_dirs``
    (defaults: unit, integration, contract, regression).
    """
    if not context.src_root.is_dir():
        return DetectorResult(count=0, samples=[])

    audit_cfg = context.config.get("audit") or {}
    excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("T7") or [])
    extra_dirs: list[str] = list(audit_cfg.get("t7_test_dirs") or [])
    hints = _DEFAULT_T7_TEST_DIR_HINTS + tuple(extra_dirs)

    samples: list[str] = []
    count = 0
    for path in sorted(context.src_root.rglob("*.py")):
        if not path.is_file():
            continue
        if path.name == "__init__.py":
            continue
        if path.name.startswith("__") and path.name.endswith("__.py"):
            continue
        rel = path.relative_to(context.repo_root)
        rel_posix = rel.as_posix()
        if excludes and any(glob_match(rel_posix, g) for g in excludes):
            continue
        rel_src = path.relative_to(context.src_root)
        candidates = _t7_candidate_paths(rel_src, context.tests_root, hints)
        if any(c.is_file() for c in candidates):
            continue
        count += 1
        if len(samples) < _MAX_SAMPLES:
            expected = (context.tests_root / "unit" / rel_src.parent / f"test_{rel_src.stem}.py")
            samples.append(
                f"{rel}: no parallel test (expected e.g. {expected.relative_to(context.repo_root)})"
            )
    return DetectorResult(count=count, samples=samples)


# ── T8 ────────────────────────────────────────────────────────────────────────


def _src_top_level_packages(src_root: Path) -> set[str]:
    """Names tests can use to import from src.

    Two conventions are accepted:
      1. ``src_root`` itself is a package (``src/foo`` with ``foo/__init__.py``)
         → tests import ``from foo.X import ...``; we add ``foo``.
      2. ``src_root`` is a flat directory of packages (``src/`` contains
         ``foo/`` and ``bar/``) → tests import ``from foo.X``; we add the
         children's names.

    Both are supported simultaneously since some repos mix them.
    """
    out: set[str] = set()
    if not src_root.is_dir():
        return out
    # Convention 1: src_root itself is the importable package.
    if (src_root / "__init__.py").is_file():
        out.add(src_root.name)
    # Convention 2: children of src_root are the importable packages.
    for child in src_root.iterdir():
        if child.is_dir() and (child / "__init__.py").is_file():
            out.add(child.name)
        elif child.is_file() and child.suffix == ".py" and child.stem != "__init__":
            out.add(child.stem)
    return out


def _file_touches_src(tree: ast.AST, src_packages: set[str]) -> bool:
    """True when any import in tree's AST touches a top-level src package."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                head = (alias.name or "").split(".", 1)[0]
                if head in src_packages:
                    return True
        elif isinstance(node, ast.ImportFrom):
            if node.level and node.level > 0:
                continue
            if not node.module:
                continue
            head = node.module.split(".", 1)[0]
            if head in src_packages or head == "src":
                return True
    return False


def _conftest_dirs_touching_src(
    tests_root: Path, src_packages: set[str],
) -> set[Path]:
    """Return dir paths whose conftest.py (or any ancestor's conftest.py)
    imports a src package.

    Pytest fixtures defined in a conftest.py are visible to every test
    file at or below that directory. So if conftest.py imports src, the
    tests under it implicitly exercise src — they're not dangling.
    """
    touching: set[Path] = set()
    for conftest in tests_root.rglob("conftest.py"):
        try:
            tree = ast.parse(conftest.read_text(encoding="utf-8", errors="replace"))
        except (OSError, SyntaxError):
            continue
        if _file_touches_src(tree, src_packages):
            touching.add(conftest.parent.resolve())
    return touching


_T8_DEFAULT_EXEMPT_GLOBS: tuple[str, ...] = (
    "tests/integration/**",
    "tests/e2e/**",
    "tests/smoke/**",
    "test/integration/**",
    "test/e2e/**",
    "test/smoke/**",
)


def detect_t8(context: AuditContext) -> DetectorResult:
    """Flag test files whose imports never reach any src package.

    A test that imports only stdlib + helpers and never touches a top-level
    src package is dangling — it doesn't exercise the codebase under audit.
    Excludes ``conftest.py`` and ``__init__.py``. Tests under a directory
    whose ``conftest.py`` (or any ancestor conftest) imports src are
    considered to touch src transitively — pytest fixtures from those
    conftests are visible to the test, so the test is not dangling.

    Default-exempt: ``tests/integration/**``, ``tests/e2e/**``,
    ``tests/smoke/**`` (and ``test/...`` variants) — these conventionally
    exercise the codebase via subprocess/HTTP/CLI rather than imports.
    Override via ``audit.t8_default_exempt: false`` to re-enable, or add
    repo-specific globs via ``audit.t8_exempt`` / ``audit.exclude_paths.T8``.
    """
    if not context.tests_root.is_dir():
        return DetectorResult(count=0, samples=[])

    audit_cfg = context.config.get("audit") or {}
    excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("T8") or [])
    extra_exempt: list[str] = list(audit_cfg.get("t8_exempt") or [])
    if audit_cfg.get("t8_default_exempt", True):
        extra_exempt = list(_T8_DEFAULT_EXEMPT_GLOBS) + extra_exempt

    src_packages = _src_top_level_packages(context.src_root)
    if not src_packages:
        return DetectorResult(count=0, samples=[])

    conftest_dirs = _conftest_dirs_touching_src(context.tests_root, src_packages)

    samples: list[str] = []
    count = 0
    for path, tree in _parse_test_files(context.tests_root):
        if path.name == "conftest.py" or path.name == "__init__.py":
            continue
        rel = path.relative_to(context.repo_root)
        rel_posix = rel.as_posix()
        if excludes and any(glob_match(rel_posix, g) for g in excludes):
            continue
        if extra_exempt and any(glob_match(rel_posix, g) for g in extra_exempt):
            continue

        # Direct import?
        if _file_touches_src(tree, src_packages):
            continue
        # Transitive via conftest? Walk ancestors up to tests_root.
        cur = path.resolve().parent
        tests_root_abs = context.tests_root.resolve()
        transitive = False
        while True:
            if cur in conftest_dirs:
                transitive = True
                break
            if cur == tests_root_abs or cur.parent == cur:
                break
            cur = cur.parent
        if transitive:
            continue

        count += 1
        if len(samples) < _MAX_SAMPLES:
            pkgs = sorted(src_packages)
            preview = pkgs[:3]
            extra = len(pkgs) - len(preview)
            pkg_summary = ", ".join(preview) + (f" (+{extra} more)" if extra > 0 else "")
            samples.append(f"{rel}: no imports from any src package ({pkg_summary})")
    return DetectorResult(count=count, samples=samples)
