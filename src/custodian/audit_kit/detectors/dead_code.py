# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""D-class and F-class detectors — dead code and unused definitions.

Detectors
─────────
D1  Module-level functions defined but never called within the same
    codebase.  Uses the call-graph pass for cross-file analysis.
    Conservative: only flags non-private, non-test, non-main functions.
    Functions exported via ``__all__`` or used as decorators are excluded.

D2  Dead else after terminal if-branch — an else clause present when the
    if-body always exits (return/raise/break/continue).  The else is
    structurally unreachable via the if-path and can be deleted, flattening
    the indentation level.  Only flagged inside function bodies.

D3  Functions that never return normally — every code path ends with
    ``raise`` or a call to ``sys.exit``/``exit``/``quit``.  These should
    be annotated ``-> NoReturn``.  Functions already annotated NoReturn or
    Never are excluded.  Excludes @abstractmethod and Protocol methods.

D4  Unreachable code after unconditional return/raise/break/continue.
    Any statement following a terminal in the same block can never execute.
    Recurses into nested if/for/while/try/with bodies but not into nested
    function or class definitions (separate scopes).

D5  Module-level classes never referenced anywhere in the codebase.
    A class is dead if its name never appears as a Name Load in any
    scanned file — it is never instantiated, subclassed, used in
    isinstance(), used as a type annotation, or imported.  Complements D1.

D6  Module-level classes referenced (e.g. in type annotations or imports)
    but never instantiated (constructor never called) in the codebase.
    Complements D5: catches classes that exist in the type system but are
    never constructed — common with DTO classes defined for pipelines that
    are partially implemented.  Only flags classes whose name appears in
    called_names (referenced) but not in constructed_names (never called
    as a constructor).  Does NOT flag classes not in called_names — D5
    covers that case.

D7  A function/method parameter that is never referenced in the function
    body.  Only checks regular params (not *args/**kwargs).  Skips self,
    cls, underscore-prefixed params, functions with **kwargs (dynamic
    forwarding), and stub bodies (abstractmethod, overload, pass/ellipsis).

D9  A ``try/except`` handler whose body is a bare ``raise`` with no
    argument — i.e. the handler immediately re-raises the caught exception
    unconditionally.  This is a no-op: the exception would propagate
    identically without the handler.  The pattern usually appears after
    removing logging or cleanup code from the handler and forgetting to
    delete the try wrapper.  Handlers that have any statement other than
    the bare ``raise`` (e.g. logging, cleanup, context attachment) are
    intentional and are not flagged.

D10 An ``async def`` function that never uses ``await`` anywhere in its
    body.  An async function with no await expressions runs synchronously
    inside the event loop — it blocks the loop if it does any I/O and
    creates unnecessary coroutine overhead otherwise.  Common causes:
    a sync-to-async conversion where the implementation wasn't updated,
    or a helper that was made async "just in case" without a real need.
    Skips abstract methods, Protocol stubs, overloaded forms, and functions
    whose body is only ``pass``/``...`` (those are stubs flagged by U-class).
    Skips ``__aenter__`` / ``__aexit__`` / ``__aiter__`` / ``__anext__``
    (async protocol dunders that are async by contract).

F1  ``@dataclass`` fields never accessed as attributes anywhere in the
    codebase.  Uses the call-graph pass to collect all attribute accesses.
    Conservative: only flags fields whose name does not appear in any
    attribute-load expression across all source files.

F2  Private module-level constant defined but never referenced in the same
    file.  Matches _ALL_CAPS names at module scope.  Names in ``__all__``
    are excluded (they may be imported by consumers).

F3  Pydantic ``BaseModel`` / ``BaseSettings`` fields never accessed as
    attributes anywhere in the codebase.  Uses the call-graph pass to
    collect attribute accesses.  Skips private fields and classes that
    expose all fields via serialization methods (model_dump/dict/to_dict).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW, MEDIUM,
)

_MAX_SAMPLES = 8
_NEEDS_AST = frozenset({"ast_forest"})
_NEEDS_CG  = frozenset({"call_graph"})
_PRIVATE_CAPS = re.compile(r"^_[A-Z][A-Z0-9_]*$")

# Module-level function names that should never be flagged as dead.
_NEVER_DEAD = frozenset({
    "main", "setup", "teardown", "conftest",
    "__main__", "app", "create_app", "get_app",
})


_NEEDS_CG_AND_AST = frozenset({"call_graph", "ast_forest"})


def build_dead_code_detectors() -> list[Detector]:
    """D-class + F-class dead-code detectors.

    Detectors marked ``deprecated=True`` have an equivalent in Vulture
    (the dead-code adapter, default-on at min_confidence=80) or in ty/mypy.
    Per the boundary refinement, "use the tool first." Deprecated detectors
    are skipped by default.

    D2 (unnecessary else after terminal if-branch) and D7 (dead method
    parameter) were retired entirely 2026-05-05 — high false-positive rate,
    no canonical tool equivalent worth the maintenance overhead. See
    docs/design/detector_disposition_matrix.md.
    """
    return [
        # ── KEEP — no tool equivalent ────────────────────────────────────
        Detector("D4", "unreachable code after return/raise/break/continue", "open",
                 detect_d4, MEDIUM, _NEEDS_AST),
        Detector("D6", "class referenced but constructor never called — may be incomplete wiring, not dead code", "open",
                 detect_d6, LOW, _NEEDS_CG_AND_AST),
        Detector("F3", "BaseModel field never accessed as attribute in codebase", "open",
                 detect_f3, LOW, _NEEDS_CG),
        Detector("D9", "try/except handler unconditionally re-raises (no-op handler)", "open",
                 detect_d9, LOW, _NEEDS_AST),
        Detector("D10", "async def function that never awaits anything", "open",
                 detect_d10, LOW, _NEEDS_AST),
        # D3 stays NON-deprecated until ty/mypy is enabled across the major
        # consumers (currently disabled in OC + VF). When enabled, mark
        # deprecated=True and let the type checker take over.
        Detector("D3", "function never returns normally — missing -> NoReturn", "open",
                 detect_d3, LOW, _NEEDS_AST),
        # ── DEPRECATED — Vulture covers (default-on, min_confidence=80) ──
        Detector("D1", "module-level function defined but never called in codebase", "open",
                 detect_d1, LOW, _NEEDS_CG, deprecated=True),  # Vulture
        Detector("D5", "module-level class never referenced in codebase", "open",
                 detect_d5, LOW, _NEEDS_CG_AND_AST, deprecated=True),  # Vulture
        Detector("D8", "function returns value on some paths but falls through on others (implicit None)", "open",
                 detect_d8, LOW, _NEEDS_AST, deprecated=True),  # Ruff RET503
        Detector("F1", "dataclass field never accessed as attribute in codebase", "open",
                 detect_f1, LOW, _NEEDS_CG, deprecated=True),  # Vulture
        Detector("F2", "private module-level constant defined but never referenced", "open",
                 detect_f2, LOW, _NEEDS_AST, deprecated=True),  # Vulture
    ]


# ── D1 ────────────────────────────────────────────────────────────────────────

def detect_d1(context: AuditContext) -> DetectorResult:
    """Flag module-level functions never called anywhere in the codebase."""
    if context.graph is None or context.graph.call_graph is None:
        return DetectorResult(count=0, samples=[])

    cg = context.graph.call_graph
    all_calls = cg.called_names | cg.called_attrs | cg.decorated_names

    samples: list[str] = []
    count = 0

    for name in sorted(cg.module_functions):
        if name.startswith("_"):
            continue
        if name.startswith("test_"):
            continue
        if name in _NEVER_DEAD:
            continue
        if name in cg.defined_in_all:
            continue
        if name in all_calls:
            continue
        if name in cg.framework_decorated:
            continue
        count += 1
        if len(samples) < _MAX_SAMPLES:
            samples.append(f"{name}() — defined but never called")

    return DetectorResult(count=count, samples=samples)


_D5_D6_SKIP_BASES = frozenset({
    "Protocol", "ABC",          # structural typing / abstract
    "BaseModel", "BaseSettings", "TypedDict",  # Pydantic — deserialized, not constructed directly
})

# ── D5 ────────────────────────────────────────────────────────────────────────

def detect_d5(context: AuditContext) -> DetectorResult:
    """Flag module-level classes never referenced anywhere in the codebase.

    A class is dead if its name never appears as a Name Load (instantiation,
    subclassing, isinstance(), type annotation, import) in any scanned file.
    The call_graph's Name Load tracking captures all of these forms.

    Skips:
    - Private classes (name starts with ``_``)
    - Classes exported via ``__all__``
    - Test classes (name starts with ``Test``)
    - Exception/Warning classes (name ends with Error/Exception/Warning/Fault)
      Note: raised/caught exceptions DO appear as Name Loads, so these are
      only excluded as a conservative hedge for exception hierarchies.
    """
    if (context.graph is None
            or context.graph.call_graph is None
            or context.graph.ast_forest is None):
        return DetectorResult(count=0, samples=[])

    cg = context.graph.call_graph
    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        for stmt in tree.body:
            if not isinstance(stmt, ast.ClassDef):
                continue
            name = stmt.name
            if name.startswith("_"):
                continue
            if name in cg.defined_in_all:
                continue
            if name.startswith("Test"):
                continue
            if name.endswith(("Error", "Exception", "Warning", "Fault")):
                continue
            if any(
                (isinstance(b, ast.Name) and b.id in _D5_D6_SKIP_BASES)
                or (isinstance(b, ast.Attribute) and b.attr in _D5_D6_SKIP_BASES)
                for b in stmt.bases
            ):
                continue
            if name in cg.called_names:
                continue
            # Classes accessed via module alias (e.g. mod.ClassName) appear as
            # attribute loads, not Name Loads — check both attr sets
            if name in cg.called_attrs or name in cg.accessed_attrs:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                rel = path.relative_to(context.repo_root)
                samples.append(f"{rel}:{stmt.lineno}: class {name} — never referenced")

    return DetectorResult(count=count, samples=samples)


# ── D6 ────────────────────────────────────────────────────────────────────────

def detect_d6(context: AuditContext) -> DetectorResult:
    """Flag module-level classes referenced but never instantiated in the codebase.

    D6 complements D5: D5 catches classes that are never mentioned at all;
    D6 catches classes that appear in the type system (annotations, imports,
    isinstance checks) but whose constructor is never called anywhere.

    **D6 is investigative, not prescriptive.** A finding means: "something
    references this class but nothing constructs it." Before removing, check
    whether the produce-side is simply missing — the class may be a partially
    wired DTO or a planned extension point, not dead code. Compare with D5
    (class not referenced at all) which is safer to remove.

    Only flags if:
    - name is in cg.called_names (referenced somewhere — D5 skips these)
    - name is NOT in cg.constructed_names (constructor never called)

    Same skips as D5: private, __all__, Test*, Error/Exception/Warning/Fault,
    Protocol/ABC base classes.
    """
    if (context.graph is None
            or context.graph.call_graph is None
            or context.graph.ast_forest is None):
        return DetectorResult(count=0, samples=[])

    audit_cfg: dict = context.config.get("audit") or {}
    d6_globs: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("D6") or [])

    cg = context.graph.call_graph
    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        if d6_globs:
            rel_str = str(path.relative_to(context.repo_root))
            from pathlib import PurePosixPath
            if any(PurePosixPath(rel_str).match(g) for g in d6_globs):
                continue
        for stmt in tree.body:
            if not isinstance(stmt, ast.ClassDef):
                continue
            name = stmt.name
            if name.startswith("_"):
                continue
            if name in cg.defined_in_all:
                continue
            if name.startswith("Test"):
                continue
            if name.endswith(("Error", "Exception", "Warning", "Fault")):
                continue
            if any(
                (isinstance(b, ast.Name) and b.id in _D5_D6_SKIP_BASES)
                or (isinstance(b, ast.Attribute) and b.attr in _D5_D6_SKIP_BASES)
                for b in stmt.bases
            ):
                continue
            # Only flag if referenced (in called_names) but never constructed
            if name not in cg.called_names:
                continue  # D5 covers this case
            if name in cg.constructed_names:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                rel = path.relative_to(context.repo_root)
                samples.append(
                    f"{rel}:{stmt.lineno}: class {name} — never constructed (referenced in annotations/imports only)"
                )

    return DetectorResult(count=count, samples=samples)



# ── F1 ────────────────────────────────────────────────────────────────────────

_SERIALIZATION_METHODS = frozenset({"to_dict", "to_json", "asdict", "model_dump", "dict", "__dict__"})


def _dataclass_field_names(src_root: Path, path_excludes: list[str] | None = None) -> set[str]:
    """Collect field names from @dataclass classes that lack serialization methods.

    Dataclasses with to_dict/to_json/model_dump/asdict methods expose all fields
    indirectly via serialization — we skip those to avoid false positives.

    Also skips dataclasses that inherit from a class with serialization methods
    (e.g. subclasses of a BaseContract that defines to_dict()).
    """
    import fnmatch as _fnmatch

    # First pass: collect class names that have serialization methods defined
    serializable_classes: set[str] = set()
    all_trees: list[tuple[Path, ast.Module]] = []
    repo_root_guess = src_root.parent  # approximate — used for relative path matching only

    for path in sorted(src_root.rglob("*.py")):
        if not path.is_file():
            continue
        # Apply path excludes (relative to repo root approximation)
        if path_excludes:
            try:
                rel_posix = path.relative_to(repo_root_guess).as_posix()
            except ValueError:
                rel_posix = path.as_posix()
            if any(_fnmatch.fnmatch(rel_posix, excl) for excl in path_excludes):
                continue
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        all_trees.append((path, tree))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            method_names = {
                stmt.name
                for stmt in node.body
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            if method_names & _SERIALIZATION_METHODS:
                serializable_classes.add(node.name)

    # Second pass: collect fields, skipping dataclasses with serialization methods
    # OR that inherit from a class with serialization methods
    fields: set[str] = set()
    for _path, tree in all_trees:
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not any(
                (isinstance(d, ast.Name) and d.id == "dataclass")
                or (isinstance(d, ast.Attribute) and d.attr == "dataclass")
                for d in node.decorator_list
            ):
                continue
            # Skip dataclasses that expose fields via serialization methods (direct or inherited)
            method_names = {
                stmt.name
                for stmt in node.body
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            if method_names & _SERIALIZATION_METHODS:
                continue
            # Skip subclasses of serializable classes
            base_names = set()
            for b in node.bases:
                if isinstance(b, ast.Name):
                    base_names.add(b.id)
                elif isinstance(b, ast.Attribute):
                    base_names.add(b.attr)
            if base_names & serializable_classes:
                continue
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    fields.add(stmt.target.id)
                elif isinstance(stmt, ast.Assign):
                    for t in stmt.targets:
                        if isinstance(t, ast.Name) and not t.id.startswith("_"):
                            fields.add(t.id)
    return fields


def detect_f1(context: AuditContext) -> DetectorResult:
    """Flag @dataclass fields never accessed as attributes anywhere in the codebase."""
    if context.graph is None or context.graph.call_graph is None:
        return DetectorResult(count=0, samples=[])

    cg = context.graph.call_graph
    audit_cfg: dict = context.config.get("audit") or {}
    exempt: set[str] = set(audit_cfg.get("f1_exempt") or [])
    f1_path_excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("F1") or [])
    field_names = _dataclass_field_names(context.src_root, path_excludes=f1_path_excludes or None)

    samples: list[str] = []
    count = 0

    for name in sorted(field_names):
        if name.startswith("_"):
            continue
        if name in exempt:
            continue
        if name in cg.accessed_attrs:
            continue
        if name in cg.kw_arg_names:  # set via SomeClass(field=value) — still in use
            continue
        count += 1
        if len(samples) < _MAX_SAMPLES:
            samples.append(f"{name} — dataclass field never accessed as attribute")

    return DetectorResult(count=count, samples=samples)


# ── F3 ────────────────────────────────────────────────────────────────────────

_PYDANTIC_BASES = frozenset({"BaseModel", "BaseSettings"})
_PYDANTIC_VALIDATOR_DECORATORS = frozenset({"validator", "field_validator", "model_validator"})


def _pydantic_field_names(src_root: Path) -> dict[str, set[str]]:
    """Collect annotated field names from BaseModel/BaseSettings subclasses.

    Returns a mapping of field_name → set of class names that declare it.

    Skips:
    - Classes with serialization methods (model_dump/dict/to_dict) — all fields
      exposed indirectly via serialization.
    - Private fields (starting with ``_``).
    - Fields that are decorated (validators, class methods, etc.).
    """
    fields: dict[str, set[str]] = {}
    for path in sorted(src_root.rglob("*.py")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            # Only consider direct BaseModel/BaseSettings subclasses
            if not any(
                (isinstance(b, ast.Name) and b.id in _PYDANTIC_BASES)
                or (isinstance(b, ast.Attribute) and b.attr in _PYDANTIC_BASES)
                for b in node.bases
            ):
                continue
            # Skip classes that expose all fields via serialization
            method_names = {
                stmt.name
                for stmt in node.body
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            if method_names & _SERIALIZATION_METHODS:
                continue
            # Collect decorated names (validators) to skip
            decorated_names: set[str] = set()
            for stmt in node.body:
                if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for dec in stmt.decorator_list:
                    dec_name = (
                        dec.id if isinstance(dec, ast.Name)
                        else dec.attr if isinstance(dec, ast.Attribute)
                        else dec.func.id if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name)
                        else dec.func.attr if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                        else None
                    )
                    if dec_name in _PYDANTIC_VALIDATOR_DECORATORS:
                        decorated_names.add(stmt.name)
            # Collect AnnAssign fields (Pydantic v2 style)
            for stmt in node.body:
                if not isinstance(stmt, ast.AnnAssign):
                    continue
                if not isinstance(stmt.target, ast.Name):
                    continue
                name = stmt.target.id
                if name.startswith("_"):
                    continue
                if name in decorated_names:
                    continue
                fields.setdefault(name, set()).add(node.name)
    return fields


def _expand_model_validate_classes(src_root: Path, seed: set[str]) -> set[str]:
    """Transitively expand model_validate_classes to include nested Pydantic models.

    If class A is deserialized via model_validate and has a field typed as class B,
    then B is also effectively deserialized (Pydantic handles nested model inflation).
    Runs until stable (usually 2-3 iterations for real codebases).
    """
    # Build: class_name → set of field type names (from AnnAssign annotations)
    class_to_field_types: dict[str, set[str]] = {}
    for path in sorted(src_root.rglob("*.py")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            type_names: set[str] = set()
            for stmt in node.body:
                if not isinstance(stmt, ast.AnnAssign):
                    continue
                ann = stmt.annotation
                # Unwrap Optional/list/Union subscripts to find the inner Name
                to_check = [ann]
                while to_check:
                    a = to_check.pop()
                    if isinstance(a, ast.Name):
                        type_names.add(a.id)
                    elif isinstance(a, ast.Subscript):
                        to_check.append(a.value)
                        if isinstance(a.slice, ast.Tuple):
                            to_check.extend(a.slice.elts)
                        else:
                            to_check.append(a.slice)
                    elif isinstance(a, ast.BinOp):  # X | Y union syntax
                        to_check.extend([a.left, a.right])
            if type_names:
                class_to_field_types.setdefault(node.name, set()).update(type_names)

    expanded = set(seed)
    while True:
        added: set[str] = set()
        for cls in list(expanded):
            for field_type in class_to_field_types.get(cls, set()):
                if field_type not in expanded:
                    added.add(field_type)
        if not added:
            break
        expanded |= added
    return expanded


def _scan_validate_wrappers(src_root: Path, func_names: list[str]) -> set[str]:
    """Find class names passed as the first arg to custom model_validate wrappers.

    Detects the pattern: ``model_validate(ClassName, data)`` where
    ``model_validate`` is a project-specific free function wrapper around
    Pydantic's ``ClassName.model_validate(data)``.  The function names to
    scan for are declared in ``audit.f3_validate_functions`` in
    ``.custodian.yaml``.
    """
    if not func_names:
        return set()
    func_set = set(func_names)
    found: set[str] = set()
    for path in sorted(src_root.rglob("*.py")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Name) and func.id in func_set):
                continue
            if node.args and isinstance(node.args[0], ast.Name):
                found.add(node.args[0].id)
    return found


def detect_f3(context: AuditContext) -> DetectorResult:
    """Flag Pydantic BaseModel/BaseSettings fields never accessed as attributes."""
    if context.graph is None or context.graph.call_graph is None:
        return DetectorResult(count=0, samples=[])

    cg = context.graph.call_graph
    field_map = _pydantic_field_names(context.src_root)  # field_name → set of class names

    audit_cfg: dict = context.config.get("audit") or {}
    exempt: set[str] = set(audit_cfg.get("f3_exempt") or [])
    validate_fns: list[str] = list(audit_cfg.get("f3_validate_functions") or [])

    # Expand: nested Pydantic models under deserialized classes are also schema fields.
    # Also include classes passed as first arg to custom model_validate wrappers.
    seed = cg.model_validate_classes | _scan_validate_wrappers(context.src_root, validate_fns)
    model_validate_classes = _expand_model_validate_classes(context.src_root, seed)

    samples: list[str] = []
    count = 0

    for name, class_names in sorted(field_map.items()):
        if name.startswith("_"):
            continue
        if name in exempt:
            continue
        if name in cg.accessed_attrs:
            continue
        if name in cg.kw_arg_names:  # set via Model(field=value) — still in use
            continue
        # Skip fields from classes that use getattr(self, variable) — dynamic access
        if class_names & cg.dynamic_getattr_classes:
            continue
        # Skip fields from classes deserialized via model_validate* — all fields are schema fields
        if class_names & model_validate_classes:
            continue
        count += 1
        if len(samples) < _MAX_SAMPLES:
            samples.append(f"{name} — BaseModel field never accessed as attribute")

    return DetectorResult(count=count, samples=samples)


# ── AST helpers ───────────────────────────────────────────────────────────────

def _is_terminal(stmt: ast.stmt) -> bool:
    return isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue))


def _block_terminates(body: list[ast.stmt]) -> bool:
    return bool(body) and _is_terminal(body[-1])


def _stmts_of(stmt: ast.stmt) -> list[list[ast.stmt]]:
    """Return all nested statement lists within stmt (excluding function/class bodies)."""
    if isinstance(stmt, ast.If):
        return [stmt.body, stmt.orelse]
    if isinstance(stmt, (ast.For, ast.While)):
        return [stmt.body, stmt.orelse]
    if isinstance(stmt, ast.Try):
        nested = [stmt.body, stmt.orelse, stmt.finalbody]
        for h in stmt.handlers:
            nested.append(h.body)
        return nested
    if isinstance(stmt, ast.With):
        return [stmt.body]
    return []


# ── D3 helpers ────────────────────────────────────────────────────────────────

def _is_noreturn_call(stmt: ast.stmt) -> bool:
    """True for bare calls to sys.exit / exit / quit / os._exit."""
    if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
        return False
    func = stmt.value.func
    if isinstance(func, ast.Name) and func.id in {"exit", "quit"}:
        return True
    if isinstance(func, ast.Attribute) and func.attr in {"exit", "_exit"}:
        return True
    return False


def _is_noreturn_terminal(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Raise) or _is_noreturn_call(stmt)


def _all_paths_noreturn(stmts: list[ast.stmt]) -> bool:
    """True if every code path through stmts ends in raise or a sys.exit-style call."""
    if not stmts:
        return False
    last = stmts[-1]
    if _is_noreturn_terminal(last):
        return True
    if isinstance(last, ast.If):
        # Without an else, the if-false path falls through — not NoReturn.
        if not last.orelse:
            return False
        return _all_paths_noreturn(last.body) and _all_paths_noreturn(last.orelse)
    if isinstance(last, ast.Try):
        if not _all_paths_noreturn(last.body):
            return False
        for handler in last.handlers:
            if not _all_paths_noreturn(handler.body):
                return False
        return True
    return False


def _has_decorator(func: ast.FunctionDef | ast.AsyncFunctionDef, *names: str) -> bool:
    for dec in func.decorator_list:
        dec_name = (dec.id if isinstance(dec, ast.Name)
                    else dec.attr if isinstance(dec, ast.Attribute) else None)
        if dec_name in names:
            return True
    return False


def _protocol_class_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                base_name = (base.id if isinstance(base, ast.Name)
                             else base.attr if isinstance(base, ast.Attribute) else None)
                if base_name == "Protocol":
                    names.add(node.name)
    return names


def _direct_class(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    tree: ast.Module,
) -> ast.ClassDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if item is func:
                    return node
    return None


def _is_annotated_noreturn(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    ann = func.returns
    if ann is None:
        return False
    if isinstance(ann, ast.Name) and ann.id in {"NoReturn", "Never"}:
        return True
    if isinstance(ann, ast.Attribute) and ann.attr in {"NoReturn", "Never"}:
        return True
    return False


def _has_return_in_scope(stmts: list[ast.stmt]) -> bool:
    """True if stmts contains a Return statement not inside a nested function/class."""
    for stmt in stmts:
        if isinstance(stmt, ast.Return):
            return True
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue  # nested scope — do not descend
        # Recurse into compound statement blocks
        for nested in _stmts_of(stmt):
            if _has_return_in_scope(nested):
                return True
    return False



# ── D3 ────────────────────────────────────────────────────────────────────────

def detect_d3(context: AuditContext) -> DetectorResult:
    """Flag functions that never return normally but lack -> NoReturn."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        protocol_names = _protocol_class_names(tree)

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if _has_decorator(node, "abstractmethod", "overload"):
                continue
            container = _direct_class(node, tree)
            if container and container.name in protocol_names:
                continue
            if _is_annotated_noreturn(node):
                continue
            if not node.body:
                continue
            if _has_return_in_scope(node.body):
                continue  # can return normally — not NoReturn
            if _all_paths_noreturn(node.body):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"{rel}:{node.lineno}: {node.name}() — never returns, missing -> NoReturn"
                    )

    return DetectorResult(count=count, samples=samples)


# ── D4 ────────────────────────────────────────────────────────────────────────

def _unreachable_stmts(stmts: list[ast.stmt]) -> list[ast.stmt]:
    """Find first unreachable statement in this block, then recurse into compounds."""
    results: list[ast.stmt] = []
    for i, stmt in enumerate(stmts):
        if _is_terminal(stmt) and i + 1 < len(stmts):
            results.append(stmts[i + 1])
            break
        for nested in _stmts_of(stmt):
            results.extend(_unreachable_stmts(nested))
    return results


def detect_d4(context: AuditContext) -> DetectorResult:
    """Flag statements that follow an unconditional return/raise/break/continue."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for hit in _unreachable_stmts(node.body):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    lineno = getattr(hit, "lineno", node.lineno)
                    samples.append(
                        f"{rel}:{lineno}: {node.name}() — unreachable code"
                    )

    return DetectorResult(count=count, samples=samples)


# ── F2 ────────────────────────────────────────────────────────────────────────

def _private_constant_defs(tree: ast.Module) -> dict[str, ast.AST]:
    defs: dict[str, ast.AST] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and _PRIVATE_CAPS.match(target.id):
                    defs[target.id] = target
        elif isinstance(stmt, ast.AnnAssign):
            if isinstance(stmt.target, ast.Name) and _PRIVATE_CAPS.match(stmt.target.id):
                defs[stmt.target.id] = stmt.target
    return defs


def _module_all_exports(tree: ast.Module) -> set[str]:
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "__all__" for t in stmt.targets):
            continue
        if isinstance(stmt.value, (ast.List, ast.Tuple)):
            return {
                elt.value
                for elt in stmt.value.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            }
    return set()


def _usage_counts(
    tree: ast.Module,
    names: set[str],
    exclude_node_ids: set[int],
) -> dict[str, int]:
    counts: dict[str, int] = {n: 0 for n in names}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in counts and id(node) not in exclude_node_ids:
            counts[node.id] += 1
    return counts


def detect_f2(context: AuditContext) -> DetectorResult:
    """Flag private _ALL_CAPS module-level constants never referenced in their file."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        defs = _private_constant_defs(tree)
        if not defs:
            continue
        exports = _module_all_exports(tree)
        checkable = {k: v for k, v in defs.items() if k not in exports}
        if not checkable:
            continue

        def_node_ids = {id(n) for n in checkable.values()}
        usages = _usage_counts(tree, set(checkable), def_node_ids)

        for name, use_count in sorted(usages.items()):
            if use_count == 0:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    lineno = getattr(checkable[name], "lineno", 0)
                    rel = path.relative_to(context.repo_root)
                    samples.append(f"{rel}:{lineno}: {name} — defined but never used")

    return DetectorResult(count=count, samples=samples)


# ── D8 helpers ────────────────────────────────────────────────────────────────

def _all_paths_terminate(stmts: list[ast.stmt]) -> bool:
    """True if every code path through stmts ends in a return or raise."""
    if not stmts:
        return False
    last = stmts[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    if _is_noreturn_call(last):
        return True
    if isinstance(last, ast.If):
        if not last.orelse:
            return False  # else branch can fall through
        return _all_paths_terminate(last.body) and _all_paths_terminate(last.orelse)
    if isinstance(last, ast.Try):
        if not _all_paths_terminate(last.body):
            return False
        for handler in last.handlers:
            if not _all_paths_terminate(handler.body):
                return False
        return True
    if isinstance(last, ast.With):
        return _all_paths_terminate(last.body)
    if isinstance(last, ast.While):
        # while True: loops are infinite — execution can't fall past them
        # unless there's an unconditional break (not modeled here; conservative).
        cond = last.test
        if isinstance(cond, ast.Constant) and cond.value is True:
            return True
        if isinstance(cond, ast.Name) and cond.id == "True":
            return True
    return False


def _is_annotated_none(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    ann = func.returns
    if ann is None:
        return False
    if isinstance(ann, ast.Constant) and ann.value is None:
        return True
    if isinstance(ann, ast.Name) and ann.id == "None":
        return True
    return False


def _value_returns_in_scope(stmts: list[ast.stmt]) -> list[ast.Return]:
    """Collect Return nodes with a non-None, non-bare value (not in nested funcs)."""
    results: list[ast.Return] = []
    for stmt in stmts:
        if isinstance(stmt, ast.Return):
            v = stmt.value
            if v is not None and not (isinstance(v, ast.Constant) and v.value is None):
                results.append(stmt)
            continue
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue  # nested scope
        for nested in _stmts_of(stmt):
            results.extend(_value_returns_in_scope(nested))
    return results


# ── D8 ────────────────────────────────────────────────────────────────────────

def detect_d8(context: AuditContext) -> DetectorResult:
    """Flag functions that return a value on some paths but fall through on others.

    A function that returns a meaningful value on some branches but has an
    execution path that falls off the end (implicitly returning None) is almost
    always a bug — typically a missing ``return`` in one branch, or a guard
    clause that forgets to propagate the result.

    Exclusions:
    - Functions annotated ``-> None`` or ``-> NoReturn`` (intentional)
    - Functions with no value-bearing return at all (void functions)
    - ``@abstractmethod`` / ``@overload`` stubs
    - Protocol methods
    - Exclude paths via ``audit.exclude_paths.D8``
    """
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    from custodian.audit_kit.code_health import _exclude_globs, _glob_to_regex

    exclude_globs = _exclude_globs(context, "D8")
    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel_str = str(path.relative_to(context.repo_root))
        if exclude_globs and any(_glob_to_regex(g).match(rel_str) for g in exclude_globs):
            continue

        protocol_names = _protocol_class_names(tree)
        rel = path.relative_to(context.repo_root)

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if _has_decorator(node, "abstractmethod", "overload"):
                continue
            container = _direct_class(node, tree)
            if container and container.name in protocol_names:
                continue
            if _is_annotated_none(node) or _is_annotated_noreturn(node):
                continue
            if not node.body:
                continue

            value_rets = _value_returns_in_scope(node.body)
            if not value_rets:
                continue  # void function — no value returns at all

            if _all_paths_terminate(node.body):
                continue  # all paths return or raise — no fall-through

            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(
                    f"{rel}:{node.lineno}: {node.name}() — returns value on some paths, falls through on others"
                )

    return DetectorResult(count=count, samples=samples)


# ── D9 ────────────────────────────────────────────────────────────────────────

def detect_d9(context: AuditContext) -> DetectorResult:
    """Flag try/except handlers whose body is only a bare raise (no-op handlers).

    Only flags when the try block has exactly one except handler and its body
    is a single bare ``raise``.  Multi-handler try blocks where one handler
    does ``except SpecificError: raise`` are intentional — they let a specific
    exception escape a broader catch-all below.

    Exclude paths via ``audit.exclude_paths.D9``.
    """
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    from custodian.audit_kit.code_health import _exclude_globs, _glob_to_regex

    exclude_globs = _exclude_globs(context, "D9")
    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel_str = str(path.relative_to(context.repo_root))
        if exclude_globs and any(_glob_to_regex(g).match(rel_str) for g in exclude_globs):
            continue
        rel = path.relative_to(context.repo_root)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Try):
                continue
            # Only flag when there's exactly one handler — multiple handlers
            # mean the bare-reraise is filtering which exceptions to pass through.
            if len(node.handlers) != 1:
                continue
            handler = node.handlers[0]
            body = handler.body
            if len(body) == 1 and isinstance(body[0], ast.Raise) and body[0].exc is None:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"{rel}:{handler.lineno}: except handler immediately re-raises — no-op, remove the try/except"
                    )

    return DetectorResult(count=count, samples=samples)


# ── D10 ───────────────────────────────────────────────────────────────────────

_ASYNC_DUNDER_EXEMPT = frozenset({
    "__aenter__", "__aexit__", "__aiter__", "__anext__",
})

# Decorator attribute names that make a function "async by framework contract".
# Includes FastAPI route methods, event handlers, middleware, and common
# async context manager decorators.
_FRAMEWORK_ASYNC_DECORATOR_ATTRS = frozenset({
    "get", "post", "put", "patch", "delete", "head", "options", "route",
    "websocket", "on_event", "middleware", "asynccontextmanager",
    "contextmanager", "lifespan",
})


def _has_await(node: ast.AST) -> bool:
    """Return True if the subtree contains any Await expression."""
    for child in ast.walk(node):
        if isinstance(child, ast.Await):
            return True
    return False


def _has_yield(body: list[ast.stmt]) -> bool:
    """Return True if the body contains a yield/yield from — async generator."""
    for node in body:
        for child in ast.walk(node):
            if isinstance(child, (ast.Yield, ast.YieldFrom)):
                return True
    return False


def _is_stub_body(body: list[ast.stmt]) -> bool:
    """True if the body is a bare stub (pass, ..., return None, or docstring-only)."""
    stmts = [s for s in body if not (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str))]
    if not stmts:
        return True  # docstring-only
    if len(stmts) == 1:
        s = stmts[0]
        if isinstance(s, ast.Pass):
            return True
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and s.value.value is ...:
            return True
        if isinstance(s, ast.Raise):
            return True  # raise NotImplementedError
        if isinstance(s, ast.Return):
            if s.value is None or (isinstance(s.value, ast.Constant) and s.value.value is None):
                return True
    return False


def _is_framework_async_decorator(dec: ast.expr) -> bool:
    """Return True if the decorator makes a function async by framework contract.

    Recognises ``@router.get``, ``@app.on_event``, ``@asynccontextmanager``,
    and other patterns that require ``async def`` without necessarily awaiting.
    """
    if isinstance(dec, ast.Name):
        return dec.id in _FRAMEWORK_ASYNC_DECORATOR_ATTRS
    if isinstance(dec, ast.Attribute):
        return dec.attr in _FRAMEWORK_ASYNC_DECORATOR_ATTRS
    if isinstance(dec, ast.Call):
        return _is_framework_async_decorator(dec.func)
    return False


def _has_exempt_decorator(node: ast.AsyncFunctionDef) -> bool:
    for dec in node.decorator_list:
        name = None
        if isinstance(dec, ast.Name):
            name = dec.id
        elif isinstance(dec, ast.Attribute):
            name = dec.attr
        elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
            name = dec.func.id
        elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
            name = dec.func.attr
        if name in ("abstractmethod", "overload") or _is_framework_async_decorator(dec):
            return True
    return False


def detect_d10(context: AuditContext) -> DetectorResult:
    """Flag async def functions that contain no await expression.

    Skips: abstract/overload stubs, async generators (yield), protocol dunders,
    and functions decorated with framework-async decorators (FastAPI routes,
    on_event, middleware, asynccontextmanager, etc.).
    """
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    import fnmatch as _fnmatch
    audit_cfg: dict = context.config.get("audit") or {}
    excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("D10") or [])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        rel_posix = rel.as_posix()
        if excludes and any(_fnmatch.fnmatch(rel_posix, excl) for excl in excludes):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue
            if node.name in _ASYNC_DUNDER_EXEMPT:
                continue
            if _has_exempt_decorator(node):
                continue
            if _is_stub_body(node.body):
                continue
            if _has_yield(node.body):
                continue  # async generator — yield makes it async by design
            if _has_await(node):
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(
                    f"{rel}:{node.lineno}: async def {node.name}() — no await expression"
                )

    return DetectorResult(count=count, samples=samples)
