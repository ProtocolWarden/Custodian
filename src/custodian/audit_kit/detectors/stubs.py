# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""U-class and P-class detectors — unimplemented / stub / hollow functions.

These detectors use the ``ast_forest`` analysis pass to inspect function
bodies across all source files.

Detectors
─────────
U1  ``raise NotImplementedError`` stubs — functions whose entire body
    (after an optional docstring) is a single ``raise NotImplementedError``
    statement.  Excludes ``@abstractmethod``-decorated methods (intentionally
    abstract) and methods in ``Protocol`` classes (convention uses ``...``).

U2  Ellipsis-only stubs — functions whose entire body (after an optional
    docstring) is a single ``...`` expression.  Excludes ``@abstractmethod``,
    ``@overload``, and methods inside ``Protocol`` classes, where ``...`` is
    the correct idiom.

U3  Docstring-only functions — functions that contain only a docstring and
    no other statements.  These are almost always unfinished implementations
    left after scaffolding.  Excludes ``@abstractmethod`` and ``Protocol``
    methods.

P1  Hollow return bodies — functions whose entire body (after an optional
    docstring) is only a single ``return`` of an empty collection or None
    (``return []``, ``return {}``, ``return None``, ``return ""``,
    ``return list()``, ``return dict()``).  Unlike U1-U3 stubs, these
    look "implemented" but produce no useful output.  Excludes
    ``@abstractmethod``, ``@overload``, Protocol methods, explicitly-void
    functions (``-> None`` annotation), and sink-pattern methods (``**_``
    kwargs absorber — the null-object idiom).

U4  Protocol implementation gap — a concrete class inherits from a Protocol
    (or a chain that includes a Protocol) but does not implement one or more
    of the Protocol's non-dunder methods.  Catches partially-completed
    Protocol implementations: the class is registered as a Protocol consumer
    but is missing methods, which would fail at runtime when those methods
    are called.  Only considers methods explicitly defined in the Protocol
    class itself (not inherited from further bases).  Excludes abstract
    subclasses (themselves Protocols or ABC subclasses), ``@overload``
    stubs, and ``__init__``/``__new__`` (not part of a Protocol interface).

    Methods the class inherits from its **non-Protocol** bases count as
    implemented — Python resolves those through the MRO, so
    ``class Impl(ConcreteBase, SomeProtocol)`` is complete when
    ``ConcreteBase`` supplies the method.  Resolution is name-based across the
    scanned tree, so a base defined outside it contributes nothing; that
    direction under-reports inherited methods rather than inventing them.
"""
from __future__ import annotations

import ast
from pathlib import Path

from custodian.audit_kit.detector import (
    LOW,
    MEDIUM,
    AuditContext,
    Detector,
    DetectorResult,
)

_MAX_SAMPLES = 8
_NEEDS = frozenset({"ast_forest"})


def build_stub_detectors() -> list[Detector]:
    return [
        Detector("U1", "raise NotImplementedError stub (unimplemented function)", "open",
                 detect_u1, MEDIUM, _NEEDS),
        Detector("U2", "ellipsis-only stub outside Protocol/abstractmethod", "open",
                 detect_u2, LOW, _NEEDS),
        Detector("U3", "docstring-only function body (no implementation)", "open",
                 detect_u3, LOW, _NEEDS),
        Detector("U5", "hollow return body (returns only empty collection/None)", "open",
                 detect_p1, LOW, _NEEDS),
        Detector("U4", "concrete class inherits Protocol but is missing Protocol methods", "open",
                 detect_u4, LOW, _NEEDS),
    ]


# ── AST helpers ───────────────────────────────────────────────────────────────

def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    """Return body with a leading docstring removed, if present."""
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        return body[1:]
    return body


def _has_decorator(func: ast.FunctionDef | ast.AsyncFunctionDef, *names: str) -> bool:
    for dec in func.decorator_list:
        dec_name = None
        if isinstance(dec, ast.Name):
            dec_name = dec.id
        elif isinstance(dec, ast.Attribute):
            dec_name = dec.attr
        if dec_name in names:
            return True
    return False


def _is_not_implemented_raise(stmt: ast.stmt) -> bool:
    if not isinstance(stmt, ast.Raise):
        return False
    exc = stmt.exc
    if exc is None:
        return False
    # Unwrap Call: raise NotImplementedError(...)
    if isinstance(exc, ast.Call):
        exc = exc.func
    if isinstance(exc, ast.Name):
        return exc.id == "NotImplementedError"
    if isinstance(exc, ast.Attribute):
        return exc.attr == "NotImplementedError"
    return False


def _is_ellipsis_only(stmt: ast.stmt) -> bool:
    return (isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and stmt.value.value is ...)


def _base_names(node: ast.ClassDef) -> set[str]:
    """Base-class names for a ClassDef, as written (``Name`` or ``a.b`` attr)."""
    names: set[str] = set()
    for base in node.bases:
        if isinstance(base, ast.Name):
            names.add(base.id)
        elif isinstance(base, ast.Attribute):
            names.add(base.attr)
    return names


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    """Map local alias -> original name for ``import X as Y`` in this module.

    A base written as an alias (``from m import Impl as _Base``) otherwise
    resolves to nothing, because classes are indexed by their real name. That
    is the common shape when a class is re-bound to avoid a name clash with the
    subclass it is being mixed into.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name.rsplit(".", 1)[-1]
    return aliases


def _protocol_classes(tree: ast.Module) -> set[str]:
    """Return names of Protocol-subclassing classes in this module."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for base in node.bases:
            base_name = None
            if isinstance(base, ast.Name):
                base_name = base.id
            elif isinstance(base, ast.Attribute):
                base_name = base.attr
            if base_name == "Protocol":
                names.add(node.name)
    return names


def _except_handler_functions(tree: ast.Module) -> set[int]:
    """Return ids of FunctionDef nodes that live inside except-handler bodies.

    try/except fallback stubs (e.g. ``except ImportError: class Foo: def add():...``)
    are intentional no-ops, not unfinished implementations.
    """
    ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ids.add(id(child))
    return ids


def _containing_class(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    tree: ast.Module,
) -> ast.ClassDef | None:
    """Return the ClassDef that directly contains func, or None."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if item is func:
                    return node
    return None


def _sample(
    path: Path,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    context: AuditContext,
) -> str:
    rel = path.relative_to(context.repo_root)
    return f"{rel}:{func.lineno}: {func.name}()"


# ── per-file scanner factory ──────────────────────────────────────────────────

def _scan_functions(
    context: AuditContext,
    predicate,
    *,
    detector_id: str | None = None,
) -> DetectorResult:
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    excluded_paths: set[str] = set()
    if detector_id:
        audit_cfg: dict = context.config.get("audit") or {}
        globs: list[str] = list((audit_cfg.get("exclude_paths") or {}).get(detector_id) or [])
        if globs:
            from pathlib import PurePosixPath
            for path in context.graph.ast_forest.trees:
                rel = path.relative_to(context.repo_root).as_posix()
                if any(PurePosixPath(rel).match(g) for g in globs):
                    excluded_paths.add(str(path))

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        if str(path) in excluded_paths:
            continue
        protocol_names = _protocol_classes(tree)
        except_fn_ids = _except_handler_functions(tree)

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if _has_decorator(node, "abstractmethod", "overload"):
                continue
            if id(node) in except_fn_ids:
                continue
            container = _containing_class(node, tree)
            if container and container.name in protocol_names:
                continue
            if predicate(node, container):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(_sample(path, node, context))

    return DetectorResult(count=count, samples=samples)


# ── U1 ────────────────────────────────────────────────────────────────────────

def detect_u1(context: AuditContext) -> DetectorResult:
    """Flag functions whose body (after docstring) is only raise NotImplementedError."""
    def predicate(func, _container):
        body = _strip_docstring(func.body)
        return len(body) == 1 and _is_not_implemented_raise(body[0])
    return _scan_functions(context, predicate, detector_id="U1")


# ── U2 ────────────────────────────────────────────────────────────────────────

def detect_u2(context: AuditContext) -> DetectorResult:
    """Flag functions whose body (after docstring) is only ``...``."""
    def predicate(func, _container):
        body = _strip_docstring(func.body)
        return len(body) == 1 and _is_ellipsis_only(body[0])
    return _scan_functions(context, predicate, detector_id="U2")


# ── U3 ────────────────────────────────────────────────────────────────────────

def detect_u3(context: AuditContext) -> DetectorResult:
    """Flag functions that contain only a docstring (no implementation at all)."""
    def predicate(func, _container):
        # Has a docstring
        if not (func.body and isinstance(func.body[0], ast.Expr)
                and isinstance(func.body[0].value, ast.Constant)
                and isinstance(func.body[0].value.value, str)):
            return False
        # And nothing else after the docstring
        return len(func.body) == 1
    return _scan_functions(context, predicate, detector_id="U3")


# ── P1 ────────────────────────────────────────────────────────────────────────

def _is_empty_return(stmt: ast.stmt) -> bool:
    """True if stmt is ``return`` / ``return None`` / ``return []`` / etc."""
    if not isinstance(stmt, ast.Return):
        return False
    val = stmt.value
    if val is None:
        return True
    # return None (constant)
    if isinstance(val, ast.Constant) and (val.value is None or val.value == "" or val.value == 0):
        return True
    # return [] / return {}
    if isinstance(val, ast.List) and not val.elts:
        return True
    if isinstance(val, ast.Dict) and not val.keys:
        return True
    if isinstance(val, ast.Set) and not val.elts:
        return True
    if isinstance(val, ast.Tuple) and not val.elts:
        return True
    # return list() / return dict() / return set() / return tuple()
    return bool(isinstance(val, ast.Call) and isinstance(val.func, ast.Name) and val.func.id in {"list", "dict", "set", "tuple"} and not val.args and not val.keywords)


def _returns_none_explicitly(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if the function is annotated ``-> None`` (explicitly void)."""
    ret = func.returns
    if ret is None:
        return False
    if isinstance(ret, ast.Constant) and ret.value is None:
        return True
    return bool(isinstance(ret, ast.Name) and ret.id == "None")


_NULL_CLASS_PREFIXES = ("Null", "_Null", "Mock", "Fake", "Stub", "Dummy")


def _in_null_named_class(container: ast.ClassDef | None) -> bool:
    """True if the containing class name signals a null-object or test-double pattern."""
    if container is None:
        return False
    return container.name.startswith(_NULL_CLASS_PREFIXES)


def _has_sink_args(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """True if positional or keyword varargs use ``_``-prefixed names (discard pattern).

    Matches ``*_args`` / ``**_kwargs`` / ``**_`` — all signal that the
    arguments are intentionally absorbed and ignored (null-object / sink idiom).
    """
    if func.args.vararg and func.args.vararg.arg.startswith("_"):
        return True
    return bool(func.args.kwarg and func.args.kwarg.arg.startswith("_"))


def detect_p1(context: AuditContext) -> DetectorResult:
    """Flag functions whose body (after docstring) is only a hollow return."""
    def predicate(func, container):
        body = _strip_docstring(func.body)
        if len(body) != 1 or not _is_empty_return(body[0]):
            return False
        if _returns_none_explicitly(func):
            return False
        if _has_sink_args(func):
            return False
        return not _in_null_named_class(container)
    return _scan_functions(context, predicate, detector_id="U5")


# ── U4 ────────────────────────────────────────────────────────────────────────

def _protocol_method_names(cls: ast.ClassDef) -> set[str]:
    """Collect non-dunder, non-overload method names defined directly in a Protocol class."""
    names: set[str] = set()
    for node in cls.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name.startswith("__") and node.name.endswith("__"):
            continue  # dunder not part of structural interface
        # Skip @overload stubs — they're typing artefacts
        if any(
            (isinstance(d, ast.Name) and d.id == "overload") or
            (isinstance(d, ast.Attribute) and d.attr == "overload")
            for d in node.decorator_list
        ):
            continue
        names.add(node.name)
    return names


def detect_u4(context: AuditContext) -> DetectorResult:
    """Flag concrete classes that inherit a Protocol but are missing its methods.

    Exclude paths via ``audit.exclude_paths.U4``.
    """
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    from custodian.audit_kit.code_health import _exclude_globs, _glob_to_regex

    exclude_globs = _exclude_globs(context, "U4")

    # Pass 1: collect all Protocol classes and their required methods across all
    # files, plus every class's own methods and bases so pass 2 can resolve what
    # a class inherits. Without the latter, `class Foo(ConcreteBase, SomeProto)`
    # is reported as missing methods that ConcreteBase supplies — a false
    # positive on any legitimate mixin.
    protocol_methods: dict[str, set[str]] = {}  # protocol_name → {method_names}
    class_methods: dict[str, set[str]] = {}     # class_name → own method names
    class_bases: dict[str, set[str]] = {}       # class_name → base class names
    for _path, tree, _src in context.graph.ast_forest.items():
        proto_names = _protocol_classes(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            class_methods.setdefault(node.name, set()).update(
                n.name for n in ast.walk(node)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
            class_bases.setdefault(node.name, set()).update(_base_names(node))
            if node.name in proto_names:
                methods = _protocol_method_names(node)
                if methods:  # only track Protocols that actually declare methods
                    protocol_methods[node.name] = methods

    if not protocol_methods:
        return DetectorResult(count=0, samples=[])

    def _inherited_methods(start_bases: set[str]) -> set[str]:
        """Methods reachable through the class's non-Protocol ancestors.

        Name-based and best-effort: the AST cannot resolve imports, so a base
        defined outside the scanned tree contributes nothing. That direction is
        safe — it can only under-report inherited methods, never invent them.
        """
        found: set[str] = set()
        seen: set[str] = set()
        queue = [b for b in start_bases if b not in protocol_methods]
        while queue:
            base = queue.pop()
            if base in seen:
                continue
            seen.add(base)
            found |= class_methods.get(base, set())
            queue.extend(
                b for b in class_bases.get(base, set())
                if b not in seen and b not in protocol_methods
            )
        return found

    # Pass 2: find concrete subclasses and check for gaps
    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel_str = path.relative_to(context.repo_root).as_posix()
        if exclude_globs and any(_glob_to_regex(g).match(rel_str) for g in exclude_globs):
            continue
        rel = path.relative_to(context.repo_root)

        this_file_protocols = _protocol_classes(tree)
        file_aliases = _import_aliases(tree)

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if node.name in this_file_protocols:
                continue  # this IS a Protocol — skip
            if node.name in protocol_methods:
                continue  # also a protocol defined elsewhere (same name)

            base_names: set[str] = _base_names(node)
            # Resolve `import X as Y` so an aliased base is matched by its real
            # name. Both spellings are kept: the alias may itself be a class
            # defined in this file.
            base_names |= {file_aliases[b] for b in base_names if b in file_aliases}

            # Check if it's itself a Protocol or ABC (abstract — skip)
            if "Protocol" in base_names or "ABC" in base_names or "ABCMeta" in base_names:
                continue

            # Find which Protocols this class inherits from
            for proto_name, required in protocol_methods.items():
                if proto_name not in base_names:
                    continue
                # Methods defined in this class body, plus anything reachable
                # through its non-Protocol ancestors — Python resolves those
                # through the MRO, so they are not missing.
                defined: set[str] = {
                    n.name for n in ast.walk(node)
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                }
                defined |= _inherited_methods(base_names)
                missing = required - defined
                if missing:
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        missing_str = ", ".join(sorted(missing))
                        samples.append(
                            f"{rel}:{node.lineno}: {node.name} inherits {proto_name} "
                            f"but is missing: {missing_str}"
                        )

    return DetectorResult(count=count, samples=samples)
