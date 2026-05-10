# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""K-class detectors — documentation consistency.

Detectors
─────────
K1  Doc phantom symbols — a backtick-quoted identifier in ``docs/`` or
    README that looks like a code symbol (lowercase, ≥8 chars, snake_case)
    but has no matching ``def``/``class``/field definition in ``src/``.
    Helps catch docs that reference renamed or removed functions. Lines
    in sections marked "deferred", "deprecated", or "out of scope" are
    skipped.  Configure ``audit.common_words`` and ``audit.stale_handlers``
    in ``.custodian.yaml`` to suppress known false positives.

K2  Doc value drift — a backtick-quoted lowercase token on a line that
    names a status/state/kind/priority value (e.g. "status: `pending`")
    but that token does not appear as a string literal anywhere in
    ``src/``.  Catches docs that cite stale enum values after a rename.
    Configure ``audit.known_values`` to suppress common English words
    that are not project-specific enum values.

K3  Docstring parameter drift — a function has a Google-style ``Args:``
    section in its docstring that names a parameter not present in the
    actual function signature.  Catches docstrings that were not updated
    after a parameter was renamed or removed.  ``self``, ``cls``,
    ``*args``, and ``**kwargs`` are excluded from checking.

K4  Docstring parameter type drift — a Google-style ``Args:`` entry
    declares a type (e.g. ``count (int): ...``) that does not match
    the parameter's signature annotation. Flags only when *both* sides
    declare a type and they disagree after whitespace/whitespace-around-
    operators normalization. A docstring without a type or a parameter
    without an annotation is not flagged here (E1/missing-type detectors
    cover those).  Common aliases are recognised: ``Optional[X]`` ↔
    ``X | None``, ``List[X]`` ↔ ``list[X]``, etc.

    Configure ``audit.exclude_paths.K4`` to skip files.
"""
from __future__ import annotations

import ast as _ast
import re
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)
from custodian.audit_kit.code_health import _py_files

_MAX_SAMPLES = 8


def build_docs_detectors() -> list[Detector]:
    return [
        Detector("K1", "doc references a symbol not found in src (phantom symbol)", "open",
                 detect_k1, LOW),
        Detector("K2", "doc cites a value not present as string literal in src (value drift)", "open",
                 detect_k2, LOW),
        Detector("K3", "docstring Args section names parameter not in function signature (param drift)", "open",
                 detect_k3, LOW),
        Detector("K4", "docstring Args type does not match signature annotation (type drift)", "open",
                 detect_k4, LOW),
    ]


# ── helpers ───────────────────────────────────────────────────────────────────

_DOC_SKIP_PARTS = frozenset({"history", "audits", "archive", "plans", "changelog", "specs"})


def _doc_files(repo_root: Path, audit_cfg: dict) -> list[Path]:
    """Collect docs/**/*.md + README.md, excluding volatile/historical subdirs.

    Skips ``history/``, ``audits/``, ``archive/``, ``plans/``, ``changelog/``
    subdirs — these reference future or removed symbols by design. Also skips
    any file whose name contains "changelog" (case-insensitive).
    """
    extra_doc_dirs: list[str] = list(audit_cfg.get("k1_extra_doc_dirs") or [])
    files: list[Path] = []
    readme = repo_root / "README.md"
    if readme.exists():
        files.append(readme)
    docs_root = repo_root / "docs"
    if docs_root.is_dir():
        files.extend(docs_root.rglob("*.md"))
    for d in extra_doc_dirs:
        extra = repo_root / d
        if extra.is_dir():
            files.extend(extra.rglob("*.md"))

    def _ok(f: Path) -> bool:
        parts_lower = {p.lower() for p in f.parts}
        if parts_lower & _DOC_SKIP_PARTS:
            return False
        if "changelog" in f.name.lower():
            return False
        return True

    return [f for f in files if _ok(f)]


def _build_src_text(context: AuditContext) -> tuple[str, str]:
    """Return concatenated src text and tests text."""
    src_text = ""
    for f in _py_files(context):
        try:
            src_text += f.read_text(encoding="utf-8", errors="replace") + "\n"
        except OSError:
            continue
    tests_text = ""
    if context.tests_root.is_dir():
        for f in context.tests_root.rglob("*.py"):
            try:
                tests_text += f.read_text(encoding="utf-8", errors="replace") + "\n"
            except OSError:
                continue
    return src_text, tests_text


_DEFERRED_WORDS = ("deferred", "out of scope", "not yet implemented", "future:", "deprecated")
_IMPL_MARKER_RE = re.compile(
    r"\*\*Files:\*\*|\bImplementation:|see\s+`|defined in `|"
    r"\b(?:def|class)\s+|`\s*\(.*?\)\s*",
    re.IGNORECASE,
)
_VALUE_CONTEXT_RE = re.compile(
    r"(?:status|state|kind|name|value|id|type|family|key|column)s?\s*[:=]|"
    r"(?:enum|constant|literal)|\bset\s+to\s+`|\bone\s+of\s+",
    re.IGNORECASE,
)
_SYM_RE = re.compile(r"`(_?[a-z][a-z0-9_]{7,})`")


# ── K1 ────────────────────────────────────────────────────────────────────────

def detect_k1(context: AuditContext) -> DetectorResult:
    """Flag backtick symbols in docs that have no def/class/field in src."""
    audit_cfg = context.config.get("audit") or {}
    common_words: set[str] = set(audit_cfg.get("common_words") or [])
    stale_handlers: set[str] = set(audit_cfg.get("stale_handlers") or [])

    src_text, tests_text = _build_src_text(context)

    def _exists(name: str) -> bool:
        if name in common_words or name in stale_handlers:
            return True
        if re.search(rf"\b(def|class)\s+{re.escape(name)}\b", src_text):
            return True
        if re.search(rf"^\s+{re.escape(name)}\s*:\s*[A-Za-z]", src_text, re.MULTILINE):
            return True
        if re.search(rf"\b(def|class)\s+{re.escape(name)}\b", tests_text):
            return True
        # Exists as a quoted string literal in src (e.g. dict key, enum value, config key)
        if re.search(rf"""['"]{re.escape(name)}['"]""", src_text):
            return True
        return False

    seen: dict[str, tuple[Path, int]] = {}
    for f in _doc_files(context.repo_root, audit_cfg):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        current_section_deferred = False
        for i, line in enumerate(text.splitlines(), 1):
            lower = line.lower()
            if line.startswith("#"):
                current_section_deferred = any(w in lower for w in _DEFERRED_WORDS)
                continue
            if current_section_deferred or any(w in lower for w in _DEFERRED_WORDS):
                continue
            if not _IMPL_MARKER_RE.search(line) or _VALUE_CONTEXT_RE.search(line):
                continue
            for m in _SYM_RE.finditer(line):
                name = m.group(1)
                if name not in seen and not _exists(name):
                    seen[name] = (f, i)

    samples = [
        f"{path.relative_to(context.repo_root)}:{ln}: `{name}` referenced but no def/class in src/"
        for name, (path, ln) in sorted(seen.items())
    ]
    return DetectorResult(count=len(seen), samples=samples[:_MAX_SAMPLES])


# ── K2 ────────────────────────────────────────────────────────────────────────

_VALUE_LINE_RE = re.compile(
    r"(?:status|state|kind|value|priority|severity|level|verdict|outcome)s?\s*"
    r"(?:[:=]|\bcan be\b|\bis\b|\bof\b)",
    re.IGNORECASE,
)
_VAL_SYM_RE = re.compile(r"`([a-z][a-z0-9_]{2,})`")

_DEFAULT_KNOWN_VALUES = {
    "ready for ai", "in review", "in progress", "backlog", "done",
    "cancelled", "blocked", "running", "awaiting input",
    "lgtm", "concerns", "approved", "rejected",
    "low", "medium", "high", "urgent", "none",
    "small", "large",
    "info", "warn", "warning", "error", "critical",
    "bool", "int", "str", "list", "dict", "tuple", "float", "bytes",
    # Standard library module names commonly cited in docs (not enum values)
    "fcntl", "subprocess", "logging", "pathlib", "datetime", "asyncio",
    "threading", "multiprocessing", "json", "yaml", "toml",
}


def detect_k2(context: AuditContext) -> DetectorResult:
    """Flag enum/status values in docs not found as string literals in src."""
    audit_cfg = context.config.get("audit") or {}
    extra_known: set[str] = {v.lower() for v in (audit_cfg.get("known_values") or [])}
    known_values = _DEFAULT_KNOWN_VALUES | extra_known

    src_text, _ = _build_src_text(context)

    seen: dict[str, tuple[Path, int]] = {}
    for f in _doc_files(context.repo_root, audit_cfg):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if not _VALUE_LINE_RE.search(line):
                continue
            for m in _VAL_SYM_RE.finditer(line):
                name = m.group(1)
                if name in seen or name.lower() in known_values:
                    continue
                if re.search(rf"""['"]{re.escape(name)}['"]""", src_text):
                    continue
                if re.search(rf"^\s+{re.escape(name)}\s*:\s*[A-Za-z]", src_text, re.MULTILINE):
                    continue
                if re.search(rf"\b(def|class)\s+{re.escape(name)}\b", src_text):
                    continue
                seen[name] = (f, i)

    samples = [
        f"{path.relative_to(context.repo_root)}:{ln}: `{name}` cited as value but no string literal in src/"
        for name, (path, ln) in sorted(seen.items())
    ]
    return DetectorResult(count=len(seen), samples=samples[:_MAX_SAMPLES])


# ── K3: docstring Args section parameter drift ────────────────────────────────

# Matches a Google-style Args: section header (indented or not)
_ARGS_HEADER_RE = re.compile(r"^\s*Args:\s*$")
# `name (type): description` — captures both the name and the type when present.
_ARGS_PARAM_TYPED_RE = re.compile(r"^\s{4,}(\w+)\s*\(([^)]+)\)\s*:")
# Matches a documented parameter name in a Google-style Args section.
# Allows optional type annotation in parens: `param_name (type): description`
_ARGS_PARAM_RE = re.compile(r"^\s{4,}(\w+)(?:\s*\(.*?\))?\s*:")

# Google-style section headers that end the Args section
_GOOGLE_SECTION_HEADERS = frozenset({
    "Returns", "Return", "Yields", "Yield", "Raises", "Raise",
    "Note", "Notes", "Example", "Examples", "Attributes", "References",
    "Todo", "Warning", "Warnings", "See", "Hint", "Kwargs", "Kwarg",
})
_SECTION_HEADER_RE = re.compile(r"^(\s*)(\w[\w ]*?):\s*$")

# Parameters that are conventional and not worth checking
_SKIP_PARAMS = frozenset({"self", "cls", "args", "kwargs"})


def _get_docstring(func: _ast.FunctionDef | _ast.AsyncFunctionDef) -> str | None:
    """Return the docstring of a function node, or None."""
    if not func.body:
        return None
    first = func.body[0]
    if isinstance(first, _ast.Expr) and isinstance(first.value, _ast.Constant):
        val = first.value.value
        if isinstance(val, str):
            return val
    return None


def _parse_google_args(docstring: str) -> list[str]:
    """Extract parameter names from a Google-style Args: section."""
    lines = docstring.splitlines()
    in_args = False
    args_indent: int | None = None
    params: list[str] = []
    for line in lines:
        if _ARGS_HEADER_RE.match(line):
            in_args = True
            args_indent = None
            continue
        if in_args:
            if not line.strip():
                continue  # blank lines inside section — keep going
            # Check for another section header (same or less indentation than Args)
            sm = _SECTION_HEADER_RE.match(line)
            if sm and sm.group(2).rstrip() in _GOOGLE_SECTION_HEADERS:
                in_args = False
                continue
            # End section if line is not indented (no leading whitespace)
            if line and not line[0].isspace():
                in_args = False
                continue
            # A line with ≥4 leading spaces and a colon = parameter entry
            m = _ARGS_PARAM_RE.match(line)
            if m:
                param_name = m.group(1)
                # Track the indent level of first param to detect section headers at same level
                if args_indent is None:
                    args_indent = len(line) - len(line.lstrip())
                # Skip section headers and ALL_CAPS words (notes within param text)
                if param_name not in _GOOGLE_SECTION_HEADERS and not param_name.isupper():
                    params.append(param_name)
    return params


def _func_param_names(func: _ast.FunctionDef | _ast.AsyncFunctionDef) -> set[str]:
    """Collect all parameter names (excluding *args/**kwargs variadics)."""
    args = func.args
    names: set[str] = set()
    for arg in args.args + args.posonlyargs + args.kwonlyargs:
        names.add(arg.arg)
    if args.vararg:
        names.add(args.vararg.arg)
    if args.kwarg:
        names.add(args.kwarg.arg)
    return names - _SKIP_PARAMS


def detect_k3(context: AuditContext) -> DetectorResult:
    """Flag functions whose Google-style Args: docstring names a non-existent param.

    When a parameter is renamed or removed, the docstring is often left
    pointing at the old name.  K3 catches this by comparing the ``Args:``
    section of the docstring against the actual function signature.

    Only functions with a Google-style ``Args:`` block are checked.  Sphinx
    and NumPy docstrings are not parsed.  ``self``, ``cls``, ``*args``,
    and ``**kwargs`` are excluded.

    Exclude files via ``audit.exclude_paths.K3``.
    """
    globs: list[str] = []
    audit_cfg = context.config.get("audit") or {}
    exclude = (audit_cfg.get("exclude_paths") or {}).get("K3") or []
    globs.extend(exclude)

    samples: list[str] = []
    count = 0

    for path in _py_files(context, "K3"):
        if globs:
            from custodian.audit_kit.code_health import _glob_to_regex
            rel_str = str(path.relative_to(context.repo_root))
            if any(_glob_to_regex(g).match(rel_str) for g in globs):
                continue
        try:
            raw = path.read_text(encoding="utf-8")
            tree = _ast.parse(raw)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)

        for node in _ast.walk(tree):
            if not isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                continue
            doc = _get_docstring(node)
            if doc is None:
                continue
            doc_params = _parse_google_args(doc)
            if not doc_params:
                continue  # no Args section — nothing to check
            sig_params = _func_param_names(node)
            for pname in doc_params:
                if pname not in sig_params and pname not in _SKIP_PARAMS:
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        samples.append(
                            f"{rel}:{node.lineno}: {node.name}() — docstring Args `{pname}` not in signature"
                        )

    return DetectorResult(count=count, samples=samples)


# ── K4: docstring type drift ─────────────────────────────────────────────────


# Recognised aliases — both directions. Stored as a frozenset of frozensets;
# lookup normalises to canonical form (lowercase) before comparing.
_TYPE_ALIASES: tuple[frozenset[str], ...] = (
    frozenset({"list", "List"}),
    frozenset({"dict", "Dict"}),
    frozenset({"tuple", "Tuple"}),
    frozenset({"set", "Set"}),
    frozenset({"frozenset", "FrozenSet"}),
    frozenset({"type", "Type"}),
    frozenset({"none", "None", "NoneType"}),
    frozenset({"bool", "boolean", "Bool"}),
    frozenset({"str", "string", "String"}),
    frozenset({"int", "integer", "Int"}),
    frozenset({"float", "Float", "double", "Double"}),
    frozenset({"bytes", "Bytes"}),
    frozenset({"any", "Any", "object", "Object"}),
)


def _normalise_type(s: str) -> str:
    """Normalise a type string for K4 comparison.

    Strip whitespace, normalise spaces around ``|`` / ``,``, rewrite
    ``Optional[X]`` as ``X | None``, and rewrite generic-bracket aliases
    (``List[X]`` → ``list[X]``, ``Dict[K, V]`` → ``dict[K, V]``, ...).
    """
    if s is None:
        return ""
    out = s.strip()
    # Capitalised generics → lowercase builtins (List[X] → list[X]) FIRST
    # so Optional[List[str]] → Optional[list[str]] → list[str] | None
    # works without bracket-matching gymnastics.
    for word in ("List", "Dict", "Tuple", "Set", "FrozenSet", "Type"):
        out = re.sub(rf"\b{word}\[", f"{word.lower()}[", out)
    # Optional[X] → X | None — bracket-balanced match for X.
    out = _rewrite_optional(out)
    # Tighten spaces around `|` and `,`
    out = re.sub(r"\s*\|\s*", " | ", out)
    out = re.sub(r"\s*,\s*", ", ", out)
    out = re.sub(r"\s+", " ", out).strip()
    return out


def _rewrite_optional(s: str) -> str:
    """Rewrite ``Optional[X]`` → ``X | None`` with proper bracket balancing
    so nested generics survive (``Optional[List[str]]`` → ``list[str] | None``).
    """
    out = s
    while True:
        idx = out.find("Optional[")
        if idx == -1:
            return out
        depth = 0
        for j in range(idx + len("Optional["), len(out)):
            if out[j] == "[":
                depth += 1
            elif out[j] == "]":
                if depth == 0:
                    inner = out[idx + len("Optional[") : j].strip()
                    out = out[:idx] + f"{inner} | None" + out[j + 1 :]
                    break
                depth -= 1
        else:
            return out  # unmatched `[` — give up rewriting


def _types_equivalent(a: str, b: str) -> bool:
    """True when two type strings are equivalent under K4's aliases."""
    if not a or not b:
        return True  # don't flag — one side is missing, K4 only catches drift
    na = _normalise_type(a)
    nb = _normalise_type(b)
    if na == nb:
        return True
    # Atomic-name aliases (``str`` vs ``string``)
    for cluster in _TYPE_ALIASES:
        if na in cluster and nb in cluster:
            return True
    return False


def _parse_google_args_typed(docstring: str) -> dict[str, str]:
    """Return ``{param_name: type_string}`` from a Google-style Args section.

    Only includes entries that explicitly declare a type ``param (type):``.
    Untyped entries (``param: ...``) are skipped — they're K3 territory,
    not K4. Returns ``{}`` when no Args section is present.
    """
    out: dict[str, str] = {}
    in_args = False
    for line in docstring.splitlines():
        if _ARGS_HEADER_RE.match(line):
            in_args = True
            continue
        if not in_args:
            continue
        if not line.strip():
            continue
        sm = _SECTION_HEADER_RE.match(line)
        if sm and sm.group(2).rstrip() in _GOOGLE_SECTION_HEADERS:
            in_args = False
            continue
        if line and not line[0].isspace():
            in_args = False
            continue
        m = _ARGS_PARAM_TYPED_RE.match(line)
        if m:
            name, typ = m.group(1), m.group(2).strip()
            if name not in _GOOGLE_SECTION_HEADERS and not name.isupper():
                out[name] = typ
    return out


def _signature_param_types(
    func: _ast.FunctionDef | _ast.AsyncFunctionDef,
) -> dict[str, str]:
    """Return ``{param_name: annotation_string}`` for parameters that have
    a type annotation. Parameters without an annotation are omitted.
    """
    out: dict[str, str] = {}
    args = func.args
    for arg in args.args + args.posonlyargs + args.kwonlyargs:
        if arg.annotation is not None:
            out[arg.arg] = _ast.unparse(arg.annotation)
    return out


def detect_k4(context: AuditContext) -> DetectorResult:
    """Flag functions where docstring Args type doesn't match signature.

    Only flags when *both* sides declare a type and they disagree after
    normalisation. Either side missing = silent (K3/E1 territory).

    Exclude files via ``audit.exclude_paths.K4``.
    """
    audit_cfg = context.config.get("audit") or {}
    globs: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("K4") or [])

    samples: list[str] = []
    count = 0

    for path in _py_files(context, "K4"):
        if globs:
            from custodian.audit_kit.code_health import _glob_to_regex
            rel_str = str(path.relative_to(context.repo_root))
            if any(_glob_to_regex(g).match(rel_str) for g in globs):
                continue
        try:
            raw = path.read_text(encoding="utf-8")
            tree = _ast.parse(raw)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)

        for node in _ast.walk(tree):
            if not isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                continue
            doc = _get_docstring(node)
            if doc is None:
                continue
            doc_types = _parse_google_args_typed(doc)
            if not doc_types:
                continue
            sig_types = _signature_param_types(node)
            for pname, doc_type in doc_types.items():
                if pname in _SKIP_PARAMS:
                    continue
                sig_type = sig_types.get(pname)
                if sig_type is None:
                    continue  # E1 territory
                if not _types_equivalent(doc_type, sig_type):
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        samples.append(
                            f"{rel}:{node.lineno}: {node.name}() — "
                            f"docstring `{pname}` typed `{doc_type}` "
                            f"but signature says `{sig_type}`"
                        )

    return DetectorResult(count=count, samples=samples)
