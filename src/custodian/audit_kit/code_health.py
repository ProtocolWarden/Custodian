# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
from __future__ import annotations

import ast
from pathlib import Path
import re

from custodian.audit_kit.detector import AuditContext, Detector, DetectorResult, HIGH, MEDIUM, LOW


def _glob_to_regex(glob: str) -> re.Pattern[str]:
    """Translate a path-style glob to a regex.

    Supports:
      ``*``    — any chars except path separator (``/``)
      ``/**/`` — zero or more directory segments (recursive marker)
      ``**``   — any chars including ``/`` (loose recursive form)
      ``?``    — any single char except ``/``

    Unlike stdlib ``fnmatch``, ``*`` here is path-component aware so
    ``src/foo/*.py`` matches ``src/foo/bar.py`` but **not**
    ``src/foo/sub/bar.py``. Use ``**`` for recursive intent.

    The ``/**/`` form is special-cased so ``src/pkg/**/*.py`` matches
    both ``src/pkg/leaf.py`` (zero dir segments) and
    ``src/pkg/sub/leaf.py`` (one or more).
    """
    # Pre-pass: collapse `/**/` to a sentinel that becomes `(?:/.*/|/)` —
    # this matches a single separator OR `/anything/`, i.e. zero or more
    # directory segments. Done before per-char processing so the special
    # form isn't mistaken for `**` followed by `/`.
    SENTINEL = "\x00DOUBLESTAR_DIR\x00"
    glob = glob.replace("/**/", SENTINEL)

    out: list[str] = []
    i = 0
    while i < len(glob):
        if glob.startswith(SENTINEL, i):
            out.append("(?:/.*/|/)")
            i += len(SENTINEL)
            continue
        ch = glob[i]
        if ch == "*":
            if i + 1 < len(glob) and glob[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("\\A" + "".join(out) + "\\Z")


def _matches_any(rel_path: str, globs: list[str]) -> bool:
    return any(_glob_to_regex(g).match(rel_path) for g in globs)


def _exclude_globs(context: AuditContext, detector_id: str) -> list[str]:
    """Per-detector path exclusions from `.custodian.yaml`.

    Schema:
        audit:
          exclude_paths:
            C2: ["src/cli/**", "src/foo/cli.py"]

    Globs are matched against each file's path relative to ``repo_root``
    via the glob matcher above (`*` is path-aware, `**` is recursive).
    A file is excluded if any glob matches. Repos use this
    to opt specific files out of a generic detector that doesn't fit
    (e.g. C2 'print statements' is wrong for a CLI tool's command files).
    """
    audit_cfg = context.config.get("audit", {}) or {}
    exclude = audit_cfg.get("exclude_paths", {}) or {}
    return list(exclude.get(detector_id, []) or [])


def _py_files(context: AuditContext, detector_id: str | None = None) -> list[Path]:
    """All .py files under ``src_root``, minus any matched by exclude globs."""
    paths = [path for path in context.src_root.rglob("*.py") if path.is_file()]
    if detector_id is None:
        return paths
    globs = _exclude_globs(context, detector_id)
    if not globs:
        return paths
    repo_root = context.repo_root
    kept: list[Path] = []
    for p in paths:
        rel = str(p.relative_to(repo_root))
        if _matches_any(rel, globs):
            continue
        kept.append(p)
    return kept


_MAX_SAMPLES = 8


_COMMENT_LINE_RE = re.compile(r"^\s*#.*$", re.MULTILINE)


def _strip_comment_lines(text: str) -> str:
    """Remove pure-comment lines (lines whose first non-whitespace char is '#')."""
    return _COMMENT_LINE_RE.sub("", text)


def _count_pattern(
    paths: list[Path],
    pattern: re.Pattern[str],
    *,
    skip_comment_lines: bool = False,
) -> DetectorResult:
    samples: list[str] = []
    count = 0
    for path in paths:
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        text = _strip_comment_lines(raw) if skip_comment_lines else raw
        for match in pattern.finditer(text):
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{path}:{match.group(0)[:60]}")
    return DetectorResult(count=count, samples=samples)


def build_code_health_detectors() -> list[Detector]:
    """C-class detector inventory.

    Detectors marked ``deprecated=True`` have an equivalent in an external
    tool (Ruff, Vulture, ty, Semgrep) that Custodian wraps via an adapter.
    Per the boundary refinement, the principle is "use the tool first,
    don't reimplement." Deprecated detectors are skipped by default; pass
    ``--include-deprecated`` (or ``skip_deprecated=False`` programmatically)
    to run them alongside the adapter equivalents.

    Detectors NOT marked deprecated either have no tool equivalent or
    encode nuance the tool doesn't capture (e.g. C1's ``[deferred, reviewed]``
    suppression). The "Replacement" column in
    ``docs/design/detector_disposition_matrix.md`` is the source of truth.
    """
    D = Detector
    return [
        # ── KEEP — no tool equivalent or unique nuance ───────────────────
        D("C1",  "TODO markers in source",                                          "open",    detect_c1,   LOW),
        D("C6",  "FIXME markers",                                                   "open",    detect_c6,   LOW),
        D("C8",  "stale handler references",                                        "partial", detect_c8,   MEDIUM),
        D("C11", "subprocess call without timeout",                                 "open",    detect_c11,  MEDIUM),
        D("C28", "hardcoded IP address in string literal",                          "open",    detect_c28,  LOW),
        D("C29", "file exceeds line-count threshold",                               "open",    detect_c29,  LOW),
        D("C13", "raw os.environ/os.getenv access outside config layer",            "open",    detect_c13,  MEDIUM),
        D("C32", "hardcoded credential in assignment",                              "open",    detect_c32,  HIGH),
        D("C33", "file with high ghost-work comment density (TODO/FIXME/HACK/XXX)", "open",    detect_c33,  LOW),
        D("C34", "commented-out function, class, or decorator definition",          "open",    detect_c34,  LOW),
        D("C37", "audit config key in .custodian.yaml not read by any source file", "open",    detect_c37,  LOW),
        D("C41", "json.dumps() without ensure_ascii=False (silently escapes Unicode)", "open", detect_c41, LOW),
        D("C42", "warnings.warn() without stacklevel= (warning points to wrong caller)", "open", detect_c42, LOW),
        D("C43", "json.dump() without ensure_ascii=False (silently escapes Unicode to file)", "open", detect_c43, LOW),
        # ── DEPRECATED — Ruff covers; kept for opt-in audit comparisons ──
        # See docs/design/detector_disposition_matrix.md for the mapping.
        D("C2",  "print() call in production code (use logging instead)",           "open",    detect_c2,   LOW,    deprecated=True),  # Ruff T201
        D("C4",  "broad except with pass: bare/Exception/BaseException swallowed",  "open",    detect_c4,   MEDIUM, deprecated=True),  # Ruff S110
        D("C9",  "except … as e handler where e is never used",                     "open",    detect_c9,   MEDIUM, deprecated=True),  # Ruff BLE001 (drops "without logger" nuance)
        D("C10", "naive datetime: datetime.now()/utcnow() without timezone",        "open",    detect_c10,  MEDIUM, deprecated=True),  # Ruff DTZ001/DTZ003/DTZ005
        D("C15", "f-string passed to logger (use %-formatting instead)",            "open",    detect_c15,  LOW,    deprecated=True),  # Ruff G004
        D("C16", "Path.read_text/write_text without encoding=",                     "open",    detect_c16,  LOW,    deprecated=True),  # Ruff PLW1514 (verify Path.* coverage)
        D("C17", "len(x) == 0 / len(x) > 0 comparison (use truthiness)",           "open",    detect_c17,  LOW,    deprecated=True),  # Ruff PLC1802
        D("C18", "f-string with no interpolation (redundant f-prefix)",             "open",    detect_c18,  LOW,    deprecated=True),  # Ruff F541
        D("C20", "raise Exception/BaseException directly (use specific type)",      "open",    detect_c20,  LOW,    deprecated=True),  # Ruff TRY002
        D("C23", "subprocess call with shell=True (injection risk)",                "open",    detect_c23,  HIGH,   deprecated=True),  # Ruff S602/S603
        D("C31", "weak hash algorithm (md5/sha1) without usedforsecurity=False",    "open",    detect_c31,  MEDIUM, deprecated=True),  # Ruff S324
        D("C35", "bare `# type: ignore` without specific error code in brackets",   "open",    detect_c35,  LOW,    deprecated=True),  # Ruff PGH003
        D("C36", "built-in open() in text mode without encoding= argument",         "open",    detect_c36,  LOW,    deprecated=True),  # Ruff PLW1514
        D("C38", "mutable default argument (list/dict/set literal as default)",      "open",    detect_c38,  MEDIUM, deprecated=True),  # Ruff B006
        D("C39", "logger.exception() called outside an exception handler",           "open",    detect_c39,  MEDIUM, deprecated=True),  # Ruff LOG014
        D("C40", "assert statement in non-test production code (disabled by -O)",    "open",    detect_c40,  LOW,    deprecated=True),  # Ruff S101
    ]


_DEFERRED_REVIEWED_RE = re.compile(r"\[deferred,\s*reviewed\b", re.IGNORECASE)
_TODO_RE = re.compile(r"\bTODO\b")


def detect_c1(context: AuditContext) -> DetectorResult:
    """Flag TODO comments, skipping lines tagged [deferred, reviewed]."""
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C1"):
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(raw.splitlines(), 1):
            if not _TODO_RE.search(line):
                continue
            if _DEFERRED_REVIEWED_RE.search(line):
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{path}:{lineno}: {line.strip()[:60]}")
    return DetectorResult(count=count, samples=samples)


# ── C2: print() in production code ───────────────────────────────────────────


def detect_c2(context: AuditContext) -> DetectorResult:
    """Flag bare print() calls in production source.

    ``print()`` is appropriate in CLI entrypoints but not in library or
    domain code where structured logging should be used instead.
    Exclude CLI/entrypoint files via ``audit.exclude_paths.C2``.

    Uses AST-based detection to avoid matching ``print(`` inside string
    literals (e.g. code passed to ``python -c "...print(...)"``).
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C2"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Name) and func.id == "print"):
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{rel}:{node.lineno}: print() call")
    return DetectorResult(count=count, samples=samples)


# ── C10: naive datetime ───────────────────────────────────────────────────────

_NAIVE_DT_RE = re.compile(r"\bdatetime\.(?:now|utcnow)\s*\(\s*\)")


def detect_c10(context: AuditContext) -> DetectorResult:
    """Flag datetime.now() / datetime.utcnow() calls without a timezone argument.

    Naive datetimes (no tzinfo) are ambiguous and often produce wrong
    comparisons when mixed with timezone-aware datetimes.  Use
    ``datetime.now(tz=timezone.utc)`` or ``datetime.now(tz=UTC)`` instead.
    ``datetime.utcnow()`` is deprecated in Python 3.12 for the same reason.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C10"):
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(raw.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if _NAIVE_DT_RE.search(line):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    rel = path.relative_to(context.repo_root)
                    samples.append(f"{rel}:{lineno}: {line.strip()[:70]}")
    return DetectorResult(count=count, samples=samples)


def detect_c6(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context, "C6"), re.compile(r"FIXME"))


def detect_c8(context: AuditContext) -> DetectorResult:
    stale_handlers = set(context.config.get("audit", {}).get("stale_handlers", []))
    common_words = set(context.config.get("audit", {}).get("common_words", []))
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C8"):
        text = path.read_text(encoding="utf-8")
        for handler in stale_handlers:
            if handler in text and handler not in common_words:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(f"{path}:{handler}")
    return DetectorResult(count=count, samples=samples)


_SUBPROCESS_CALL_RE = re.compile(
    r"\bsubprocess\.(run|call|check_output|check_call)\s*\("
)


def _extract_call_body(text: str, start: int) -> str:
    """Return the full text of a function call starting at ``start``.

    ``start`` should point to the opening ``(`` or the function name.
    Tracks parenthesis depth to find the closing ``)``; does not handle
    string literals containing unmatched parens (good enough for subprocess).
    """
    depth = 0
    i = text.find("(", start)
    if i == -1:
        return ""
    for j, ch in enumerate(text[i:], i):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[i : j + 1]
    return text[i:]


def detect_c11(context: AuditContext) -> DetectorResult:
    """Flag ``subprocess.run/call/check_output/check_call`` calls without ``timeout=``.

    A subprocess without a timeout can hang indefinitely, blocking the
    calling process (and any polling worker that owns it).  Short-lived
    tool calls (git, ruff, etc.) should specify a conservative timeout;
    long-running agent invocations may legitimately omit one and should
    be excluded via ``audit.exclude_paths.C11`` in ``.custodian.yaml``.

    Detection extracts the full call body by tracking parenthesis depth,
    so multi-line calls are handled correctly.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C11"):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        lines = text.splitlines()
        for m in _SUBPROCESS_CALL_RE.finditer(text):
            lineno = text[: m.start()].count("\n") + 1
            if lines[lineno - 1].lstrip().startswith("#"):
                continue
            call_body = _extract_call_body(text, m.start())
            if "timeout" in call_body:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                rel = path.relative_to(context.repo_root)
                samples.append(f"{rel}:{lineno}: {lines[lineno - 1].strip()[:60]}")
    return DetectorResult(count=count, samples=samples)


# ── C4: pass-in-except (swallowed exception) ─────────────────────────────────


_C4_BROAD_TYPES = frozenset({"Exception", "BaseException"})


def detect_c4(context: AuditContext) -> DetectorResult:
    """Flag broad ``except`` handlers (bare / Exception / BaseException) whose only statement is ``pass``.

    Broadly catching and silently swallowing exceptions hides real errors.
    Narrow catches (``except ValueError: pass``) are intentional suppression
    of a known failure mode and are not flagged.

    When suppression is genuinely required, either narrow the exception type,
    add a logger call, or exclude the file via ``audit.exclude_paths.C4``.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C4"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            body = node.body
            if not (len(body) == 1 and isinstance(body[0], ast.Pass)):
                continue
            exc_type = node.type
            is_broad = (
                exc_type is None  # bare except:
                or (isinstance(exc_type, ast.Name) and exc_type.id in _C4_BROAD_TYPES)
                or (isinstance(exc_type, ast.Attribute) and exc_type.attr in _C4_BROAD_TYPES)
            )
            if not is_broad:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                type_str = (
                    "except:" if exc_type is None
                    else f"except {exc_type.id if isinstance(exc_type, ast.Name) else exc_type.attr}:"
                )
                samples.append(f"{rel}:{node.lineno}: {type_str} pass")
    return DetectorResult(count=count, samples=samples)


# ── C9: broad exception catch with swallowed error ────────────────────────────


def _exception_var_referenced(handler: ast.ExceptHandler) -> bool:
    """Return True if the handler's bound variable is referenced in its body."""
    if handler.name is None:
        return False
    for node in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
        if isinstance(node, ast.Name) and node.id == handler.name:
            return True
    return False


def _handler_has_raise(handler: ast.ExceptHandler) -> bool:
    for node in ast.walk(ast.Module(body=handler.body, type_ignores=[])):
        if isinstance(node, ast.Raise):
            return True
    return False


def detect_c9(context: AuditContext) -> DetectorResult:
    """Flag ``except … as e`` handlers where ``e`` is never referenced in the body.

    Writing ``except Exception as e:`` explicitly binds the exception, signalling
    intent to use it — but if ``e`` never appears in the handler body, the error
    information is silently discarded.  Either remove ``as e`` (if suppression is
    intentional), or actually log/store/re-raise ``e``.

    Handlers without ``as name`` (e.g. bare ``except Exception:``) are not flagged
    because they make no implicit promise to use the exception object.

    Exclude known-intentional sites via ``audit.exclude_paths.C9``.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C9"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ExceptHandler):
                continue
            if node.name is None:
                continue
            if _exception_var_referenced(node):
                continue
            if _handler_has_raise(node):
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                exc_type = node.type
                type_str = (
                    "except:" if exc_type is None
                    else f"except {exc_type.id if isinstance(exc_type, ast.Name) else exc_type.attr}:"
                )
                samples.append(f"{rel}:{node.lineno}: {type_str} as {node.name} (variable unused)")
    return DetectorResult(count=count, samples=samples)


# ── C23: subprocess call with shell=True ──────────────────────────────────────

_SUBPROCESS_FUNCS = frozenset({"run", "call", "check_output", "check_call", "Popen"})


def detect_c23(context: AuditContext) -> DetectorResult:
    """Flag ``subprocess`` calls that use ``shell=True``.

    ``shell=True`` passes the command to the OS shell, which introduces a
    command-injection vector if any part of the command string includes
    user-controlled input.  Prefer passing a list of arguments instead.
    Exclude trusted-source usages via ``audit.exclude_paths.C23``.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C23"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_subprocess = (
                isinstance(func, ast.Attribute)
                and func.attr in _SUBPROCESS_FUNCS
                and isinstance(func.value, ast.Name)
                and func.value.id == "subprocess"
            )
            if not is_subprocess:
                continue
            has_shell_true = any(
                isinstance(kw, ast.keyword)
                and kw.arg == "shell"
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in node.keywords
            )
            if not has_shell_true:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{rel}:{node.lineno}: subprocess.{func.attr}(..., shell=True)")
    return DetectorResult(count=count, samples=samples)




def detect_c28(context: AuditContext) -> DetectorResult:
    """Flag hardcoded IPv4 address literals in string constants.

    Hardcoded IPs couple code to a specific environment and are easy to
    overlook when infrastructure changes.  Use configuration, environment
    variables, or named constants instead.  ``127.0.0.1`` and ``0.0.0.0``
    (localhost/any-bind) are excluded as they are almost always intentional.
    """
    _EXCLUDED = {"127.0.0.1", "0.0.0.0", "127.0.0.0"}
    samples: list[str] = []
    count = 0
    _IP_IN_STRING = re.compile(r"""["'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})["']""")
    for path in _py_files(context, "C28"):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for m in _IP_IN_STRING.finditer(text):
            ip = m.group(1)
            if ip in _EXCLUDED:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{path}:{m.group(0)[:40]}")
    return DetectorResult(count=count, samples=samples)


def detect_c29(context: AuditContext) -> DetectorResult:
    """Flag source files that exceed the line-count threshold.

    Very long files are hard to navigate and often indicate a missing
    abstraction boundary.  Default threshold: 500 lines.  Configurable:
        audit:
          c29_threshold: 800
    """
    audit_cfg = context.config.get("audit") or {}
    try:
        limit = int(audit_cfg.get("c29_threshold") or 500)
    except (TypeError, ValueError):
        limit = 500

    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C29"):
        try:
            n = path.read_text(encoding="utf-8").count("\n")
        except (OSError, UnicodeDecodeError):
            continue
        if n > limit:
            count += 1
            if len(samples) < _MAX_SAMPLES:
                rel = path.relative_to(context.repo_root)
                samples.append(f"{rel}: {n} lines (limit {limit})")
    return DetectorResult(count=count, samples=samples)


# ── C31: weak hash algorithms ─────────────────────────────────────────────────

_IMPORTS_HASHLIB_RE = re.compile(r"^\s*import\s+hashlib\b|from\s+hashlib\b", re.MULTILINE)
_WEAK_HASH_CALL_RE = re.compile(r"\.(md5|sha1)\s*\(", re.IGNORECASE)
_USEDFORSECURITY_RE = re.compile(r"usedforsecurity\s*=\s*False", re.IGNORECASE)


def detect_c31(context: AuditContext) -> DetectorResult:
    """Flag hashlib.md5() / hashlib.sha1() calls without usedforsecurity=False.

    MD5 and SHA1 are cryptographically broken and should not be used for
    security-sensitive purposes (MACs, signatures, password hashing).
    Python 3.9+ added ``usedforsecurity=False`` to explicitly mark
    non-security uses (e.g. content-addressing, cache keys).  Calls that
    omit this flag are ambiguous and should be reviewed.

    Only files that import hashlib are scanned to avoid false positives from
    unrelated methods named ``.md5()`` or ``.sha1()``.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C31"):
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if not _IMPORTS_HASHLIB_RE.search(raw):
            continue
        for lineno, line in enumerate(raw.splitlines(), 1):
            m = _WEAK_HASH_CALL_RE.search(line)
            if not m:
                continue
            if _USEDFORSECURITY_RE.search(line):
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                rel = path.relative_to(context.repo_root)
                algo = m.group(1).lower()
                samples.append(
                    f"{rel}:{lineno}: .{algo}() — add usedforsecurity=False if non-security use"
                )
    return DetectorResult(count=count, samples=samples)


# ── C32: hardcoded credentials ────────────────────────────────────────────────

_CREDENTIAL_NAMES = frozenset({
    "password", "passwd", "pwd", "secret", "token",
    "api_key", "apikey", "access_key", "private_key",
    "client_secret", "auth_token", "signing_key", "service_key",
    "credentials", "credential",
})

_CREDENTIAL_NAME_EXCLUSION_SUFFIXES = frozenset({
    "endpoint", "url", "uri", "path", "env", "var", "name", "param",
    "header", "field", "label",
})

_PLACEHOLDER_RE = re.compile(
    r"(?i)(your[-_]?|example|test[-_]?|dummy|fake|change[-_]?me|"
    r"replace|placeholder|xxx+|yyy+|aaa+|\$\{|<[^>]+>|todo|fixme)"
)

_ENV_VAR_RE = re.compile(r"^[A-Z][A-Z0-9_]+$")


def _is_credential_name(name: str) -> bool:
    """True if the variable/key name refers to an actual credential value.

    Uses word-boundary matching: splits on ``_``, ``.``, ``-`` and checks
    unigrams and bigrams against the credential name set.  Names whose last
    word is an exclusion suffix (endpoint, url, env, …) are skipped — they
    typically hold a URL or env-var name, not the secret itself.

    Examples that match:  password, api_key, client_secret, auth_token
    Examples that don't:  token_endpoint, word_tokenizer, secret_env
    """
    words = [w.lower().rstrip("s") for w in re.split(r"[_.\-]", name) if w]
    if not words:
        return False
    # If the last word is a non-credential suffix, this name is a URL/env ref
    if words[-1] in _CREDENTIAL_NAME_EXCLUSION_SUFFIXES:
        return False
    # Check unigrams
    if any(w in _CREDENTIAL_NAMES for w in words):
        return True
    # Check bigrams (api_key, access_key, client_secret, etc.)
    bigrams = ["_".join(words[i:i+2]) for i in range(len(words) - 1)]
    return any(b in _CREDENTIAL_NAMES for b in bigrams)


def _is_real_credential(value: str) -> bool:
    """Return True if value looks like an actual credential (not a placeholder)."""
    if not value or len(value) < 4:
        return False
    if _PLACEHOLDER_RE.search(value):
        return False
    # URL values are not credentials
    if value.startswith(("http://", "https://", "ftp://")):
        return False
    # ALL_CAPS values are env-var names pointing to where the secret lives
    if _ENV_VAR_RE.match(value):
        return False
    return True


def detect_c32(context: AuditContext) -> DetectorResult:
    """Flag assignments where a credential-named variable is set to a string literal.

    Detects patterns like:
        password = "actual_value"
        self.api_key = "sk-..."
        config = {"token": "live-secret"}

    Skips obvious placeholders ("your-token-here", "example", etc.) and
    very short values that are likely defaults or empty sentinels.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C32"):
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            # Variable assignments: password = "..."
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                    continue
                for target in targets:
                    name = None
                    if isinstance(target, ast.Name):
                        name = target.id
                    elif isinstance(target, ast.Attribute):
                        name = target.attr
                    if name and _is_credential_name(name) and _is_real_credential(value.value):
                        count += 1
                        if len(samples) < _MAX_SAMPLES:
                            samples.append(
                                f"{rel}:{node.lineno}: {name} = {value.value[:20]!r}..."
                                if len(value.value) > 20
                                else f"{rel}:{node.lineno}: {name} = {value.value!r}"
                            )
            # Dict literals: {"password": "...", "token": "..."}
            elif isinstance(node, ast.Dict):
                for key, val in zip(node.keys, node.values):
                    if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                        continue
                    if not (isinstance(val, ast.Constant) and isinstance(val.value, str)):
                        continue
                    if _is_credential_name(key.value) and _is_real_credential(val.value):
                        count += 1
                        if len(samples) < _MAX_SAMPLES:
                            samples.append(
                                f"{rel}:{node.lineno}: dict key {key.value!r} = {val.value[:20]!r}..."
                                if len(val.value) > 20
                                else f"{rel}:{node.lineno}: dict key {key.value!r} = {val.value!r}"
                            )
    return DetectorResult(count=count, samples=samples)


# ── C33: ghost-work comment density ──────────────────────────────────────────

_GHOST_MARKER_RE = re.compile(r"#[^\n]*\b(TODO|FIXME|HACK|XXX|NOCOMMIT)\b", re.IGNORECASE)


def detect_c33(context: AuditContext) -> DetectorResult:
    """Flag files with a high density of ghost-work comment markers.

    Counts # TODO / FIXME / HACK / XXX / NOCOMMIT per file. Files at or
    above the threshold are flagged with their total count. The threshold
    is configurable via audit.c33_threshold in .custodian.yaml (default 5).
    """
    audit_cfg = context.config.get("audit") or {}
    threshold = int(audit_cfg.get("c33_threshold") or 5)
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C33"):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        markers = _GHOST_MARKER_RE.findall(text)
        if len(markers) >= threshold:
            count += 1
            if len(samples) < _MAX_SAMPLES:
                rel = path.relative_to(context.repo_root)
                samples.append(
                    f"{rel} — {len(markers)} ghost markers (TODO/FIXME/HACK/XXX)"
                )
    return DetectorResult(count=count, samples=samples)


# ── C13: raw os.environ / os.getenv outside config layer ─────────────────────

_ENV_ACCESS_RE = re.compile(r"\bos\.(environ|getenv)\b")


def detect_c13(context: AuditContext) -> DetectorResult:
    """Flag raw os.environ/os.getenv access outside the designated config layer.

    Bypassing a centralised config layer makes secret rotation and test
    isolation harder. Mark allowed paths via ``audit.c13_allowed_paths``
    in ``.custodian.yaml`` (glob patterns relative to repo root). Tests
    and the config layer itself are allowed by default.

    Config example::

        audit:
          c13_allowed_paths:
            - "src/config/**"
            - "tests/**"
            - "src/myapp/start.py"
    """
    audit_cfg = context.config.get("audit") or {}
    extra_globs: list[str] = list(audit_cfg.get("c13_allowed_paths") or [])
    tests_rel = (
        str(context.tests_root.relative_to(context.repo_root))
        if context.tests_root.is_dir()
        else "tests"
    )
    allowed_globs = [f"{tests_rel}/**", f"{tests_rel}/*.py"] + extra_globs

    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C13"):
        rel = str(path.relative_to(context.repo_root))
        if _matches_any(rel, allowed_globs):
            continue
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for lineno, line in enumerate(raw.splitlines(), 1):
            if _ENV_ACCESS_RE.search(line):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(f"{path}:{lineno}: {line.strip()[:60]}")
    return DetectorResult(count=count, samples=samples)


# C7 (assert True) was retired 2026-05-05. Ruff B011 covers `assert False`;
# `assert True` is low-value (always passes, never raises). Per the
# disposition matrix, this detector adds no signal worth maintaining.


# ── C15: f-string in logger call (use %-formatting instead) ──────────────────

_LOGGER_METHODS = frozenset({"debug", "info", "warning", "error", "critical", "exception"})


def detect_c15(context: AuditContext) -> DetectorResult:
    """Flag f-strings passed directly to logger calls.

    Logger calls like ``logger.info(f"val={x}")`` evaluate the f-string eagerly
    even when the log level is suppressed, wasting CPU on string formatting.
    Use ``logger.info("val=%s", x)`` instead — the format is applied lazily only
    when the message will actually be emitted.
    Exclude files via ``audit.exclude_paths.C15``.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C15"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr in _LOGGER_METHODS):
                continue
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        samples.append(
                            f"{rel}:{node.lineno}: logger.{func.attr}(f\"...\") — use %s args"
                        )
                    break
    return DetectorResult(count=count, samples=samples)


# ── C16: Path.read_text / write_text without encoding ────────────────────────

_TEXT_IO_METHODS = frozenset({"read_text", "write_text"})


def detect_c16(context: AuditContext) -> DetectorResult:
    """Flag ``Path.read_text()`` / ``Path.write_text()`` calls missing ``encoding=``.

    Without an explicit encoding the system default is used, which varies
    across platforms and locales.  Always pass ``encoding="utf-8"`` (or the
    relevant encoding) to ensure consistent behaviour.
    Exclude files via ``audit.exclude_paths.C16``.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C16"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Attribute) and func.attr in _TEXT_IO_METHODS):
                continue
            # Path.read_text() takes 0 positional args; Path.write_text() takes 1.
            # A call with 2+ positional args is likely a custom write_text(name, data)
            # method on a non-Path object — skip to avoid false positives.
            max_pos_args = 1 if func.attr == "write_text" else 0
            if len(node.args) > max_pos_args:
                continue
            has_encoding = any(
                isinstance(kw, ast.keyword) and kw.arg == "encoding"
                for kw in node.keywords
            )
            if not has_encoding:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"{rel}:{node.lineno}: .{func.attr}() without encoding="
                    )
    return DetectorResult(count=count, samples=samples)


# ── C17: len(x) == 0 / len(x) > 0 comparison ────────────────────────────────


def detect_c17(context: AuditContext) -> DetectorResult:
    """Flag ``len(x) == 0`` and ``len(x) > 0`` — use ``not x`` / ``bool(x)`` instead.

    Comparing ``len()`` to a literal is less idiomatic and slower than the
    truthiness check.  ``len(x) == 0`` → ``not x``;  ``len(x) > 0`` → ``x``
    or ``bool(x)`` (or ``if x:``).
    Exclude files via ``audit.exclude_paths.C17``.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C17"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare):
                continue
            left = node.left
            if not (isinstance(left, ast.Call)
                    and isinstance(left.func, ast.Name)
                    and left.func.id == "len"):
                continue
            for op, comp in zip(node.ops, node.comparators):
                if not isinstance(comp, ast.Constant) or comp.value != 0:
                    continue
                if isinstance(op, (ast.Eq, ast.NotEq, ast.Gt, ast.GtE, ast.Lt, ast.LtE)):
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        samples.append(f"{rel}:{node.lineno}: len(...) comparison to 0")
                    break
    return DetectorResult(count=count, samples=samples)


# ── C18: f-string with no interpolation (redundant f-prefix) ─────────────────


def detect_c18(context: AuditContext) -> DetectorResult:
    """Flag f-strings that contain no ``{...}`` interpolation.

    An f-string with no format expression (e.g. ``f"plain text"``) is identical
    to a plain string but carries the overhead of f-string syntax and confuses
    readers.  Remove the ``f`` prefix.
    Exclude files via ``audit.exclude_paths.C18``.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C18"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        # format_spec of a FormattedValue is itself a JoinedStr but is not redundant
        format_spec_ids: set[int] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FormattedValue) and node.format_spec is not None:
                format_spec_ids.add(id(node.format_spec))
        for node in ast.walk(tree):
            if not isinstance(node, ast.JoinedStr):
                continue
            if id(node) in format_spec_ids:
                continue
            has_value = any(isinstance(v, ast.FormattedValue) for v in node.values)
            if not has_value:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"{rel}:{node.lineno}: f-string with no interpolation"
                    )
    return DetectorResult(count=count, samples=samples)


# ── C20: raise with generic Exception/BaseException ──────────────────────────

_GENERIC_EXCEPTION_NAMES = frozenset({"Exception", "BaseException"})


def detect_c20(context: AuditContext) -> DetectorResult:
    """Flag ``raise Exception(...)`` and ``raise BaseException(...)`` directly.

    Raising a generic ``Exception`` or ``BaseException`` gives callers no way
    to catch the error selectively.  Define or reuse a specific exception class
    so that callers can distinguish this failure from others.
    Exclude files via ``audit.exclude_paths.C20``.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C20"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Raise):
                continue
            exc = node.exc
            if not isinstance(exc, ast.Call):
                continue
            func = exc.func
            is_generic = (
                isinstance(func, ast.Name) and func.id in _GENERIC_EXCEPTION_NAMES
            )
            if not is_generic:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{rel}:{node.lineno}: raise {func.id}(...)")
    return DetectorResult(count=count, samples=samples)


# ── C34: commented-out function / class / decorator definitions ───────────────

# Matches lines where a `def`, `async def`, `class`, or `@decorator` appears
# right after the `#` marker (with optional leading whitespace on both sides).
# English prose almost never starts with these keywords after a hash.
_COMMENTED_DEF_RE = re.compile(
    r"^\s*#\s*(async\s+def\s+|def\s+|class\s+[A-Za-z_]|@[A-Za-z_]).*",
    re.MULTILINE,
)


def detect_c34(context: AuditContext) -> DetectorResult:
    """Flag commented-out ``def``, ``async def``, ``class``, or ``@decorator`` lines.

    A comment that starts with ``def``, ``class``, ``async def``, or a decorator
    sigil (``@name``) is almost never English prose.  These lines are nearly always
    production code that was disabled by prepending ``#`` instead of being deleted.
    Commented-out code accumulates silently, causes merge conflicts, and misleads
    readers about what the module actually does.

    Exclude files via ``audit.exclude_paths.C34``.
    Examples that are *not* flagged: ``# type: ignore``, ``# noqa``,
    ``# see SomeClass for details``, regular sentence comments.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C34"):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = path.relative_to(context.repo_root)
        for match in _COMMENTED_DEF_RE.finditer(text):
            line_text = match.group(0).strip()
            # Skip lines that are part of a docstring (heuristic: if the match
            # falls inside a triple-quote block we'd need a full parse; instead
            # skip lines where the comment marker is preceded by a quote char).
            start = match.start()
            preceding = text[max(0, start - 3):start].strip()
            if preceding and preceding[-1] in ('"', "'"):
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{rel}: {line_text[:80]}")
    return DetectorResult(count=count, samples=samples)


# ── C35: bare `# type: ignore` without error-code brackets ───────────────────

_BARE_TYPE_IGNORE_COMMENT_RE = re.compile(r"#\s*type:\s*ignore(?!\s*\[)")


def detect_c35(context: AuditContext) -> DetectorResult:
    """Flag inline ``# type: ignore`` suppressions that lack a specific error-code.

    ``# type: ignore`` without ``[error-code]`` is a blanket suppression that
    hides ALL type errors on the line.  When the underlying issue is later fixed
    the suppression silently masks new errors.  The correct form is::

        some_call()  # type: ignore[attr-defined]

    Uses ``tokenize`` to scan only real comment tokens — string literals and
    docstrings that discuss ``# type: ignore`` are never flagged.
    Only inline suppression comments are counted: comment-only lines (where
    the comment is the only non-whitespace content) are skipped.

    Exclude files via ``audit.exclude_paths.C35``.
    """
    import io
    import tokenize as _tokenize

    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C35"):
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        rel = path.relative_to(context.repo_root)
        lines = raw.splitlines()
        try:
            tokens = list(_tokenize.generate_tokens(io.StringIO(raw).readline))
        except _tokenize.TokenError:
            continue
        for tok_type, tok_string, (lineno, col), _, _ in tokens:
            if tok_type != _tokenize.COMMENT:
                continue
            if not _BARE_TYPE_IGNORE_COMMENT_RE.search(tok_string):
                continue
            # Skip comment-only lines — col 0 or nothing but whitespace before #
            if lineno <= len(lines):
                line = lines[lineno - 1]
                before = line[:col].strip()
                if not before:
                    continue  # pure comment line, not an active suppression
            count += 1
            if len(samples) < _MAX_SAMPLES:
                stripped = lines[lineno - 1].strip() if lineno <= len(lines) else tok_string
                samples.append(f"{rel}:{lineno}: {stripped[:80]}")
    return DetectorResult(count=count, samples=samples)


# ── C36: built-in open() in text mode without encoding= ──────────────────────

_TEXT_OPEN_MODES = frozenset({"r", "w", "a", "x", "r+", "w+", "a+", "x+"})


def _is_text_open_mode(mode_node: ast.expr | None) -> bool:
    """True if the mode node represents a text (non-binary) open mode or is absent."""
    if mode_node is None:
        return True  # default mode "r" — text
    if not isinstance(mode_node, ast.Constant) or not isinstance(mode_node.value, str):
        return True  # unknown mode — conservatively flag it
    return mode_node.value.strip('"\'') in _TEXT_OPEN_MODES


def detect_c36(context: AuditContext) -> DetectorResult:
    """Flag built-in ``open()`` calls in text mode without an ``encoding=`` argument.

    ``open(file)`` uses the system locale encoding by default, which differs
    across platforms and locales.  Code that omits ``encoding=`` silently
    reads/writes incorrect bytes on non-UTF-8 systems.  Always pass
    ``encoding="utf-8"`` (or the applicable encoding).

    Only the built-in ``open()`` function is checked — attribute-based opens
    like ``wave.open()``, ``Image.open()``, or ``webbrowser.open()`` are
    different APIs and not flagged.  Binary modes (containing ``b``) are
    skipped.

    Exclude files via ``audit.exclude_paths.C36``.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C36"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw)
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            # Only the bare built-in open(), not wave.open(), Image.open(), etc.
            if not (isinstance(func, ast.Name) and func.id == "open"):
                continue
            # Second positional argument is the mode (first is the file).
            mode_node = node.args[1] if len(node.args) >= 2 else None
            # Also check mode= keyword argument.
            for kw in node.keywords:
                if kw.arg == "mode":
                    mode_node = kw.value
                    break
            # Binary modes don't need encoding=
            if isinstance(mode_node, ast.Constant) and isinstance(mode_node.value, str):
                if "b" in mode_node.value:
                    continue
            if not _is_text_open_mode(mode_node):
                continue
            # Already has encoding=
            has_encoding = any(kw.arg == "encoding" for kw in node.keywords)
            if has_encoding:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{rel}:{node.lineno}: open() in text mode without encoding=")
    return DetectorResult(count=count, samples=samples)


# ── C37 ───────────────────────────────────────────────────────────────────────

def _flatten_yaml_keys(obj: object, prefix: str = "") -> list[str]:
    """Recursively flatten a YAML dict into dotted key paths.

    Only descends into dicts; list and scalar values terminate the path.
    The ``audit`` top-level section is the root prefix for Custodian config.
    """
    if not isinstance(obj, dict):
        return []
    result: list[str] = []
    for k, v in obj.items():
        full = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            result.extend(_flatten_yaml_keys(v, full))
        else:
            result.append(full)
    return result


def detect_c37(context: AuditContext) -> DetectorResult:
    """Flag audit keys in .custodian.yaml whose string never appears in source.

    Reads the ``audit:`` section of ``.custodian.yaml`` (if present) and
    collects every leaf key name.  Then scans all Python source files for
    that key as a string literal (``"key_name"``).  A key absent from all
    source files is likely stale from a retired detector and can be removed.

    Only checks simple leaf keys (not dotted paths) to avoid false positives
    from nested config structures.  ``exclude_paths`` sub-keys are always
    skipped — they are used generically by the runner, not per-detector code.

    This detector only runs if ``.custodian.yaml`` is present at ``repo_root``.
    """
    config_path = context.repo_root / ".custodian.yaml"
    if not config_path.exists():
        return DetectorResult(count=0, samples=[])

    try:
        import yaml  # type: ignore[import-not-found]
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except Exception:
        return DetectorResult(count=0, samples=[])

    if not isinstance(raw, dict):
        return DetectorResult(count=0, samples=[])

    audit_section = raw.get("audit")
    if not isinstance(audit_section, dict):
        return DetectorResult(count=0, samples=[])

    # Collect leaf key names in the audit section, skip exclude_paths (generic runner key)
    candidate_keys: list[str] = []
    for k in audit_section.keys():
        if k == "exclude_paths":
            continue
        candidate_keys.append(k)

    if not candidate_keys:
        return DetectorResult(count=0, samples=[])

    # Concatenate all source text once
    src_text = ""
    for path in _py_files(context):
        try:
            src_text += path.read_text(encoding="utf-8", errors="replace") + "\n"
        except OSError:
            continue

    # Also scan plugin modules under repo_root
    for extra in context.repo_root.rglob("*.py"):
        if extra.is_relative_to(context.src_root):
            continue  # already included
        try:
            src_text += extra.read_text(encoding="utf-8", errors="replace") + "\n"
        except OSError:
            continue

    samples: list[str] = []
    count = 0
    for key in sorted(candidate_keys):
        # Key must appear as a string literal in source
        if re.search(rf"""['"]{re.escape(key)}['"]""", src_text):
            continue
        count += 1
        if len(samples) < _MAX_SAMPLES:
            samples.append(f".custodian.yaml: audit.{key} — key never referenced in source")
    return DetectorResult(count=count, samples=samples)


# ── C38: mutable default argument ────────────────────────────────────────────

def detect_c38(context: AuditContext) -> DetectorResult:
    """Flag function definitions with a mutable literal as a default argument.

    Mutable defaults (``[]``, ``{}``, ``set()``) are shared across all calls that
    use the default — mutations accumulate across invocations.  Recognized forms:

    - ``def f(x=[]):``  — list literal
    - ``def f(x={}):``  — dict literal
    - ``def f(x={1,2}):`` — set literal
    - ``def f(x=set()):`` — bare ``set()`` call (dict literal covers ``dict()``)

    ``None`` defaults used as sentinels are not flagged.
    Excludes paths via ``audit.exclude_paths.C38``.
    """
    import fnmatch as _fnmatch
    audit_cfg: dict = context.config.get("audit") or {}
    excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("C38") or [])

    samples: list[str] = []
    count = 0

    for path in _py_files(context, "C38"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw, filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        rel_posix = rel.as_posix()
        if excludes and any(_fnmatch.fnmatch(rel_posix, excl) for excl in excludes):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for default in node.args.defaults + node.args.kw_defaults:
                if default is None:
                    continue
                is_mutable = (
                    isinstance(default, (ast.List, ast.Dict, ast.Set))
                    or (
                        isinstance(default, ast.Call)
                        and isinstance(default.func, ast.Name)
                        and default.func.id in ("set", "dict", "list")
                        and not default.args
                        and not default.keywords
                    )
                )
                if not is_mutable:
                    continue
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    kind = type(default).__name__.lower().replace("dict", "{}").replace("list", "[]").replace("set", "set()")
                    samples.append(
                        f"{rel}:{node.lineno}: {node.name}() — mutable default {kind}"
                    )
                break  # one finding per function
    return DetectorResult(count=count, samples=samples)


# ── C39: logger.exception() outside except handler ───────────────────────────


class _ExceptionContextVisitor(ast.NodeVisitor):
    """Collect X.exception(...) calls that are not inside any except handler."""

    def __init__(self) -> None:
        self._depth: int = 0
        self.findings: list[tuple[int, str]] = []  # (lineno, logger_name)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self._depth += 1
        self.generic_visit(node)
        self._depth -= 1

    def visit_Call(self, node: ast.Call) -> None:
        if (
            self._depth == 0
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "exception"
            and isinstance(node.func.value, ast.Name)
        ):
            self.findings.append((node.lineno, node.func.value.id))
        self.generic_visit(node)


def detect_c39(context: AuditContext) -> DetectorResult:
    """Flag ``logger.exception()`` calls made outside an active exception handler.

    ``logging.Logger.exception()`` attaches the current exception traceback via
    ``sys.exc_info()``.  When called outside an ``except`` block there is no
    active exception, so the call logs ``NoneType: None`` as the traceback —
    a misleading no-op.  The correct replacement is ``logger.error()``.

    Only the *attribute name* ``exception`` is matched (``*.exception(...)``),
    so the detector is name-agnostic about the logger variable.  Calls to
    unrelated methods named ``exception`` on other objects (e.g. a pytest
    ``raises`` result) are therefore also flagged — exclude those paths via
    ``audit.exclude_paths.C39`` if needed.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C39"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw, filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        visitor = _ExceptionContextVisitor()
        visitor.visit(tree)
        rel = path.relative_to(context.repo_root)
        for lineno, name in visitor.findings:
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(
                    f"{rel}:{lineno}: {name}.exception() outside except block — use {name}.error()"
                )
    return DetectorResult(count=count, samples=samples)


# ── C40 ───────────────────────────────────────────────────────────────────────


def _collect_assert_linenos(tree: ast.AST) -> list[int]:
    """Return linenos of assert statements outside `if __debug__:` blocks."""

    def _is_debug_check(test: ast.expr) -> bool:
        if isinstance(test, ast.Name) and test.id == "__debug__":
            return True
        # `if __debug__ and ...:` — BoolOp where first value is __debug__
        if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
            first = test.values[0] if test.values else None
            if isinstance(first, ast.Name) and first.id == "__debug__":
                return True
        return False

    results: list[int] = []

    def _walk(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            if isinstance(stmt, ast.Assert):
                results.append(stmt.lineno)
            elif isinstance(stmt, ast.If) and _is_debug_check(stmt.test):
                # skip the body of `if __debug__:` blocks entirely
                _walk(stmt.orelse)
            elif isinstance(stmt, (ast.If, ast.While, ast.For)):
                _walk(stmt.body)
                _walk(stmt.orelse)
            elif isinstance(stmt, ast.With):
                _walk(stmt.body)
            elif isinstance(stmt, (ast.Try, ast.TryStar)):
                _walk(stmt.body)
                _walk(stmt.orelse)
                _walk(stmt.finalbody if hasattr(stmt, "finalbody") else [])
                for handler in getattr(stmt, "handlers", []):
                    _walk(handler.body)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                _walk(stmt.body)

    _walk(tree.body if isinstance(tree, ast.Module) else [])  # type: ignore[arg-type]
    return results


def detect_c40(context: AuditContext) -> DetectorResult:
    """Flag assert statements in production (non-test) code.

    Python's assert statement is silently disabled when the interpreter runs
    with the -O (optimize) flag.  Production invariants must use explicit
    conditionals with raise statements instead.

    Skips files under tests_root and asserts inside `if __debug__:` blocks
    (those are intentionally debug-only).  Respects C40 exclude_paths config.
    """
    samples: list[str] = []
    count = 0

    for path in _py_files(context, "C40"):
        # skip test files
        if context.tests_root and path.is_relative_to(context.tests_root):
            continue
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw, filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        src_lines = raw.splitlines()
        for lineno in _collect_assert_linenos(tree):
            line = src_lines[lineno - 1] if 0 < lineno <= len(src_lines) else ""
            if "noqa" in line:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{rel}:{lineno}: assert statement — use explicit raise instead")
    return DetectorResult(count=count, samples=samples)


# ── C41 ───────────────────────────────────────────────────────────────────────


class _JsonDumpsVisitor(ast.NodeVisitor):
    """Collect line numbers of json.dumps() calls missing ensure_ascii=False."""

    def __init__(self) -> None:
        self.hits: list[int] = []
        # Track whether `dumps` was imported directly from json
        self._dumps_imported = False

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module == "json":
            for alias in node.names:
                if alias.name == "dumps":
                    self._dumps_imported = True
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if self._is_json_dumps(node):
            if not self._has_ensure_ascii_false(node):
                self.hits.append(node.lineno)
        self.generic_visit(node)

    def _is_json_dumps(self, node: ast.Call) -> bool:
        func = node.func
        # json.dumps(...)
        if (
            isinstance(func, ast.Attribute)
            and func.attr == "dumps"
            and isinstance(func.value, ast.Name)
            and func.value.id == "json"
        ):
            return True
        # from json import dumps; dumps(...)
        if self._dumps_imported and isinstance(func, ast.Name) and func.id == "dumps":
            return True
        return False

    @staticmethod
    def _has_ensure_ascii_false(node: ast.Call) -> bool:
        """Return True if the call has any explicit ensure_ascii= kwarg.

        Flags only calls where ensure_ascii is entirely absent.  Explicit
        ``ensure_ascii=True`` is treated as a deliberate choice and is not
        flagged — only the accidental default (missing kwarg) is reported.
        """
        return any(kw.arg == "ensure_ascii" for kw in node.keywords)


def detect_c42(context: AuditContext) -> DetectorResult:
    """Flag ``warnings.warn()`` calls that omit the ``stacklevel=`` argument.

    Without ``stacklevel``, the warning points to the site inside the
    helper/wrapper that called ``warn()``, not to the external caller.
    This makes the warning misleading and hard to suppress with
    ``-W ignore::WarningCategory:module``.

    Add ``stacklevel=2`` when ``warn()`` is inside a one-level wrapper, or
    ``stacklevel=N`` for deeper nesting.  Use ``stacklevel=1`` (the default)
    only in top-level code where the call site IS the relevant location.

    When ``stacklevel=1`` is intentional, pass it explicitly to make the
    intent visible to readers.

    Suppress with ``# noqa: C42`` for sites where the default is deliberate.
    """
    samples: list[str] = []
    count = 0

    for path in _py_files(context, "C42"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw, filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        src_lines = raw.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_warn = (
                (isinstance(func, ast.Attribute) and func.attr == "warn"
                 and isinstance(func.value, ast.Name) and func.value.id == "warnings")
                or (isinstance(func, ast.Name) and func.id == "warn")
            )
            if not is_warn:
                continue
            has_stacklevel = any(kw.arg == "stacklevel" for kw in node.keywords)
            if has_stacklevel:
                continue
            line = src_lines[node.lineno - 1] if 0 < node.lineno <= len(src_lines) else ""
            if "noqa" in line:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{rel}:{node.lineno}: warnings.warn() without stacklevel=")
    return DetectorResult(count=count, samples=samples)


def detect_c43(context: AuditContext) -> DetectorResult:
    """Flag json.dump(obj, fp) calls that omit ensure_ascii=False.

    The file-write sibling of C41 (json.dumps).  Python's json.dump also
    defaults to ensure_ascii=True, silently escaping non-ASCII characters to
    \\uXXXX sequences in the written file.  On platforms that handle
    international content this produces unreadable files.

    Pass ensure_ascii=False alongside indent= for human-readable output, or
    suppress with ``# noqa: C43`` for ASCII-only write contexts.
    """
    samples: list[str] = []
    count = 0

    for path in _py_files(context, "C43"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw, filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        src_lines = raw.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            is_json_dump = (
                isinstance(func, ast.Attribute)
                and func.attr == "dump"
                and isinstance(func.value, ast.Name)
                and func.value.id == "json"
            )
            if not is_json_dump:
                continue
            if any(kw.arg == "ensure_ascii" for kw in node.keywords):
                continue
            line = src_lines[node.lineno - 1] if 0 < node.lineno <= len(src_lines) else ""
            if "noqa" in line:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(
                    f"{rel}:{node.lineno}: json.dump() without ensure_ascii=False"
                )
    return DetectorResult(count=count, samples=samples)


def detect_c41(context: AuditContext) -> DetectorResult:
    """Flag json.dumps() calls that omit ensure_ascii=False.

    Python's json.dumps defaults to ensure_ascii=True, which silently escapes
    all non-ASCII characters to \\uXXXX sequences.  On a platform that handles
    international content (scripts, titles, subtitles) this produces unreadable
    logs and inflated payloads.  Pass ensure_ascii=False unless the output is
    consumed by a system known to require ASCII-safe JSON.

    Suppress with ``# noqa: C41`` on the call line for hashing/fingerprinting
    contexts where ensure_ascii consistency is more important than readability.
    """
    samples: list[str] = []
    count = 0

    for path in _py_files(context, "C41"):
        try:
            raw = path.read_text(encoding="utf-8")
            tree = ast.parse(raw, filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue
        rel = path.relative_to(context.repo_root)
        src_lines = raw.splitlines()
        visitor = _JsonDumpsVisitor()
        visitor.visit(tree)
        for lineno in visitor.hits:
            line = src_lines[lineno - 1] if 0 < lineno <= len(src_lines) else ""
            if "noqa" in line:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(
                    f"{rel}:{lineno}: json.dumps() without ensure_ascii=False"
                )
    return DetectorResult(count=count, samples=samples)
