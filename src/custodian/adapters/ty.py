# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 ProtocolWarden
"""ty adapter — runs `ty check --output-format concise` and maps diagnostics to Findings."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

from custodian.adapters.base import ToolAdapter, find_tool
from custodian.core.finding import HIGH, LOW, MEDIUM, Finding

# ty concise output: path:line:col: level[rule-id] message
_LINE_RE = re.compile(
    r"^(?P<path>.+):(?P<line>\d+):\d+:\s+(?P<level>\w+)\[(?P<rule>[^\]]+)\]\s+(?P<message>.+)$"
)

_TY_SEVERITY: dict[str, str] = {
    "error":   HIGH,
    "warning": MEDIUM,
    "info":    LOW,
}


def _ty_severity(level: str) -> str:
    return _TY_SEVERITY.get(level.lower(), MEDIUM)


class TyAdapter(ToolAdapter):
    """Runs ty type-checker and maps diagnostics to Finding objects.

    ty is optional — when not installed ``is_available`` returns False.

    ``docker=True`` runs ty inside a container instead of against a host
    binary. A type checker is only as good as the environment it resolves
    imports in, and for a containerized repo that environment does not exist
    on the host: a venv built ``--system-site-packages`` against the image's
    interpreter leaves the dependencies at ``/usr/local/lib/...`` *inside the
    image*, and ``pyvenv.cfg`` points ``home`` at a path the host does not
    have.

    That is not a cosmetic difference. An import ty cannot resolve infers as
    ``Unknown``, which both invents attribute errors and suppresses real ones,
    so a host run is wrong in both directions rather than merely noisy —
    measured on one repo as 61 false positives *and* 22 missed errors against
    the same tree. Docker mode is how a host-unrunnable checker still produces
    sound findings, the same reason the semgrep adapter has it.
    """

    name = "ty"

    #: Default location the repo is mounted at inside the container. Repos
    #: whose venv hardcodes an absolute prefix (``/work/.venv/bin/python``)
    #: must override this to match, or the interpreter will not be found.
    _MOUNT = "/src"

    def __init__(
        self,
        docker: bool = False,
        image: str = "python:3.12-slim",
        mount: str = _MOUNT,
        command: str = "ty",
        timeout: int = 120,
    ) -> None:
        self._docker = docker
        self._image = image
        self._mount = mount or self._MOUNT
        self._command = command or "ty"
        self._timeout = timeout

    def is_available(self) -> bool:
        if self._docker:
            return find_tool("docker") is not None
        return find_tool("ty") is not None

    def _docker_cmd(self, repo_path: Path, src_root: Path) -> list[str]:
        """Build a ``docker run`` invocation equivalent to the native call.

        The target is passed **relative to the mount**. ty echoes back the
        form it was given, so a relative target yields repo-relative
        diagnostic paths — which are already correct on the host side and need
        no translation out of container space.

        Raises:
            ValueError: if the source root lies outside the repo, since only
                the repo is mounted.
        """
        repo_root = repo_path.resolve()
        try:
            rel_src = src_root.resolve().relative_to(repo_root).as_posix()
        except ValueError:
            raise ValueError(
                f"ty docker mode cannot reach a path outside the repo: {src_root} "
                f"(only {repo_root} is mounted). Move the source root under the "
                "repo, or set docker: false for this adapter."
            ) from None

        return [
            find_tool("docker") or "docker", "run", "--rm",
            "-v", f"{repo_root.as_posix()}:{self._mount}",
            "-w", self._mount,
            "--entrypoint", self._command,
            self._image,
            "check", "--output-format", "concise", rel_src or ".",
        ]

    def run(self, repo_path: Path, config: dict) -> list[Finding]:
        src_root = repo_path / config.get("src_root", "src")
        if not src_root.exists():
            src_root = repo_path

        if self._docker:
            try:
                cmd = self._docker_cmd(repo_path, src_root)
            except ValueError as exc:
                return [Finding(
                    tool=self.name,
                    rule="TOOL_ERROR",
                    severity=LOW,
                    path=None,
                    line=None,
                    message=str(exc),
                )]
        else:
            cmd = [find_tool("ty") or "ty", "check", "--output-format", "concise", str(src_root)]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=repo_path,
                timeout=self._timeout,
                # Parse the output regardless of exit status; a non-zero
                # code is handled per-adapter, not by raising.
                check=False,
            )
        except FileNotFoundError:
            return [Finding.tool_unavailable(self.name)]
        except subprocess.TimeoutExpired:
            # Previously uncaught, which took the whole audit down instead of
            # reporting one dead tool. ty itself is fast; a cold `docker run`
            # that has to pull an image is not.
            return [Finding(
                tool=self.name,
                rule="TOOL_ERROR",
                severity=LOW,
                path=None,
                line=None,
                message=f"ty timed out after {self._timeout}s",
            )]

        findings: list[Finding] = []
        # ty writes diagnostics to stderr in concise mode
        output = proc.stderr or proc.stdout
        for raw_line in output.splitlines():
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            m = _LINE_RE.match(raw_line)
            if not m:
                continue
            path_str = m.group("path")
            try:
                # as_posix(), not str(): docker mode reports `src/foo.py` while
                # a native Windows run reports `src\foo.py` for the same file.
                # Findings are keyed and exempted by path, so the same file
                # must not have two spellings depending on where ty ran.
                rel = Path(path_str).relative_to(repo_path).as_posix()
            except ValueError:
                # Already repo-relative (docker mode always is), or outside
                # the repo — either way, report the path as ty gave it.
                rel = path_str
            findings.append(Finding(
                tool=self.name,
                rule=m.group("rule"),
                severity=_ty_severity(m.group("level")),
                path=rel,
                line=int(m.group("line")),
                message=m.group("message").strip(),
            ))

        return findings
