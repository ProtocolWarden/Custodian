<!-- Leaf doc: CI workflow + custodian-config conventions. -->

## Inject

- **Boundary artifact in CI = the canonical B64 step.** A *path* secret cannot
  resolve on a runner. Decode the `REPOGRAPH_BOUNDARY_ARTIFACT_B64` *content*
  secret to `mktemp "${RUNNER_TEMP:-/tmp}/repograph-boundary-XXXXXX.json"`,
  append `REPOGRAPH_BOUNDARY_ARTIFACT_FILE=$dest` to `$GITHUB_ENV`, and
  `exit 0` gracefully when the secret is absent (B2 fails closed downstream).
  Never reconstruct the artifact at a baked private repo-instance path. Copy
  the step from this repo's `custodian-audit.yml` — don't re-derive it.
- **`git config core.hooksPath .hooks` before `custodian-multi`** — the config
  flags an unset hooksPath (W2) otherwise; wire it like a developer checkout.
- **venv-guard:** several fleet repos' `tests/conftest.py` hard-exit unless
  `sys.prefix` is `./.venv`. Test jobs must `python -m venv .venv &&
  .venv/bin/pip install -e ".[dev]" && .venv/bin/pytest` — never bare pytest
  against system Python, and never bypass the guard.
- **CI installs `custodian@main` — fleet-coupled.** A new detector that ships
  default-ON fails every public repo's audit at once. New detectors land
  dormant behind an opt-in `audit.` flag (see the `reconcile_enforce`
  incident); repos opt in only after they're clean.
- **Workflow naming is semantic:** `custodian-audit.yml` runs the custodian
  audit; lint/test belongs in `ci.yml`. A misnamed workflow hides enforcement
  gaps (TeamExecutor had a "custodian-audit" that ran ruff/pytest).
- **Custom `audit.` keys need declaring.** `custodian-doctor --strict` rejects
  keys outside its known set — declare extras in `audit.plugin_audit_keys`.
- **No baked artifact paths in `.custodian/config.yaml`.** Set
  `privacy.require_boundary_artifact: true` and let hook/CI export the env by
  role; absent env ⇒ B2 fails closed, as required. Verify both ways when
  touching this (with artifact → clean; without → exit 1).
- **K2 and DC7 have no `exclude_paths`** — use `audit.known_values` and
  `doc_conventions.exclude_path_patterns` instead.

## Reference

This repo's `custodian-audit.yml` carries the B64 step; the CANONICAL copy of
this doc lives in PlatformManifest (`docs/inject/ci-conventions.md`) — sync
wording changes from there.
History: PlatformManifest `.console/log.md` 2026-06-04 entries (FLEET GREEN
root causes, R2-in-CI fleet rollout) record how each convention was re-derived
the hard way.
