## Summary

<!-- One or two sentences describing what this PR does and why. -->

## Changes

<!-- Bullet list of what changed. -->

-

## Scope Checklist

- [ ] No consumer-specific paths, log formats, or state shapes hardcoded into the library
- [ ] No new external-service adapters added (Plane, GitHub, etc. stay near their primary consumer)
- [ ] No aggregation / dashboard infrastructure introduced
- [ ] `AuditResult.schema_version` is unchanged, OR bumped with a migration note

## Testing

- [ ] Tests pass: `.venv/bin/python -m pytest tests/ -v`
- [ ] Linter passes: `ruff check src/`
- [ ] New detectors include fixture-based tests
- [ ] New CLI behavior covered by integration tests

## Documentation

- [ ] `README.md` updated if CLI surface or `.custodian/config.yaml` keys changed
- [ ] `CONTRIBUTING.md` updated if project structure changed

## Related Issues

<!-- Closes #N or References #N -->

## Notes for Reviewer

<!-- Anything non-obvious: edge cases, trade-offs, plugin-loader behavior, follow-up items. -->
