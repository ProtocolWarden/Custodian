# Semantic Federation

`Custodian`'s semantic federation workflow keeps the cross-repo governance gate
operational after the initial RepoGraph hardening pass.

## What it verifies

- RepoGraph importability
- schema compatibility
- projection profile safety
- boundary artifact validity
- ownership drift
- duplicate graph vocabulary
- legacy path regression

## Local execution

Run the full federated gate against a workspace root and a materialized boundary
artifact file:

```bash
custodian-repograph-governance-gate \
  --repo-root /path/to/workspace \
  --boundary-artifact /path/to/boundary_disclosure_artifact.json \
  --json-out /tmp/repograph-governance.json \
  --summary-out /tmp/repograph-governance.md
```

The boundary artifact must already exist. `Custodian` does not generate it.

## CI execution

The `semantic-federation.yml` workflow in `Custodian` materializes the boundary
artifact into a temporary file, clones the public repo set, and runs the same
gate across the workspace.

If artifact materialization fails, the workflow fails before the gate runs.

## Inputs

- a materialized RepoGraph boundary artifact file
- a workspace root containing the public repos under test

## Failure interpretation

- missing boundary artifact: operator or CI setup error
- malformed artifact: private-manifest repo export or transport error
- ownership drift / duplicate vocabulary: RepoGraph or consumer regression
- legacy path regression: a forbidden compatibility path reappeared

The workflow is fail-closed by design. It is operational glue around the same
enforcement boundary, not a second enforcement layer.

## Policy split

- `custodian.policy.public_surface_catalog` governs which repo pages may appear
  in the browseable public repository catalog.
- Privacy and boundary detectors remain responsible for leakage, forbidden
  names, and artifact validation.
- Architecture docs may still mention the private-manifest repo; the catalog policy only
  limits first-class public repo pages.
- The public site exposes current pages only.
