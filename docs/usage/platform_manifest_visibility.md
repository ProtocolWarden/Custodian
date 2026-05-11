# PlatformManifest Visibility Checks

Custodian can validate public PlatformManifest projections against the
visibility policy declared by PlatformManifest.

PlatformManifest owns the allowed visibility model. Custodian detects
violations of that model.

## Input

Generate a public projection from PlatformManifest:

```bash
platform-manifest project-public \
  --project topology/project_manifest.yaml \
  --local topology/local_manifest.yaml \
  --output public_manifest.json
```

Emit the policy descriptor Custodian can mirror in config:

```bash
platform-manifest custodian-policy
```

## Config

Configure the public manifest paths and any private project terms:

```yaml
repo_key: my-repo
audit:
  platform_manifest:
    detector_contributor: platform_manifest.custodian_native:build_custodian_detectors
    public_manifest_paths:
      - public_manifest.json
    private_terms:
      - PrivateImpl
      - InternalDeploymentName
```

The contributor target is owned by `PlatformManifest`. Custodian loads it and
does not own the PMV detector implementation.

`PMV1` checks for forbidden public fields, private-looking URLs, internal
paths, and configured private terms.

`PMV2` checks that public relationship edges point only to public nodes
declared in the public manifest.

## Expected Flow

1. PlatformManifest projects private/effective input into a public manifest.
2. Custodian scans the generated public manifest.
3. Any PMV finding fails publication or release according to the calling CI
   policy.

Unknown visibility fails closed in PlatformManifest. Custodian treats
non-public or unknown edge endpoints as PMV2 violations in public output.
