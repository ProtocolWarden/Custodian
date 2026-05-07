# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| `main`  | ✅ Yes     |

Only the current `main` branch receives security fixes.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report security issues privately by emailing **coding.projects.1642@proton.me**.

Include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations (optional)

You will receive an acknowledgment within 72 hours. We aim to release a fix within 14 days of a confirmed report, depending on severity and complexity.

## Scope

Custodian is a library + CLI loaded into consumer repositories at audit time. The primary security surface is:

- **Arbitrary module import** via `.custodian/config.yaml` plugin entries — Custodian imports any module path the config declares
- **Path traversal** via `--repo` / `repo_root` config values used to resolve scan paths
- **Code execution in detector functions** — every plugin runs in the audit process; a malicious plugin can do anything that process can
- **JSON injection** into the `AuditResult` payload via untrusted file content read by detectors

## Out of Scope

- Vulnerabilities in consumer-supplied plugins (those are owned by the consumer repo)
- Issues requiring physical access to the host machine
- Denial-of-service via huge repository scans (resource limits are a configuration concern)
- Vulnerabilities in upstream tools the consumer integrates (Plane, GitHub, etc.)

## Hardening Guidance for Consumers

- Review every `.custodian/config.yaml` plugin entry before adding it — they execute arbitrary Python
- Run `custodian-audit` with the same trust level as `pytest` / `ruff` (i.e. dev/CI environments, not production)
- Pin Custodian to a specific version in CI to avoid silent supply-chain surprises
