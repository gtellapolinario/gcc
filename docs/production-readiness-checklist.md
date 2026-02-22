# Production Readiness Checklist

Use this checklist before promoting `gcc-mcp` into a production or production-like environment.

## 1. Source and Release Hygiene

- Pull request is merged to `main` and linked to a milestone/issue.
- CI is green on `main`:
  - test matrix (`ruff`, `pytest`, `py_compile`)
  - security scans (`bandit`, `pip-audit`)
  - package gate (`python -m build`, `twine check`, wheel install smoke)
- Release notes/changelog entry is prepared for the deployment window.
- Deployment owner and rollback owner are explicitly assigned.

## 2. Artifact Integrity

- Wheel and sdist artifacts build without warnings.
- `twine check` passes for all `dist/*` artifacts.
- Fresh-venv smoke succeeds:
  - `gcc-cli --help`
  - `gcc-mcp --help`
  - `python -m gcc_mcp --help`
- Artifact SHA256 hashes are recorded in deployment notes.

## 3. Runtime Security Baseline

- Transport mode is explicit (`stdio` for local, `streamable-http` for remote).
- Non-loopback streamable HTTP bindings are intentional and documented.
- `auth-mode` is configured for remote exposure:
  - `token`, `trusted-proxy-header`, or `oauth2`
  - never `off` for internet-reachable deployment
- For strict profile remote deployment:
  - `security-profile=strict`
  - `audit-log-file` is configured
  - audit signing key material is configured (prefer `--audit-signing-key-file` or env var)
- If containerized MCP receives host-side repo paths, `GCC_MCP_PATH_MAP` and
  `GCC_MCP_ALLOWED_ROOTS` are configured and validated.
- Secrets are sourced from files or environment variables, not shell history.

## 4. Audit and Observability

- Audit log path exists and write permissions are validated.
- Audit redaction mode is explicitly set for the environment.
- Audit signing key id is set when key rotation is in use.
- `gcc-cli audit-verify` is included in post-deploy validation for signed logs.
- Operational logs include enough context to trace failed requests and auth failures.

## 5. Deployment and Network Controls

- Reverse proxy policy is in place for streamable HTTP deployments (Envoy profile).
- TLS termination and network ACL/firewall rules are applied.
- Rate limiting (`rate-limit-per-minute`) is set to an environment-appropriate value.
- Health/availability check path and alerting destination are documented.
- On-call escalation path is documented for deployment window.

## 6. Rollout and Rollback

- Rollout strategy is defined (`all-at-once` or phased).
- Rollback command/config is pre-tested and documented.
- Previous known-good artifact version is available for immediate rollback.
- Rollback trigger conditions are agreed before deployment starts.
- Post-deploy verification includes:
  - MCP tool call smoke flow (`gcc_init` -> `gcc_commit` -> `gcc_status`)
  - auth check for configured auth mode
  - audit log verification sample
- Pre-deploy preflight is executed at least once:
  - `gcc-mcp --check-config`
  - `gcc-mcp --print-effective-config` (sanity-check effective settings)
