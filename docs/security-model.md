# GCC MCP Security Model

## Scope

This document defines security assumptions and controls for the local-first GCC MCP server.

Primary assets:

- `.GCC/` context content (`main.md`, `commit.md`, `log.md`, `metadata.yaml`, config)
- branch and history integrity
- runtime transport configuration

Primary trust boundaries:

- user-provided MCP/CLI inputs
- repository filesystem state
- environment variables used at server startup

## Security Controls

1. Sensitive-context default:
- `.GCC/` is ignored by Git by default (`git_context_policy=ignore`).
- Tracking `.GCC/` requires explicit informed acknowledgement (`acknowledge_sensitive_data_risk=true`).

2. Branch/path safety:
- Branch names are constrained to `^[a-z0-9-]+$`.
- Branch lookups use centralized validation in engine path helpers.
- Branch paths are resolved and constrained under `.GCC/branches` to prevent traversal.

3. Input validation and error contracts:
- Pydantic request models enforce constraints for branch names and payload shape.
- Errors return stable codes and actionable suggestions.

4. Context redaction:
- `redaction_mode=true` or `redact_sensitive=true` applies conservative redaction for common secret-like patterns.

5. Runtime startup validation:
- `GCC_MCP_TRANSPORT` only permits `stdio` or `streamable-http`.
- `GCC_MCP_PORT` must be integer in range `1..65535`.
- Non-loopback streamable HTTP bindings require explicit opt-in (`GCC_MCP_ALLOW_PUBLIC_HTTP=true`).

6. Structured audit logging:
- Optional JSONL audit logs can record tool invocations (`GCC_MCP_AUDIT_LOG`).
- Sensitive-looking fields are redacted by default (`GCC_MCP_AUDIT_REDACT=true`).

7. CI security scanning:
- Bandit static analysis runs on Python source.
- pip-audit checks runtime dependency constraints from `pyproject.toml`.

## Deployment Notes

- `stdio` is the default transport for local integration.
- `streamable-http` is available for remote/test setups but must be protected by network controls (private network, firewall, proxy auth/rate limits).

## Residual Risks and Backlog

- Remote mode currently relies on external authn/authz controls.
- Redaction is heuristic and should not be treated as formal secret detection.
- Add optional signed audit trails and stricter policy enforcement for production remote deployments.
