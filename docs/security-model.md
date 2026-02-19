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
- HTTP auth modes are validated and constrained (`off`, `token`, `trusted-proxy-header`, `oauth2`).
- Non-`off` auth modes require `streamable-http` transport.

6. HTTP auth controls:
- `token` mode enforces static bearer-token validation.
- `trusted-proxy-header` mode enforces a required pre-shared proxy header.
- `oauth2` mode validates bearer tokens via OAuth2 introspection.
- Auth metadata URLs/scopes are configurable for interoperability.

7. Structured audit logging:
- Optional JSONL audit logs can record tool invocations (`GCC_MCP_AUDIT_LOG`).
- Sensitive-looking fields are redacted by default (`GCC_MCP_AUDIT_REDACT=true`).
- Audit log fields are truncated with configurable limits (`GCC_MCP_AUDIT_MAX_FIELD_CHARS`).
- Optional HMAC signing adds per-event tamper-evident metadata (`GCC_MCP_AUDIT_SIGNING_KEY`).
- Optional key IDs (`GCC_MCP_AUDIT_SIGNING_KEY_ID`) support key-rotation-aware verification.

8. Operational guardrails:
- Optional per-process tool-call rate limiting (`GCC_MCP_RATE_LIMIT_PER_MINUTE`).
- Rate limiting returns explicit `RATE_LIMITED` error payloads with retry hints.

9. Security profile policy:
- Runtime security profile supports `baseline` (default) and `strict`.
- In `strict` with `streamable-http`: auth cannot be `off`, audit log must be enabled, and audit signing key must be configured.
- In `strict`, direct CLI key injection (`--audit-signing-key`) is rejected to reduce shell-history exposure risk.

10. CI security scanning:
- Bandit static analysis runs on Python source.
- pip-audit checks runtime dependency constraints from `pyproject.toml`.

## Deployment Notes

- `stdio` is the default transport for local integration.
- `streamable-http` is available for remote/test setups but must be protected by network controls (private network, firewall, Envoy policies, auth/rate limits).

## Residual Risks and Backlog

- Trusted proxy header mode depends on correct reverse-proxy behavior (strip/overwrite header from external clients).
- OAuth2 introspection availability/latency can affect request authorization outcomes.
- Redaction is heuristic and should not be treated as formal secret detection.
- Signed audits provide tamper evidence but not complete non-repudiation (key management remains critical).
- Legacy signed events without key IDs require explicit fallback key material during verification.
