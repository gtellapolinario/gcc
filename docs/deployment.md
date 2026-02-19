# Deployment Notes

## Transport Strategy

- Default transport: `stdio` (recommended for local agent integrations).
- Remote/testing transport: `streamable-http` (already implemented behind runtime flags).

## Runtime Configuration

### CLI flags

```bash
gcc-mcp --transport stdio
gcc-mcp --transport streamable-http --host 127.0.0.1 --port 8000
gcc-mcp --transport streamable-http --host 0.0.0.0 --port 8000 --allow-public-http
gcc-mcp --transport streamable-http --host 127.0.0.1 --no-allow-public-http
gcc-mcp --rate-limit-per-minute 120 --audit-max-field-chars 4096
```

### Environment variables

- `GCC_MCP_TRANSPORT` (`stdio` or `streamable-http`)
- `GCC_MCP_HOST` (default `127.0.0.1`)
- `GCC_MCP_PORT` (default `8000`)
- `GCC_MCP_ALLOW_PUBLIC_HTTP` (`true`/`false`, default `false`)
- `GCC_MCP_AUDIT_LOG` (optional JSONL file path)
- `GCC_MCP_AUDIT_REDACT` (`true`/`false`, default `true`)
- `GCC_MCP_RATE_LIMIT_PER_MINUTE` (integer, default `0` disables limiter)
- `GCC_MCP_AUDIT_MAX_FIELD_CHARS` (integer, default `4000`; `0` disables truncation, otherwise minimum `64`)

Example:

```bash
export GCC_MCP_TRANSPORT=streamable-http
export GCC_MCP_HOST=0.0.0.0
export GCC_MCP_PORT=8000
export GCC_MCP_ALLOW_PUBLIC_HTTP=true
export GCC_MCP_AUDIT_LOG=.GCC/server-audit.jsonl
export GCC_MCP_RATE_LIMIT_PER_MINUTE=120
export GCC_MCP_AUDIT_MAX_FIELD_CHARS=4096
gcc-mcp
```

## Security Considerations

- `.GCC/` may contain sensitive context and should stay ignored by default.
- Branch access is constrained by strict branch-name validation and path containment under `.GCC/branches`.
- Non-loopback `streamable-http` host binding requires explicit opt-in (`--allow-public-http` or env).
- MCP tool invocations can be logged in structured JSONL with optional sensitive-field redaction.
- Optional per-process rate limiting can cap request volume in remote mode.
- Audit log string fields are truncated using configurable max length limits.
- For remote deployments, ensure network-level controls (firewalls, private network, auth proxy).
- Use `redaction_mode=true` where broad context access is exposed.
- See `docs/security-model.md` for security assumptions and hardening controls.

## Production Hardening Backlog

- Introduce an authn/authz layer for remote endpoints.
- Expand reverse-proxy deployment guidance for production topologies.
