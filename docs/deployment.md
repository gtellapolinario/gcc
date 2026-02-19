# Deployment Notes

## Transport Strategy

- Default transport: `stdio` (recommended for local agent integrations).
- Remote/testing transport: `streamable-http` (already implemented behind runtime flags).

## Auth Strategy (v0.6)

`streamable-http` supports four runtime auth modes:

- `off`: no HTTP auth enforcement (default; recommended only for local/loopback usage).
- `token`: static bearer token validation.
- `trusted-proxy-header`: pre-shared header validation for reverse-proxy controlled networks.
- `oauth2`: bearer-token validation via OAuth2 introspection endpoint.

## Runtime Configuration

### CLI flags

```bash
gcc-mcp --transport stdio
gcc-mcp --transport streamable-http --host 127.0.0.1 --port 8000
gcc-mcp --transport streamable-http --host 0.0.0.0 --port 8000 --allow-public-http
gcc-mcp --transport streamable-http --host 127.0.0.1 --no-allow-public-http
gcc-mcp --rate-limit-per-minute 120 --audit-max-field-chars 4096
gcc-mcp --security-profile strict --audit-log-file .GCC/server-audit.jsonl --audit-signing-key-file .secrets/audit-signing.key --audit-signing-key-id key-2026-q1
gcc-mcp --transport streamable-http --auth-mode token --auth-token 'replace-me'
gcc-mcp --transport streamable-http --auth-mode trusted-proxy-header \
  --trusted-proxy-header x-gcc-proxy-auth \
  --trusted-proxy-value 'replace-me'
gcc-mcp --transport streamable-http --auth-mode oauth2 \
  --oauth2-introspection-url https://auth.example.com/oauth2/introspect \
  --oauth2-client-id gcc-mcp --oauth2-client-secret 'replace-me'
```

### Environment variables

- `GCC_MCP_TRANSPORT` (`stdio` or `streamable-http`)
- `GCC_MCP_HOST` (default `127.0.0.1`)
- `GCC_MCP_PORT` (default `8000`)
- `GCC_MCP_ALLOW_PUBLIC_HTTP` (`true`/`false`, default `false`)
- `GCC_MCP_AUDIT_LOG` (optional JSONL file path)
- `GCC_MCP_AUDIT_REDACT` (`true`/`false`, default `true`)
- `GCC_MCP_AUDIT_SIGNING_KEY` (optional key for signed audit events; requires audit log path)
- `GCC_MCP_AUDIT_SIGNING_KEY_FILE` (optional file containing signing key; mutually exclusive with direct key)
- `GCC_MCP_AUDIT_SIGNING_KEY_ID` (optional signing key identifier written to each signed event)
- `GCC_MCP_RATE_LIMIT_PER_MINUTE` (integer, default `0` disables limiter)
- `GCC_MCP_AUDIT_MAX_FIELD_CHARS` (integer, default `4000`; `0` disables truncation, otherwise minimum `64`)
- `GCC_MCP_SECURITY_PROFILE` (`baseline` default or `strict`)
- `GCC_MCP_AUTH_MODE` (`off`, `token`, `trusted-proxy-header`, `oauth2`)
- `GCC_MCP_AUTH_TOKEN` (required when `GCC_MCP_AUTH_MODE=token`)
- `GCC_MCP_TRUSTED_PROXY_HEADER` (required when `auth_mode=trusted-proxy-header`)
- `GCC_MCP_TRUSTED_PROXY_VALUE` (required when `auth_mode=trusted-proxy-header`)
- `GCC_MCP_OAUTH2_INTROSPECTION_URL` (required when `auth_mode=oauth2`)
- `GCC_MCP_OAUTH2_CLIENT_ID` + `GCC_MCP_OAUTH2_CLIENT_SECRET` (optional pair for introspection endpoint auth)
- `GCC_MCP_OAUTH2_INTROSPECTION_TIMEOUT_SECONDS` (default `5.0`)
- `GCC_MCP_AUTH_REQUIRED_SCOPES` (comma-separated scope list)
- `GCC_MCP_AUTH_ISSUER_URL` (optional; metadata URL override)
- `GCC_MCP_AUTH_RESOURCE_SERVER_URL` (optional; metadata URL override)

Example:

```bash
export GCC_MCP_TRANSPORT=streamable-http
export GCC_MCP_HOST=0.0.0.0
export GCC_MCP_PORT=8000
export GCC_MCP_ALLOW_PUBLIC_HTTP=true
export GCC_MCP_AUDIT_LOG=.GCC/server-audit.jsonl
export GCC_MCP_AUDIT_SIGNING_KEY_FILE=.secrets/audit-signing.key
export GCC_MCP_AUDIT_SIGNING_KEY_ID=key-2026-q1
export GCC_MCP_SECURITY_PROFILE=strict
export GCC_MCP_RATE_LIMIT_PER_MINUTE=120
export GCC_MCP_AUDIT_MAX_FIELD_CHARS=4096
export GCC_MCP_AUTH_MODE=token
export GCC_MCP_AUTH_TOKEN='replace-me'
export GCC_MCP_AUTH_REQUIRED_SCOPES='gcc.read,gcc.write'
gcc-mcp
```

Strict profile behavior for `streamable-http`:

- Set `auth-mode` to a non-`off` value.
- Configure `audit-log-file`.
- Provide signing key material via `GCC_MCP_AUDIT_SIGNING_KEY` or `audit-signing-key-file`.
- Avoid passing `--audit-signing-key` directly on the CLI in strict profile.

## Envoy Reverse-Proxy Profile

Use Envoy for TLS termination, IP allow-listing, and authentication/header controls.

Minimal trusted-header pattern:

```yaml
static_resources:
  listeners:
  - name: gcc_listener
    address:
      socket_address:
        address: 0.0.0.0
        port_value: 443
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager
          route_config:
            name: local_route
            virtual_hosts:
            - name: gcc
              domains: ["*"]
              routes:
              - match: { prefix: "/" }
                route:
                  cluster: gcc_mcp
                  request_headers_to_add:
                  - header:
                      key: x-gcc-proxy-auth
                      value: "${GCC_PROXY_SHARED_VALUE}"
          http_filters:
          - name: envoy.filters.http.router
  clusters:
  - name: gcc_mcp
    connect_timeout: 2s
    type: STRICT_DNS
    load_assignment:
      cluster_name: gcc_mcp
      endpoints:
      - lb_endpoints:
        - endpoint:
            address:
              socket_address:
                address: 127.0.0.1
                port_value: 8000
```

Run `gcc-mcp` behind this proxy with:

```bash
gcc-mcp \
  --transport streamable-http \
  --host 127.0.0.1 \
  --port 8000 \
  --auth-mode trusted-proxy-header \
  --trusted-proxy-header x-gcc-proxy-auth \
  --trusted-proxy-value "${GCC_PROXY_SHARED_VALUE}"
```

## Security Considerations

- `.GCC/` may contain sensitive context and should stay ignored by default.
- Branch access is constrained by strict branch-name validation and path containment under `.GCC/branches`.
- Non-loopback `streamable-http` host binding requires explicit opt-in (`--allow-public-http` or env).
- MCP tool invocations can be logged in structured JSONL with optional sensitive-field redaction.
- Signed audit metadata (HMAC + hash chain reference) is available with `audit-signing-key`.
- Signed events can include optional key identifiers (`audit-signing-key-id`) to support key rotation.
- Signed audit key can be sourced from file (`audit-signing-key-file`) to reduce secret exposure.
- Verification supports keyring files for rotated keys (`gcc-cli audit-verify --signing-keyring-file ...`).
- Optional per-process rate limiting can cap request volume in remote mode.
- Audit log string fields are truncated using configurable max length limits.
- `auth-mode` values other than `off` require streamable HTTP transport.
- `security-profile strict` enforces stronger remote controls for production-like deployments.
- Prefer secret env vars over CLI flags to avoid shell history leakage.
- For remote deployments, ensure network-level controls (firewalls, private network, Envoy policy).
- Use `redaction_mode=true` where broad context access is exposed.
- See `docs/security-model.md` for security assumptions and hardening controls.
- See `docs/audit-verification-runbook.md` for signed audit verification and rotation workflow.
