# gcc-mcp

Python MCP server for the **Git Context Controller (GCC)**.  
It implements Git-inspired context operations for AI-agent workflows:

- `gcc_init`
- `gcc_commit`
- `gcc_branch`
- `gcc_merge`
- `gcc_context`
- `gcc_status`
- `gcc_log`
- `gcc_list`
- `gcc_checkout`
- `gcc_delete`
- `gcc_config_get`
- `gcc_config_set`
- `gcc_config_list`

## Quick Start

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
pytest
```

Run the MCP server (stdio transport):

```bash
gcc-mcp
```

Run with streamable HTTP (planned for remote deployment, not default for v0.1):

```bash
gcc-mcp --transport streamable-http --host 127.0.0.1 --port 8000
```

Explicit public binding (non-loopback host) requires opt-in:

```bash
gcc-mcp --transport streamable-http --host 0.0.0.0 --port 8000 --allow-public-http
```

If `GCC_MCP_ALLOW_PUBLIC_HTTP=true` is set in environment, you can still disable it per run:

```bash
gcc-mcp --transport streamable-http --host 127.0.0.1 --no-allow-public-http
```

Or (module mode):

```bash
python -m gcc_mcp
```

Run CLI (parity with MCP tools):

```bash
gcc-cli --help
```

Implemented CLI commands:

- `init`
- `commit`
- `branch`
- `merge`
- `context`
- `status`
- `config`
- `log`
- `list`
- `checkout`
- `delete`
- `audit-verify`

Example init with secure default (`.GCC` ignored by git):

```bash
gcc-cli init \
  --directory . \
  --name "My Project" \
  --description "Context-tracked implementation"
```

Example init with explicit opt-in to track `.GCC` in git:

```bash
gcc-cli init \
  --directory . \
  --name "My Project" \
  --git-context-policy track \
  --ack-sensitive-context-risk
```

## Security Note

`.GCC/` can contain sensitive context (reasoning traces, architecture notes, and potentially
security-relevant details).  
Default behavior is `git_context_policy=ignore`, which adds `.GCC/` to `.gitignore`.  
Tracking `.GCC/` in git requires explicit acknowledgement.

Context retrieval supports optional conservative redaction:

```bash
gcc-cli context --redact-sensitive --level detailed
```

You can persist this behavior:

```bash
gcc-cli config redaction_mode true
```

## Streamable HTTP Mode

`gcc-mcp` remains stdio-first for local workflows.  
For remote-style testing/deployment, streamable HTTP mode is available:

```bash
gcc-mcp --transport streamable-http --host 127.0.0.1 --port 8000
```

Supported HTTP auth modes:

- `off` (default)
- `token`
- `trusted-proxy-header`
- `oauth2`

Examples:

```bash
# static bearer token
gcc-mcp --transport streamable-http --auth-mode token --auth-token 'replace-me'

# trusted reverse-proxy header (Envoy profile)
gcc-mcp --transport streamable-http --auth-mode trusted-proxy-header \
  --trusted-proxy-header x-gcc-proxy-auth \
  --trusted-proxy-value 'replace-me'

# OAuth2 introspection
gcc-mcp --transport streamable-http --auth-mode oauth2 \
  --oauth2-introspection-url https://auth.example.com/oauth2/introspect \
  --oauth2-client-id gcc-mcp \
  --oauth2-client-secret 'replace-me'

# strict production-oriented profile
gcc-mcp --transport streamable-http \
  --security-profile strict \
  --auth-mode token \
  --auth-token 'replace-me' \
  --audit-log-file .GCC/server-audit.jsonl \
  --audit-signing-key-file .secrets/audit-signing.key \
  --audit-signing-key-id key-2026-q1
```

Environment variable equivalents:

- `GCC_MCP_TRANSPORT` (`stdio` or `streamable-http`)
- `GCC_MCP_HOST`
- `GCC_MCP_PORT`
- `GCC_MCP_ALLOW_PUBLIC_HTTP` (`true/false`, default `false`)
- `GCC_MCP_AUDIT_LOG` (optional JSONL audit log file path)
- `GCC_MCP_AUDIT_REDACT` (`true/false`, default `true`)
- `GCC_MCP_AUDIT_SIGNING_KEY` (optional key for signed audit events; requires audit log)
- `GCC_MCP_AUDIT_SIGNING_KEY_FILE` (optional file source for audit signing key)
- `GCC_MCP_AUDIT_SIGNING_KEY_ID` (optional signing key identifier written to signed events)
- `GCC_MCP_RATE_LIMIT_PER_MINUTE` (integer, default `0` = disabled)
- `GCC_MCP_AUDIT_MAX_FIELD_CHARS` (integer, default `4000`; `0` disables truncation)
- `GCC_MCP_SECURITY_PROFILE` (`baseline` default or `strict`)
- `GCC_MCP_AUTH_MODE` (`off`, `token`, `trusted-proxy-header`, `oauth2`)
- `GCC_MCP_AUTH_TOKEN`
- `GCC_MCP_TRUSTED_PROXY_HEADER`
- `GCC_MCP_TRUSTED_PROXY_VALUE`
- `GCC_MCP_OAUTH2_INTROSPECTION_URL`
- `GCC_MCP_OAUTH2_CLIENT_ID`
- `GCC_MCP_OAUTH2_CLIENT_SECRET`
- `GCC_MCP_OAUTH2_INTROSPECTION_TIMEOUT_SECONDS` (default `5.0`)
- `GCC_MCP_AUTH_REQUIRED_SCOPES` (comma-separated)
- `GCC_MCP_AUTH_ISSUER_URL` (optional metadata override)
- `GCC_MCP_AUTH_RESOURCE_SERVER_URL` (optional metadata override)

For production remote deployments, place `gcc-mcp` behind Envoy and enforce TLS, policy,
and network controls at the proxy layer (`docs/deployment.md`).

When `security-profile` is `strict` and transport is `streamable-http`, `gcc-mcp` enforces:
- auth mode cannot be `off`
- audit log must be configured
- audit signing key material must be configured (env var or key file)
- direct `--audit-signing-key` usage is rejected

Validate runtime settings without starting server transport:

```bash
gcc-mcp --check-config
```

Print sanitized effective runtime configuration for deployment diagnostics:

```bash
gcc-mcp \
  --transport streamable-http \
  --auth-mode token \
  --auth-token 'replace-me' \
  --audit-log-file .GCC/server-audit.jsonl \
  --print-effective-config
```

Optional audit log via CLI flag:

```bash
gcc-mcp --audit-log-file .GCC/server-audit.jsonl --audit-redact-sensitive
```

Optional runtime guardrails:

```bash
gcc-mcp \
  --rate-limit-per-minute 120 \
  --audit-max-field-chars 4096
```

Verify signed audit log integrity:

```bash
gcc-cli audit-verify \
  --log-file .GCC/server-audit.jsonl \
  --signing-key-file .secrets/audit-signing.key
```

Verify rotated-key logs in one pass:

```bash
gcc-cli audit-verify \
  --log-file .GCC/server-audit.jsonl \
  --signing-keyring-file .secrets/audit-signing-keyring.json
```

## CI Quality Gates

GitHub Actions workflow: `.github/workflows/ci.yml`

Checks:

- `python -m ruff check src tests`
- `python -m pytest -q`
- `python -m py_compile src/gcc_mcp/*.py`
- `bandit -r src/gcc_mcp -q`
- `pip-audit -r .audit-requirements.txt --progress-spinner off`
- `python -m build`
- `twine check dist/*`
- wheel-install smoke (`gcc-cli --help`, `gcc-mcp --help`, `python -m gcc_mcp --help`)

Release automation workflow: `.github/workflows/release.yml`

- Auto trigger: merged PRs to `main` with title prefix `release:`
- Action: creates semver tag from `pyproject.toml` and publishes GitHub Release using `CHANGELOG.md`
- Manual fallback: `workflow_dispatch` with optional `target_sha` input for backfill releases

Security reference:

- `docs/security-model.md`
- `docs/audit-verification-runbook.md`
- `docs/production-readiness-checklist.md`

## Inspector & Evaluations

- MCP Inspector runbook: `docs/mcp-inspector-runbook.md`
- Evaluation pack: `eval/gcc_mcp_evaluation.xml`

## Project Layout

```text
src/gcc_mcp/
  cli.py           # gcc-cli command
  engine.py        # core GCC operations
  file_manager.py  # filesystem and YAML IO
  models.py        # pydantic request/response contracts
  server.py        # FastMCP tools
tests/
  test_cli.py
  test_engine.py
```
