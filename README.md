# gcc-mcp

![Version: 0.1.1](https://img.shields.io/badge/Version-0.1.1-informational?style=flat-square)
![Python: >=3.10](https://img.shields.io/badge/Python-%3E%3D3.10-informational?style=flat-square)
![Transport: stdio+streamable-http](https://img.shields.io/badge/Transport-stdio%20%2B%20streamable--http-informational?style=flat-square)

Python MCP server and CLI for the **Git Context Controller (GCC)**.  
It provides git-inspired context operations for AI agent workflows, with security-first defaults
and production-ready remote deployment controls.

**Homepage:** <https://github.com/CodeAdminDe/gcc>

## Maintainers

| Name | Contact | Profile |
| ---- | ------- | ------- |
| Frederic Roggon | <frederic.roggon@codeadmin.de> | <https://github.com/CodeAdminDe> |

## TL;DR

You do not want to read through all docs right now? This is the fast path:

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
gcc-mcp
```

Run CLI parity commands:

```bash
gcc-cli --help
```

Run remote-compatible mode with strict profile:

```bash
gcc-mcp \
  --transport streamable-http \
  --security-profile strict \
  --auth-mode token \
  --auth-token 'replace-me' \
  --audit-log-file .GCC/server-audit.jsonl \
  --audit-signing-key-file .secrets/audit-signing.key
```

_**Note**: For remote deployments, place `gcc-mcp` behind Envoy and enforce TLS plus network policy._

## Installation

### Local development install

```bash
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Validate local setup

```bash
python -m ruff check src tests
python -m pytest -q
```

### Entry points

```bash
gcc-mcp --help
gcc-cli --help
python -m gcc_mcp --help
```

## Quick Start

### 1. Initialize a project context store

Secure default (`.GCC/` ignored by git):

```bash
gcc-cli init \
  --directory . \
  --name "My Project" \
  --description "Context-tracked implementation"
```

Explicit opt-in to track `.GCC/` in git:

```bash
gcc-cli init \
  --directory . \
  --name "My Project" \
  --git-context-policy track \
  --ack-sensitive-context-risk
```

### 2. Run MCP server (default stdio transport)

```bash
gcc-mcp
```

### 3. Use CLI parity commands

```bash
gcc-cli commit --message "Implement feature X"
gcc-cli context --level detailed
gcc-cli status
```

## Implemented MCP Tools

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

## Implemented CLI Commands

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

## Transport, Auth, and Security Profiles

`stdio` is the default and recommended mode for local MCP integrations.
`streamable-http` is available for remote-style deployment and testing.

### Auth modes (`streamable-http`)

- `off` (default; local/loopback use only)
- `token`
- `trusted-proxy-header`
- `oauth2` (token introspection)

Examples:

```bash
# token mode
gcc-mcp --transport streamable-http --auth-mode token --auth-token 'replace-me'

# trusted reverse-proxy header mode
gcc-mcp --transport streamable-http \
  --auth-mode trusted-proxy-header \
  --trusted-proxy-header x-gcc-proxy-auth \
  --trusted-proxy-value 'replace-me'

# oauth2 introspection mode
gcc-mcp --transport streamable-http \
  --auth-mode oauth2 \
  --oauth2-introspection-url https://auth.example.com/oauth2/introspect \
  --oauth2-client-id gcc-mcp \
  --oauth2-client-secret 'replace-me'
```

### Strict profile behavior (`security-profile strict` + `streamable-http`)

- `auth-mode` must be non-`off`
- `audit-log-file` must be set
- signing key material must be present (env var or key file)
- direct `--audit-signing-key` CLI usage is rejected

### Public bind safety switch

Explicit non-loopback bind requires opt-in:

```bash
gcc-mcp --transport streamable-http --host 0.0.0.0 --port 8000 --allow-public-http
```

## Security Notes

- `.GCC/` may contain sensitive context and is ignored by default (`git_context_policy=ignore`).
- Tracking `.GCC/` in git requires explicit acknowledgement because sensitive details can leak.
- Signed audit logs support integrity checks and key rotation.
- Optional redaction and audit truncation controls reduce accidental data exposure.
- Prefer secret environment variables over CLI flags to avoid shell history leakage.

Redaction examples:

```bash
gcc-cli context --redact-sensitive --level detailed
gcc-cli config redaction_mode true
```

Signed audit verification examples:

```bash
gcc-cli audit-verify \
  --log-file .GCC/server-audit.jsonl \
  --signing-key-file .secrets/audit-signing.key

gcc-cli audit-verify \
  --log-file .GCC/server-audit.jsonl \
  --signing-keyring-file .secrets/audit-signing-keyring.json
```

## Configuration and Operations

Useful runtime checks:

```bash
gcc-mcp --check-config
gcc-mcp --print-effective-config
```

Core environment variables:

- `GCC_MCP_TRANSPORT` (`stdio` or `streamable-http`)
- `GCC_MCP_SECURITY_PROFILE` (`baseline` or `strict`)
- `GCC_MCP_AUTH_MODE` (`off`, `token`, `trusted-proxy-header`, `oauth2`)
- `GCC_MCP_AUDIT_LOG`
- `GCC_MCP_AUDIT_SIGNING_KEY` or `GCC_MCP_AUDIT_SIGNING_KEY_FILE`
- `GCC_MCP_RATE_LIMIT_PER_MINUTE`
- `GCC_MCP_AUDIT_MAX_FIELD_CHARS` (`0` disables truncation)

Full configuration and deployment examples: `docs/deployment.md`

## Documentation Index

- `docs/deployment.md`
- `docs/security-model.md`
- `docs/audit-verification-runbook.md`
- `docs/mcp-inspector-runbook.md`
- `docs/mcp-best-practices-mapping.md`
- `docs/production-readiness-checklist.md`
- `docs/review-workflow.md`
- `docs/implementation-plan.md`

## CI and Release Automation

Continuous integration: `.github/workflows/ci.yml`

- lint, tests, compile checks
- security scans (`bandit`, `pip-audit`)
- packaging checks (`build`, `twine`, wheel smoke)

Release automation: `.github/workflows/release.yml`

- merge PR to `main` with title prefix `release:`
- workflow creates or updates git tag and GitHub Release from `pyproject.toml` + `CHANGELOG.md`

## Transparency

This project includes AI-assisted generated code and documentation.
Generated changes are reviewed, validated, and curated before merge.

## Feedback and Security

Open an issue for bugs, ideas, and integration feedback:  
<https://github.com/CodeAdminDe/gcc/issues>

For security-relevant findings, prefer responsible disclosure via private channels.

## License

Licensed under the GNU Affero General Public License v3.0 (AGPL-3.0).  
See `LICENSE`.
