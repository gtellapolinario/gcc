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

Complete install matrix (local source, Docker-only, compose):
`docs/installation.md`

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

## Container Deployment

Container support is available for local development, production-style runtime, and
containerized test execution.

Available files:

- `Dockerfile` (multi-stage: `builder`, `runtime`, `test`)
- `docker-compose.yml` (local/dev runtime)
- `docker-compose.prod.yml` (strict-profile production baseline)
- `docker-compose.test.yml` (containerized test stage)
- `.github/workflows/docker-build-push.yml` (CI build/publish to GHCR)

### Local container quick start

```bash
docker compose up --build -d
docker compose logs -f
```

Endpoint:

- `http://127.0.0.1:8000/mcp`

`docker-compose.yml` uses a named volume for `/workspace` by default so writes work with the
container user (`uid 10001`) without host-permission adjustments.
If you switch to a bind mount (for example `./workspace:/workspace`), ensure host permissions
allow writes for uid `10001` (for example `chown -R 10001:10001 workspace`).

### Production-style compose quick start

```bash
mkdir -p secrets
openssl rand -hex 32 > secrets/audit-signing.key
chmod 600 secrets/audit-signing.key
cp .env.example .env
# optional: edit .env for auth mode/scopes and runtime tuning
# optional: set GCC_MCP_PATH_MAP / GCC_MCP_ALLOWED_ROOTS in .env when
# MCP clients send host paths and gcc-mcp runs in a container runtime path.

export GCC_MCP_AUTH_TOKEN='replace-me'
./scripts/check-container-prereqs.sh
docker compose -f docker-compose.prod.yml up -d
```

Notes:

- Production compose runs with `security-profile=strict`.
- It expects `GCC_MCP_AUTH_TOKEN` and `./secrets/audit-signing.key`.
- Port mapping defaults to loopback only: `127.0.0.1:8000:8000`.
- `GCC_MCP_ALLOW_PUBLIC_HTTP=true` is set for container-internal `0.0.0.0` binding;
  exposure remains host-loopback and should stay behind a TLS reverse proxy (Envoy/nginx/Traefik).
- `GCC_MCP_PATH_MAP` / `GCC_MCP_ALLOWED_ROOTS` can be set in `.env` for host->runtime
  path translation when containerized MCP receives host paths.

### Containerized test run

```bash
docker compose -f docker-compose.test.yml build
docker compose -f docker-compose.test.yml up --abort-on-container-exit
docker compose -f docker-compose.test.yml down --volumes
```

## Quick Start

First-time setup with side-by-side `Local (uv)` and `Docker-only` methods:
`docs/onboarding.md`

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
- `scaffold`
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

### Optional: Scaffold `SKILL.md` Templates

Create a memory-oriented `SKILL.md` in any repository (opt-in, no overwrite by default):

```bash
# Codex-oriented template
gcc-cli scaffold skill --directory /path/to/repo --template codex

# Generic template
gcc-cli scaffold skill --directory /path/to/repo --template generic

# Overwrite existing SKILL.md if needed
gcc-cli scaffold skill --directory /path/to/repo --template codex --force
```

## MCP Payload Shape Examples

For MCP tool calls, pass JSON-typed values that match schema contracts.

`gcc_commit` list/dict fields:

```json
{
  "directory": "/workspace/repos/repo-a",
  "message": "Checkpoint progress",
  "commit_type": "feature",
  "details": ["Added parser", "Added tests"],
  "files_modified": ["src/gcc_mcp/server.py", "tests/test_server_tools.py"],
  "tags": ["mcp", "docs"],
  "ota_log": {
    "observation": "Validation errors repeated on wrong payload shapes.",
    "thought": "Need explicit list/dict examples and better hints.",
    "action": "Added examples and validation guidance.",
    "result": "Calls succeed with schema-aligned payloads."
  }
}
```

`gcc_branch.tags` is `list[str]`:

```json
{
  "directory": "/workspace/repos/repo-a",
  "name": "schema-contracts",
  "description": "Document and validate payload contracts",
  "tags": ["mcp", "api"]
}
```

`gcc_context.scope` is `list[str]`:

```json
{
  "directory": "/workspace/repos/repo-a",
  "level": "detailed",
  "scope": ["main", "schema-contracts"],
  "tags": ["mcp"],
  "format": "markdown"
}
```

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
- `GCC_MCP_PATH_MAP` (JSON host->runtime path mapping for containerized MCP)
- `GCC_MCP_ALLOWED_ROOTS` (comma-separated absolute allowlist roots)

Path translation example (agent path differs from MCP runtime path):

```bash
export GCC_MCP_PATH_MAP='[
  {"from":"/home/dev/worktrees","to":"/workspace/repos"}
]'
export GCC_MCP_ALLOWED_ROOTS='/workspace/repos'
```

Full configuration and deployment examples: `docs/deployment.md`

## Documentation Index

- `docs/installation.md`
- `docs/onboarding.md`
- `docs/deployment.md`
- `docs/security-model.md`
- `docs/audit-verification-runbook.md`
- `docs/timeout-triage-runbook.md`
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
- container test/build checks, signed GHCR publishing (main/tags), and nightly image builds (`docker-build-push.yml`)

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
