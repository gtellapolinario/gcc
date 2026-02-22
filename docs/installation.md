# Installation Guide

This guide covers installation and first startup of `gcc-mcp` using either:

- local source install (`uv`, recommended for contributors)
- Docker image only (no local clone/dependency install)
- Docker Compose profiles (dev/prod-style)

For first project onboarding (`repo 1`, `repo 2+`), continue with `docs/onboarding.md`.

## Prerequisites

### Local Source (`uv`)

- Python `>=3.10`
- `uv`
- `git`

### Docker-only

- Docker engine
- optional: Docker Compose plugin (for compose profiles)

## Method A: Local Source Install (`uv`)

```bash
git clone https://github.com/CodeAdminDe/gcc.git
cd gcc

uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

Validate:

```bash
python -m ruff check src tests
python -m pytest -q
gcc-mcp --help
gcc-cli --help
```

## Method B: Docker-only (No Local Clone)

Pull image:

```bash
docker pull ghcr.io/codeadminde/gcc:latest
```

Run quick help checks:

```bash
docker run --rm ghcr.io/codeadminde/gcc:latest --help
docker run --rm --entrypoint gcc-cli ghcr.io/codeadminde/gcc:latest --help
```

## Start MCP Server (Strict + Token Auth)

This is a production-like baseline for remote-compatible usage.

## Local Source Runtime

```bash
mkdir -p .secrets .GCC
openssl rand -hex 32 > .secrets/audit-signing.key
chmod 600 .secrets/audit-signing.key

export GCC_MCP_AUTH_TOKEN='replace-me'

gcc-mcp \
  --transport streamable-http \
  --host 127.0.0.1 \
  --port 8000 \
  --security-profile strict \
  --auth-mode token \
  --audit-log-file .GCC/server-audit.jsonl \
  --audit-signing-key-file .secrets/audit-signing.key
```

## Docker-only Runtime

```bash
mkdir -p "$HOME/.config/gcc-mcp" "$HOME/.local/state/gcc-mcp" "$HOME/gcc-repos"
openssl rand -hex 32 > "$HOME/.config/gcc-mcp/audit-signing.key"
chmod 600 "$HOME/.config/gcc-mcp/audit-signing.key"
export GCC_TOKEN='replace-me'

# Optional: host/client paths -> container runtime paths
export GCC_MCP_PATH_MAP='[
  {"from":"/home/dev/worktrees","to":"/workspace/repos"}
]'
export GCC_MCP_ALLOWED_ROOTS='/workspace/repos'

docker rm -f gcc-mcp >/dev/null 2>&1 || true
docker run -d \
  --name gcc-mcp \
  --restart unless-stopped \
  --user "$(id -u):$(id -g)" \
  -p 127.0.0.1:8000:8000 \
  -e GCC_MCP_ALLOW_PUBLIC_HTTP=true \
  -e GCC_MCP_SECURITY_PROFILE=strict \
  -e GCC_MCP_AUTH_MODE=token \
  -e GCC_MCP_AUTH_TOKEN="$GCC_TOKEN" \
  -e GCC_MCP_AUDIT_LOG=/var/log/gcc/server-audit.jsonl \
  -e GCC_MCP_AUDIT_SIGNING_KEY_FILE=/run/secrets/audit_signing_key \
  -e GCC_MCP_AUDIT_SIGNING_KEY_ID=local-2026-q1 \
  -e GCC_MCP_PATH_MAP="${GCC_MCP_PATH_MAP:-}" \
  -e GCC_MCP_ALLOWED_ROOTS="${GCC_MCP_ALLOWED_ROOTS:-}" \
  -v "$HOME/gcc-repos:/workspace/repos" \
  -v "$HOME/.local/state/gcc-mcp:/var/log/gcc" \
  -v "$HOME/.config/gcc-mcp/audit-signing.key:/run/secrets/audit_signing_key:ro" \
  ghcr.io/codeadminde/gcc:latest \
  --transport streamable-http --host 0.0.0.0 --port 8000
```

## Method C: Docker Compose Profiles

## Development Compose

```bash
docker compose up --build -d
docker compose logs -f
```

Endpoint:

- `http://127.0.0.1:8000/mcp`

## Production-style Compose

```bash
mkdir -p secrets
openssl rand -hex 32 > secrets/audit-signing.key
chmod 600 secrets/audit-signing.key
cp .env.example .env
./scripts/check-container-prereqs.sh
docker compose -f docker-compose.prod.yml up -d
```

Notes:

- Keep `GCC_MCP_AUTH_TOKEN` in `.env` or shell environment (never commit secrets).
- Set `GCC_MCP_PATH_MAP` and `GCC_MCP_ALLOWED_ROOTS` in `.env` when clients send
  host paths but `gcc-mcp` resolves container runtime paths.
- If a mapped leaf path does not exist, `gcc-mcp` falls back to the nearest
  existing mapped ancestor within the configured mapping boundary.
- Relative directory inputs (for example `.`) resolve from the MCP runtime cwd.
  Use absolute repo paths from the client side when runtime cwd and client cwd differ.
- Host exposure remains loopback-only by default in production compose.
- Place a TLS reverse proxy (Envoy/nginx/Traefik) in front for external access.

## Register MCP in Codex

```bash
codex mcp add gcc \
  --url 'http://127.0.0.1:8000/mcp' \
  --bearer-token-env-var 'GCC_TOKEN' \
  --env 'GCC_TOKEN=replace-me'
```

Verify:

```bash
codex mcp list
codex mcp get gcc
```

Use ASCII quotes in shell commands. Typographic quotes can break token/env parsing.

## Post-install Checks

Choose the check commands that match how you run `gcc-mcp`.

Local-source runtime:

```bash
gcc-mcp --check-config
gcc-mcp --print-effective-config
gcc-cli audit-verify --log-file .GCC/server-audit.jsonl --signing-key-file .secrets/audit-signing.key
```

Docker runtime:

```bash
docker exec gcc-mcp gcc-mcp --check-config
docker exec gcc-mcp gcc-mcp --print-effective-config
docker exec gcc-mcp gcc-cli audit-verify --log-file /var/log/gcc/server-audit.jsonl --signing-key-file /run/secrets/audit_signing_key
```

For onboarding actual repositories after install, see `docs/onboarding.md`.
