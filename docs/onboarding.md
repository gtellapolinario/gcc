# Onboarding Guide: Local vs Docker-only

This guide provides two complete onboarding methods for `gcc-mcp`:

- `Method A: Local (uv)` installs `gcc-mcp` on your machine.
- `Method B: Docker-only` avoids local clone and Python dependency install.

Both methods cover:

- first-time server setup
- MCP client registration
- onboarding the first repository
- onboarding second and additional repositories

## Method Matrix

| Method | Use when | Host requirements |
| --- | --- | --- |
| `Method A: Local (uv)` | You want native CLI/server binaries and direct local workflows | `git`, `uv`, Python runtime support |
| `Method B: Docker-only` | You do not want local clone/dependency install of `gcc-mcp` | Docker only |

## Step 1: Prepare Runtime Secrets

### Method A: Local (uv)

```bash
git clone https://github.com/CodeAdminDe/gcc.git
cd gcc

uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"

mkdir -p "$HOME/.config/gcc-mcp" "$HOME/.local/state/gcc-mcp"
openssl rand -hex 32 > "$HOME/.config/gcc-mcp/audit-signing.key"
chmod 600 "$HOME/.config/gcc-mcp/audit-signing.key"

export GCC_TOKEN="$(openssl rand -hex 32)"
```

### Method B: Docker-only

```bash
docker pull ghcr.io/codeadminde/gcc:latest

mkdir -p "$HOME/.config/gcc-mcp" "$HOME/.local/state/gcc-mcp" "$HOME/gcc-repos"
openssl rand -hex 32 > "$HOME/.config/gcc-mcp/audit-signing.key"
chmod 600 "$HOME/.config/gcc-mcp/audit-signing.key"

export GCC_TOKEN="$(openssl rand -hex 32)"
```

## Step 2: Start `gcc-mcp`

### Method A: Local (uv)

```bash
gcc-mcp \
  --transport streamable-http \
  --host 127.0.0.1 \
  --port 8000 \
  --security-profile strict \
  --auth-mode token \
  --auth-token "$GCC_TOKEN" \
  --audit-log-file "$HOME/.local/state/gcc-mcp/server-audit.jsonl" \
  --audit-signing-key-file "$HOME/.config/gcc-mcp/audit-signing.key"
```

### Method B: Docker-only

```bash
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
  -e GCC_MCP_RATE_LIMIT_PER_MINUTE=120 \
  -e GCC_MCP_AUDIT_MAX_FIELD_CHARS=4000 \
  -v "$HOME/gcc-repos:/workspace/repos" \
  -v "$HOME/.local/state/gcc-mcp:/var/log/gcc" \
  -v "$HOME/.config/gcc-mcp/audit-signing.key:/run/secrets/audit_signing_key:ro" \
  ghcr.io/codeadminde/gcc:latest \
  --transport streamable-http --host 0.0.0.0 --port 8000
```

Health check:

```bash
curl -fsS http://127.0.0.1:8000/mcp >/dev/null || true
```

## Step 3: Register MCP in Codex

Use plain ASCII quotes in terminal commands.

```bash
codex mcp add gcc --url 'http://127.0.0.1:8000/mcp' --bearer-token-env-var 'GCC_TOKEN'

codex mcp list
codex mcp get gcc
```

## Step 4: Onboard the First Repository

By default, keep `.GCC/` out of git (`git_context_policy=ignore`).

### Method A: Local (uv)

```bash
export REPO_A="$HOME/gcc-repos/repo-a"

gcc-cli init \
  --directory "$REPO_A" \
  --name "Repo A" \
  --description "Context-tracked implementation"

gcc-cli status -d "$REPO_A"
gcc-cli commit -d "$REPO_A" -m "Bootstrap GCC context"
```

### Method B: Docker-only

In Docker mode, use container paths when calling `gcc-cli` or MCP tools.

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$HOME/gcc-repos:/workspace/repos" \
  --entrypoint gcc-cli \
  ghcr.io/codeadminde/gcc:latest \
  init \
  --directory /workspace/repos/repo-a \
  --name "Repo A" \
  --description "Context-tracked implementation"

docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$HOME/gcc-repos:/workspace/repos" \
  --entrypoint gcc-cli \
  ghcr.io/codeadminde/gcc:latest \
  status -d /workspace/repos/repo-a
```

## Step 5: Onboard Second and Additional Repositories

Repeat per repository, and select policy per repository.

### Method A: Local (uv)

```bash
export REPO_B="$HOME/gcc-repos/repo-b"

gcc-cli init --directory "$REPO_B" --name "Repo B" --description "Second repo"
gcc-cli status -d "$REPO_B"
```

Track `.GCC/` in git only with explicit risk acknowledgement:

```bash
gcc-cli init \
  --directory "$HOME/gcc-repos/repo-c" \
  --name "Repo C" \
  --git-context-policy track \
  --ack-sensitive-context-risk
```

### Method B: Docker-only

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$HOME/gcc-repos:/workspace/repos" \
  --entrypoint gcc-cli \
  ghcr.io/codeadminde/gcc:latest \
  init --directory /workspace/repos/repo-b --name "Repo B" --description "Second repo"
```

`track` variant:

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$HOME/gcc-repos:/workspace/repos" \
  --entrypoint gcc-cli \
  ghcr.io/codeadminde/gcc:latest \
  init \
  --directory /workspace/repos/repo-c \
  --name "Repo C" \
  --git-context-policy track \
  --ack-sensitive-context-risk
```

## Step 6: Optional Auth Upgrade (`oauth2`)

If you want OAuth2 token introspection instead of static token auth:

### Method A: Local (uv)

```bash
gcc-mcp \
  --transport streamable-http \
  --host 127.0.0.1 \
  --port 8000 \
  --security-profile strict \
  --auth-mode oauth2 \
  --oauth2-introspection-url https://auth.example.com/oauth2/introspect \
  --oauth2-client-id gcc-mcp \
  --oauth2-client-secret 'replace-me' \
  --audit-log-file "$HOME/.local/state/gcc-mcp/server-audit.jsonl" \
  --audit-signing-key-file "$HOME/.config/gcc-mcp/audit-signing.key"
```

### Method B: Docker-only

Use the same Docker run pattern from Step 2 and replace:

- `GCC_MCP_AUTH_MODE=token` with `GCC_MCP_AUTH_MODE=oauth2`
- `GCC_MCP_AUTH_TOKEN=...` with:
  - `GCC_MCP_OAUTH2_INTROSPECTION_URL=...`
  - `GCC_MCP_OAUTH2_CLIENT_ID=...`
  - `GCC_MCP_OAUTH2_CLIENT_SECRET=...`

## Step 7: Verify Signed Audit Log

### Method A: Local (uv)

```bash
gcc-cli audit-verify \
  --log-file "$HOME/.local/state/gcc-mcp/server-audit.jsonl" \
  --signing-key-file "$HOME/.config/gcc-mcp/audit-signing.key"
```

### Method B: Docker-only

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$HOME/.local/state/gcc-mcp:/var/log/gcc" \
  -v "$HOME/.config/gcc-mcp/audit-signing.key:/run/secrets/audit-signing.key:ro" \
  --entrypoint gcc-cli \
  ghcr.io/codeadminde/gcc:latest \
  audit-verify \
  --log-file /var/log/gcc/server-audit.jsonl \
  --signing-key-file /run/secrets/audit-signing.key
```

## Common Pitfalls

- Use ASCII quotes in shell commands; typographic quotes break tokens and URLs.
- In Docker mode, pass repository paths as container paths (`/workspace/repos/...`).
- Keep `.GCC/` ignored by default unless you intentionally accept tracking risk.
- Do not pass secrets on CLI in shared environments; prefer env vars or files.
