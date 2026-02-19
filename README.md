# gcc-mcp

Python MCP server for the **Git Context Controller (GCC)**.  
It implements Git-inspired context operations for AI-agent workflows:

- `gcc_init`
- `gcc_commit`
- `gcc_branch`
- `gcc_merge`
- `gcc_context`
- `gcc_status`

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

Or (module mode):

```bash
python -m gcc_mcp
```

Run CLI (parity with MCP tools):

```bash
gcc-cli --help
```

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
