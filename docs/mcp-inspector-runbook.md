# MCP Inspector Runbook

## Purpose

Validate tool discoverability and behavioral correctness with MCP Inspector.

## Prerequisites

- Node.js 20+
- Python environment with project installed

## Start server (stdio)

```bash
gcc-mcp
```

## Launch inspector

```bash
npx @modelcontextprotocol/inspector
```

Use stdio mode and point to:

- Command: `gcc-mcp`
- Args: none

## Verification Checklist

1. Ensure all tools are listed:
   - `gcc_init`, `gcc_commit`, `gcc_branch`, `gcc_merge`, `gcc_context`, `gcc_status`
2. Validate init security contract:
   - `git_context_policy=ignore` works by default.
   - `git_context_policy=track` fails without risk acknowledgement.
3. Validate context filters:
   - `level`, `scope`, `since`, `tags`, `format` operate as expected.
4. Validate redaction:
   - `redact_sensitive=true` returns redacted payloads.
5. Validate error contract:
   - all failures contain `status`, `error_code`, `message`, `suggestion`, `details`.
   - timeout-classified failures include `error_code=TIMEOUT` and `correlation_id`.

## Scripted smoke harness

Use:

```bash
scripts/run_mcp_inspector.sh
```

This script performs local quality checks and prints commands for launching inspector.
