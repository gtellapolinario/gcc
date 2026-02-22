# Timeout Triage Runbook

Use this runbook when MCP calls fail with timeout/deadline errors (for example:
`deadline has elapsed`).

## What GCC emits

For each tool call, `gcc-mcp` emits structured phase logs:

- `validation`
- `operation_execution`
- `serialization`
- `total`

Each phase log includes:

- `correlation_id`
- `tool_name`
- `phase`
- `status`
- `elapsed_ms`

Timeout-classified failures return:

- `error_code=TIMEOUT`
- `correlation_id`
- `details.phase=operation_execution`

## Triage flow

1. Capture client-side data:
   - timestamp (UTC)
   - tool name
   - full error payload (if available)
2. If `correlation_id` is present, search server logs for that ID.
3. If no `correlation_id` is present (client-side deadline before response),
   search by timestamp window + tool name + phase status.
4. Identify the slow/failing phase by highest `elapsed_ms` or `status=timeout`.
5. Correlate with infra signals (CPU, memory, auth endpoint latency, proxy logs).

## Example log lookup

```bash
# by correlation id
grep 'c1a2b3d4e5f6' /var/log/gcc/server.log

# recent timeout phases
grep 'mcp_tool_phase' /var/log/gcc/server.log | grep '"status": "timeout"'

# focus on one tool
grep 'mcp_tool_phase' /var/log/gcc/server.log | grep '"tool_name": "gcc_context"'
```

## Phase interpretation

- `validation` slow:
  - input/state checks, path resolution, rate-limit path
- `operation_execution` slow:
  - engine operation itself or downstream dependency stalls
- `serialization` slow:
  - unusually large payload shaping/JSON encoding overhead
- `total` much larger than phase expectations:
  - investigate host/container saturation, I/O stalls, or contention

## Escalation checklist

- Include `correlation_id` (if present) in incident ticket.
- Include affected tool(s), UTC window, and sampled timeout frequency.
- Attach relevant `mcp_tool_phase` lines and client error snippets.
