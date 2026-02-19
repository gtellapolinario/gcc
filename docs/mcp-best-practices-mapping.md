# MCP Best-Practices Mapping

This server implementation follows official MCP guidance from:

- MCP docs: https://modelcontextprotocol.io/docs/learn/server-concepts
- MCP protocol (tools + annotations): https://modelcontextprotocol.io/specification/draft/server/tools
- Python SDK README: https://github.com/modelcontextprotocol/python-sdk

## Applied Practices

1. Clear, action-oriented tool names:
   - `gcc_init`, `gcc_commit`, `gcc_branch`, `gcc_merge`, `gcc_context`, `gcc_status`
   - `gcc_log`, `gcc_list`, `gcc_checkout`, `gcc_delete`
   - `gcc_config_get`, `gcc_config_set`, `gcc_config_list`
2. Strong input validation:
   - Pydantic request models and constrained tool parameters.
3. Structured outputs:
   - Tools return machine-readable JSON payloads for success/error.
4. Actionable error handling:
   - Stable error codes, clear message, suggestion, and details.
5. Context management:
   - `level`, `scope`, `since`, and `tags` filters reduce output volume.
6. Separation of concerns:
   - Engine logic isolated from MCP transport/bindings.
7. Test coverage for core workflows:
   - Init/commit/branch/merge/context/status lifecycle tests.
8. Security-aware initialization:
   - `.GCC` tracking is explicit per repo.
   - Default is `.gitignore` protection plus informed warning about sensitive context.
9. Path-safety hardening:
   - Branch names validated with strict allow-list pattern.
   - Branch filesystem resolution constrained to `.GCC/branches` root.
10. Security quality gates:
   - CI runs Bandit static analysis and pip-audit dependency checks.
11. Transport exposure guardrails:
   - Non-loopback streamable HTTP bindings require explicit operator opt-in.
12. Operational auditability:
   - MCP tool calls can be logged in structured JSONL with sensitive-field redaction.
13. Runtime operational controls:
   - Optional per-process rate limiting and configurable audit field truncation.
14. Transport readiness:
   - stdio default for local tooling.
   - streamable HTTP mode available behind startup flag.
15. Remote auth hardening:
   - Explicit auth mode selection (`off`, `token`, `trusted-proxy-header`, `oauth2`).
   - Runtime validation of auth mode/transport combinations and required secrets/endpoints.
16. Deployment boundary controls:
   - Envoy-oriented reverse-proxy profile documented for remote operation.
17. Production policy guardrails:
   - Optional strict security profile enforces authenticated remote mode and auditable operation.
18. Audit integrity support:
   - Optional HMAC-signed audit entries with hash-chain metadata for tamper evidence.
19. Operational verifiability:
   - Signed audit logs can be validated post-hoc with deterministic chain/hash/signature checks.
20. SDK compatibility resilience:
   - FastMCP constructor/tool registration paths include compatibility fallbacks for SDK drift.
   - Regression tests cover optional-parameter fallback behavior.
