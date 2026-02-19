# MCP Best-Practices Mapping

This server implementation follows official MCP guidance from:

- MCP docs: https://modelcontextprotocol.io/docs/learn/server-concepts
- MCP protocol (tools + annotations): https://modelcontextprotocol.io/specification/draft/server/tools
- Python SDK README: https://github.com/modelcontextprotocol/python-sdk

## Applied Practices

1. Clear, action-oriented tool names:
   - `gcc_init`, `gcc_commit`, `gcc_branch`, `gcc_merge`, `gcc_context`, `gcc_status`
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
9. Transport readiness:
   - stdio default for local tooling.
   - streamable HTTP mode available behind startup flag.

## Planned Follow-up

- Verify and add explicit tool annotations (`readOnlyHint`, `idempotentHint`, etc.)
  after dependency installation in the target runtime environment.
