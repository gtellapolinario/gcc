# GCC MCP Implementation Plan

## Source Specs

- Notion root: https://www.notion.so/30cdbfde494681a2947dce59ca1cdafe
- Primary inputs used:
  - MCP Tool Definitions (Complete)
  - Python Implementation Details
  - Implementation Guide
  - CLI Specification and Command Reference

## Current Scope (v0.1)

1. Python package scaffold with install/runtime metadata.
2. Core GCC engine and filesystem persistence:
   - `initialize`
   - `commit`
   - `branch`
   - `merge`
   - `get_context`
   - `get_status`
3. FastMCP tool surface:
   - `gcc_init`
   - `gcc_commit`
   - `gcc_branch`
   - `gcc_merge`
   - `gcc_context`
   - `gcc_status`
4. Structured error contract with stable error codes.
5. Baseline tests for end-to-end lifecycle paths.

## GitHub Tracking

- Milestone: `GCC MCP v0.1 - Core Server`
- Issues:
  - #1 Scaffold Python package and project structure for GCC MCP
  - #2 Implement GCCEngine core operations and filesystem state model
  - #3 Implement context rendering and filtering (summary/detailed/full; markdown/json/yaml)
  - #4 Finalize docs and local runbook for MCP server usage
  - #5 Add automated tests for init/commit/branch/merge/context/status flows
  - #6 Expose six MCP tools via FastMCP with strict input validation

## Decisions (2026-02-19)

1. `.GCC` Git strategy:
   - Default: ignored in git (`.GCC/` added to `.gitignore`).
   - Per-repo override: `git_context_policy=track` supported at init.
   - Tracking requires explicit acknowledgement because `.GCC` may contain sensitive context.
2. Branch lifecycle semantics:
   - `merge` with `keep_branch=true`: branch remains locally `active`, but `integration_status=merged`.
   - `merge` with `keep_branch=false`: source branch marked `merged`.
3. Packaging boundary:
   - MCP + CLI both live in this repository.
   - CLI entrypoint is `gcc-cli` and mirrors the MCP tool set.
4. Transport:
   - v0.1 default remains stdio.
   - Server now includes streamable HTTP startup path for future remote deployment.
