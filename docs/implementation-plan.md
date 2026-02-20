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

## v0.3 Security and Docs Hardening (completed)

Tracking:

- Milestone: `GCC MCP v0.3 - Security and Documentation Hardening`
- Issue: `#10 v0.3 Security+Docs hardening execution`

Delivered items:

1. Global branch path hardening and strict branch validation.
2. CI security scans (`bandit`, `pip-audit`).
3. Expanded docstring coverage across core runtime modules.
4. Regression tests for traversal and runtime validation edge cases.
5. Security model and deployment hardening documentation.

## v0.4 Remote Hardening and Auditing (completed)

Tracking:

- Milestone: `GCC MCP v0.4 - Remote Transport Hardening and Auditing`
- Issue: `#12 v0.4 Remote hardening + audit logging execution`

Delivered items:

1. Public streamable HTTP binding guard with explicit operator opt-in.
2. Structured MCP tool-call audit logs (JSONL) with sensitive-field redaction.
3. Expanded runtime settings validation (`GCC_MCP_ALLOW_PUBLIC_HTTP`, audit settings).
4. Regression tests for host exposure and audit/runtime edge cases.
5. Deployment/security docs updates for remote operations.

## v0.5 Operational Guardrails and Limits (completed)

Tracking:

- Milestone: `GCC MCP v0.5 - Operational Guardrails and Limits`
- Issue: `#14 v0.5 Operational guardrails execution (rate limits + audit caps)`

Delivered items:

1. Optional per-process MCP tool-call rate limiting.
2. Audit payload field-size truncation for safer log volume bounds.
3. Runtime parsing/validation for operational control settings.
4. Regression tests for limiter behavior and runtime/audit edge cases.
5. Deployment/security docs updates for operational controls.

## v0.6 Remote AuthN/AuthZ and Deployment Profiles (completed)

Tracking:

- Milestone: `GCC MCP v0.6 - Remote AuthN/AuthZ and Deployment Profiles`
- Issue: `#16 v0.6 Execution: remote authn/authz + deployment profiles (Envoy)`

Delivered items:

1. Runtime auth mode framework (`off`, `token`, `trusted-proxy-header`, `oauth2`).
2. FastMCP auth wiring for static token and OAuth2 introspection verification.
3. Trusted proxy header enforcement middleware for streamable HTTP mode.
4. Auth + transport validation hardening and metadata URL controls.
5. Deployment/security docs updates with Envoy-based remote profile guidance.
6. Regression tests for auth runtime parsing/validation and URL resolution.

## v0.7 Policy Enforcement and Signed Audit Trails (completed)

Tracking:

- Milestone: `GCC MCP v0.7 - Policy Enforcement and Signed Audit Trails`
- Issue: `#18 v0.7 Execution: strict policy + signed audit trails`

Delivered items:

1. Runtime security profile framework (`baseline`, `strict`).
2. Strict-profile validation for remote operation (auth required; audit required; signing required).
3. Optional HMAC-signed audit events with hash-chain metadata.
4. Runtime parsing/validation for audit signing key and profile interactions.
5. Regression tests for security-policy and signed-audit behavior.
6. Deployment/security docs updates for strict profile rollout.

## v0.8 Audit Verification and Key Lifecycle Controls (completed)

Tracking:

- Milestone: `GCC MCP v0.8 - Audit Verification and Key Lifecycle Controls`
- Issue: `#20 v0.8 Execution: audit verification + key lifecycle controls`

Delivered items:

1. Signed audit verification utility and CLI command.
2. Deterministic failure diagnostics for hash/signature/chain mismatches.
3. Safer strict-profile secret sourcing (`audit-signing-key-file`; CLI key restrictions).
4. Regression tests for verification and policy refinements.
5. Audit verification runbook and key-rotation guidance.

## v0.9 Multi-Key Audit Rotation and Verification (completed)

Tracking:

- Milestone: `GCC MCP v0.9 - Multi-Key Audit Rotation and Verification`
- Issue: `#22 v0.9 Execution: multi-key audit rotation and verification`

Delivered items:

1. Runtime/server support for optional audit signing key IDs.
2. Signed events persist `event_signing_key_id`.
3. CLI + verifier support keyring-based rotated-key verification.
4. Backward-compatible mixed legacy/key-id verification behavior.
5. Regression tests and docs updates for rotation rollout and verification workflows.

## v1.0 MCP Tool Surface Completeness and Parity (completed)

Tracking:

- Milestone: `GCC MCP v1.0 - MCP Tool Surface Completeness and Parity`
- Issue: `#24 v1.0 Execution: MCP tool-surface completeness and parity`

Delivered items:

1. Expand MCP tool surface for branch operations, config operations, and history/list read paths.
2. Keep stable error contract and runtime guardrails across expanded tool set.
3. Add regression tests for new tool flows and edge cases.
4. Refresh docs/mapping/evaluation artifacts after tool expansion.

## v1.1 SDK Compatibility and CI Resilience (completed)

Tracking:

- Milestone: `GCC MCP v1.1 - SDK Compatibility and CI Resilience`
- Issue: `#26 v1.1 Execution: SDK compatibility hardening and constructor regression tests`

Delivered items:

1. Harden FastMCP constructor compatibility across supported SDK versions.
2. Add deterministic tests for optional-kwarg fallback and error propagation.
3. Keep docs/tracking aligned with compatibility policy decisions.

## v1.2 CI SDK Version Matrix Hardening (completed)

Tracking:

- Milestone: `GCC MCP v1.2 - CI SDK Version Matrix Hardening`
- Issue: `#28 v1.2 Execution: CI matrix for MCP SDK compatibility`

Delivered items:

1. Add MCP SDK version matrix coverage in CI (minimum supported + default/latest resolved).
2. Preserve existing lint/test/compile gates across matrix entries.
3. Keep runtime cost controlled with representative SDK-version coverage.

## v1.3 Tool Registration Compatibility Hardening (completed)

Tracking:

- Milestone: `GCC MCP v1.3 - Tool Registration Compatibility Hardening`
- Issue: `#30 v1.3 Execution: tighten tool annotation fallback and add regressions`

Delivered items:

1. Hardened FastMCP tool-registration compatibility for legacy annotation handling behavior.
2. Added regression coverage for non-class annotation fallback and unrelated TypeError propagation.
3. Closed delivery via PR #29 merge and reconciled superseded stacked branch/PR state.

## v1.4 Production Readiness and Release Gates (completed)

Tracking:

- Milestone: `GCC MCP v1.4 - Production Readiness and Release Gates`
- Issue: `#32 v1.4 Execution: production readiness and release gates`

Delivered items:

1. Add distribution build/install smoke checks to CI for release gating.
2. Publish operator-facing production readiness checklist and rollout/rollback guidance.
3. Keep plan/best-practice mapping aligned with release-quality and delivery state.

## v1.5 Runtime Preflight and Startup Diagnostics (completed)

Tracking:

- Milestone: `GCC MCP v1.5 - Runtime Preflight and Startup Diagnostics`
- Issue: `#34 v1.5 Execution: runtime preflight and startup diagnostics`

Delivered items:

1. Add server preflight mode (`--check-config`) to validate runtime settings and exit.
2. Add sanitized effective runtime configuration output (`--print-effective-config`).
3. Add regression tests and deployment docs for startup diagnostics workflows.

## v1.6 Automated Release Pipeline (in progress)

Tracking:

- Milestone: `GCC MCP v1.6 - Automated Release Pipeline`
- Issue: `#39 ci: automate tag/release for release PRs`

Execution items:

1. Add workflow to auto-publish releases for merged `release:` PRs into `main`.
2. Use version metadata (`pyproject.toml`) + `CHANGELOG.md` as release source of truth.
3. Provide workflow-dispatch fallback for backfill releases without manual tag/release commands.
