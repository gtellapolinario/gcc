# Changelog

## v0.1.1 - 2026-02-20

### Added

- Production release gates in CI:
  - distribution artifact build (`python -m build`)
  - metadata validation (`twine check dist/*`)
  - wheel install smoke for `gcc-cli` and `gcc-mcp` entrypoints
- Production readiness checklist for rollout/rollback, security, and observability validation.
- Runtime startup preflight diagnostics:
  - `gcc-mcp --check-config`
  - `gcc-mcp --print-effective-config` (sanitized output)

### Improved

- FastMCP compatibility hardening across SDK drift:
  - constructor compatibility fallback behavior
  - tool-registration fallback robustness for older SDK annotation behavior
  - regression coverage for compatibility paths and error propagation
- CI matrix coverage for MCP SDK compatibility (default + minimum supported version).
- Project tracking and phase closeout documentation through v1.5.

### Security

- Reinforced remote-deployment guidance around strict profile, auth mode requirements, and signed audit configuration.
- Maintained CI security scans (`bandit`, `pip-audit`) with passing gates on merged delivery.

