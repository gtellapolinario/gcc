---
name: git-context-controller
description: Use this skill to store, retrieve, and manage persistent AI-agent memory with GCC. Trigger for multi-session tasks, milestone checkpointing, user preference capture (likes/dislikes), coding style guidance, decision logs, branch exploration, and context recovery.
---

# Git Context Controller (GCC) Skill

## Purpose

GCC is a structured memory system for AI agents.  
It organizes context in a Git-inspired hierarchy so important information survives across sessions and handoffs.

Primary value:

- checkpoint meaningful progress
- preserve decisions and rationale
- capture user-specific preferences and working style
- recover context quickly in later sessions

## When to Use This Skill

Activate this skill whenever memory continuity matters, especially:

- long-running tasks across multiple sessions
- user says "remember this", "for next time", or similar
- user expresses stable likes/dislikes or communication preferences
- coding style, review style, or workflow expectations are clarified
- branching into alternative approaches and later choosing one
- handoff preparation between sessions/agents

## Memory Model

GCC stores context under `.GCC/`:

- `main.md`: high-level roadmap, stable direction, durable memory anchors
- per-branch `commit.md`: milestone summaries
- per-branch `log.md`: detailed OTA trace (Observation, Thought, Action, Result)
- `metadata`/config: branch and runtime metadata

Think in three levels:

1. global memory (`main.md`)
2. milestone memory (`commit.md`)
3. detailed trace memory (`log.md`)

## Agent Workflow (Standard)

1. Session start:
   - run `gcc_status`
   - run `gcc_context` at `summary` (or `detailed` if needed)
2. If GCC is missing:
   - run `gcc_init` for the repo/directory
   - default policy should remain safe (`ignore`), unless user explicitly chooses tracking
3. During work:
   - checkpoint meaningful milestones via `gcc_commit`
   - capture preference/style updates as dedicated commits
4. Alternative strategies:
   - create branches with `gcc_branch`
   - merge winning path with `gcc_merge`
5. Session end:
   - commit a concise summary including next steps / pending risks

## Preference Capture Standard

Store durable user preferences explicitly, not implicitly.

Capture categories:

- communication style (verbosity, directness, format)
- coding style (tests, strictness, naming, patterns)
- review preferences (severity-first, fix-only-if-needed, risk posture)
- process preferences (issue/PR linkage, commit discipline, release flow)
- security posture (hardening expectations, default policies)

Recommended commit tagging:

- `preferences`
- `coding-style`
- `review-style`
- `workflow`
- `security`

Use structured `ota_log` for preference commits so retrieval is unambiguous.

Example (MCP payload shape):

```json
{
  "directory": "/path/to/repo",
  "message": "Capture user review and workflow preferences",
  "commit_type": "docs",
  "details": [
    "User prefers verify-first and fix-only-if-needed",
    "User expects issue/PR/commit linkage discipline"
  ],
  "tags": ["preferences", "review-style", "workflow"],
  "ota_log": {
    "observation": "User clarified recurring collaboration preferences.",
    "thought": "These are stable signals and should persist across sessions.",
    "action": "Recorded as dedicated GCC milestone with tags.",
    "result": "Future sessions can restore the same collaboration style."
  }
}
```

## Retrieval Strategy

Use targeted retrieval to keep context efficient:

- quick restore: `gcc_context(level=summary)`
- detailed restore: `gcc_context(level=detailed)`
- preference-focused restore: filter by tags such as `preferences`, `coding-style`, `workflow`
- recent-only restore: use `since` filter

## Security and Consent Rules

- `.GCC/` may contain sensitive/security-relevant information.
- default should keep `.GCC/` out of git.
- if user wants `.GCC/` tracked, require explicit informed consent.
- do not store secrets in plain text when avoidable; keep logs useful but safe.

## Tool and CLI Parity (Current)

MCP tools:

- `gcc_init`, `gcc_commit`, `gcc_branch`, `gcc_merge`, `gcc_context`, `gcc_status`
- `gcc_log`, `gcc_list`, `gcc_checkout`, `gcc_delete`
- `gcc_config_get`, `gcc_config_set`, `gcc_config_list`

CLI commands:

- `init`, `commit`, `branch`, `merge`, `context`, `status`
- `log`, `list`, `checkout`, `delete`, `config`, `audit-verify`

## Quality Bar

Good GCC memory entries are:

- concise but specific
- tagged for retrieval
- decision-oriented (what changed and why)
- useful for future continuation without re-discovery

Avoid noisy commits for trivial events.

## References

- `docs/onboarding.md`
- `docs/installation.md`
- `docs/deployment.md`
- `docs/security-model.md`
