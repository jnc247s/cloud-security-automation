# Design decision records

`ARCHITECTURE.md` describes current accepted reality. This directory is for future durable design
decisions that materially change boundaries, data models, security posture, public interfaces,
deployment topology, or an intentionally accepted tradeoff.

Do not create a decision record for routine implementation detail, and do not invent
retrospective approval history. When a decision is needed, use an immutable numbered file such as
`0001-short-title.md` containing:

```text
# Title
Status: proposed | accepted | superseded
Date: YYYY-MM-DD

## Context
## Decision
## Alternatives considered
## Security and data-integrity consequences
## Compatibility and migration
## Validation
```

An accepted decision updates `ARCHITECTURE.md` and, where relevant, `SECURITY.md`,
`THREAT_MODEL.md`, `docs/api.md`, operations guidance, tests, and the active execution plan.
Supersede records with a new file and links; do not rewrite historical rationale.
