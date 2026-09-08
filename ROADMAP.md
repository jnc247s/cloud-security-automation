# Cloud Security Control Plane roadmap

`ROADMAP.md` is the canonical source of project progress. The status recorded here overrides old
prompts, conversations, branch names, and historical planning text.

Last verified: 2026-09-05
Accepted baseline: `main` at `1e190720c5c33a4edfc1cebe44c652e2ee17424f` (Sprint 4 merge)

## Current state

| Sprint | Outcome | Status |
| --- | --- | --- |
| Sprint 0 | Application Foundation | **COMPLETE** |
| Sprint 1 | AWS Resource Inventory | **COMPLETE** |
| Sprint 2 | Security Rules Engine | **COMPLETE** |
| Sprint 2.1 | Assessment Framework / NIST / Control Contracts | **COMPLETE** |
| Sprint 3 | Persistence / History / Evidence / Findings / Exceptions / Audit | **COMPLETE** |
| Sprint 4 | Service Layer / Authentication / Authorization / REST API / Scan Execution | **COMPLETE** |
| Sprint 5 | AWS Evidence Expansion | **NEXT** |
| Sprint 6 | Production Security Controls | **PLANNED** |
| Sprint 7 | Dashboard / NIST Technical Posture | **PLANNED** |
| Sprint 8 | Human-Approved Remediation | **PLANNED** |
| Sprint 9 | Hardening / Scanner Validation | **PLANNED** |
| Sprint 10 | AWS Deployment / v1.0 | **PLANNED** |
| Optional post-v1 | AI Security Investigation Agent | **DEFERRED** |

No sprint is currently `IN PROGRESS`. Sprint 5 has not begun.

## Next: Sprint 5 — AWS Evidence Expansion

Sprint 5 collects the normalized evidence needed by the Sprint 6 production control library; it
does not implement those controls. Approved roadmap scope includes EC2 and EBS facts, VPC/network
facts, IAM account and policy evidence, IAM Access Analyzer evidence where available, expanded S3
and CloudTrail facts, explicit global-versus-regional execution scope, and resource relationships.

The approved requirements are preserved in `docs/exec-plans/active/sprint-5.md`. Before
implementation, complete its analysis-only preflight and approve a reviewable execution sequence.
Only then change Sprint 5 from `NEXT` to `IN PROGRESS`.

## Pre-Sprint 5 attention

These accepted-baseline limitations were discovered during the governance audit. They are not
silently repaired by this documentation task and must be triaged before or explicitly within an
approved Sprint 5 plan:

- **HIGH — populated downgrade safety:** revision `20260904_0002` makes pending-scan identity
  columns nullable, but its downgrade restores `NOT NULL` without handling legitimate early
  `FAILED` scans whose AWS identity and inventory digest are absent.
- **HIGH — assessment-profile versioning:** changing `REQUIRED_TAGS` or
  `STALE_ACCESS_KEY_DAYS` changes the immutable content of profile `default` version `1.0.0`.
  Against a database that already stores that version, a later scan can fail with a version-content
  conflict. A version-selection/roll-forward policy is not implemented.
- **RESOLVED — acceptance coverage:** the PostgreSQL integration suite now drives authenticated
  HTTP scan creation through deterministic fake AWS collection, real execution and persistence,
  and the principal read APIs. Sprint 5 remains `NEXT` and has not begun.
- **MEDIUM — collector failure contract:** expected AWS and declared collector-evidence failures
  are isolated, but some unexpected malformed response shapes can abort the whole scan or CLI run.
- **MEDIUM — audit principal context:** scan-start audit records retain the authenticated subject,
  but not issuer, roles, or the authorizing capability.
- **MEDIUM — authorization scope:** authenticated readers can query every account in this
  control-plane database. The current deployment model is one trusted security domain, not
  tenant-isolated SaaS.
- **LOW — stable ARN presentation:** stable resource identity retains the first-seen ARN while
  snapshots retain observed ARNs. For resources whose ARN can change, the top-level resource view
  can differ from its latest snapshot.

See `docs/operations/known-limitations.md` and `THREAT_MODEL.md` for operational and security
detail.

## Status vocabulary

- `COMPLETE`: accepted implementation, full regression, required integration/security and
  acceptance validation, independent review, current documentation, and required merge approval
  are complete.
- `IN PROGRESS`: implementation is actively underway on an approved plan.
- `NEXT`: the next approved roadmap outcome; implementation has not begun.
- `PLANNED`: future committed v1 work.
- `DEFERRED`: explicitly outside the committed v1 sequence.

Normally at most one sprint is `IN PROGRESS`, exactly one future sprint is `NEXT`, and all later
work is `PLANNED` or `DEFERRED`.

## Transition protocol

At sprint start:

1. confirm this roadmap and `docs/exec-plans/active/` agree;
2. complete the analysis-only preflight and approve the execution plan;
3. create a feature branch from clean, current `main`; and
4. change the sprint from `NEXT` to `IN PROGRESS`.

Sub-sprint state may be recorded inside an active plan as `COMPLETE`, `IN PROGRESS`, or `PLANNED`,
without prematurely completing the parent sprint.

At sprint completion, require all of:

1. implementation complete;
2. targeted tests pass;
3. the complete regression suite passes;
4. lint and formatting pass;
5. relevant collector, database, migration, and integration tests pass;
6. relevant live/mock AWS validation passes safely;
7. independent correctness, security, and data-integrity review is complete;
8. all `CRITICAL` and `HIGH` findings are resolved;
9. the sprint acceptance test passes;
10. documentation is current; and
11. required merge approval and merge are complete.

Then mark the sprint `COMPLETE`, promote the following sprint from `PLANNED` to `NEXT`, and move
the execution plan from `active/` to `completed/`, retaining implemented differences.

## Protected completed-sprint contracts

- Sprint 0: startup, health/readiness, local Docker, CI, and test foundation.
- Sprint 1: standard AWS credential chain, read-only client/session layer, inventory service, and
  fact-only collectors.
- Sprint 2: deterministic, side-effect-free technical rule evaluation.
- Sprint 2.1: four-state assessments, structured evidence, versioned profiles/control contracts,
  and framework-mapping semantics.
- Sprint 3: stable resources versus immutable snapshots, historical evidence and assessments,
  finding/exception/audit integrity, and Alembic migration history.
- Sprint 4: services, OIDC/development authentication, capability authorization, versioned API
  schemas, durable scan identities, and replaceable non-blocking execution.

Changing these contracts requires the interface-change and full-regression protocol in
`AGENTS.md`.
