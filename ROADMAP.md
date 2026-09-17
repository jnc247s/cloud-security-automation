# Cloud Security Control Plane roadmap

`ROADMAP.md` is the canonical source of project progress. The status recorded here overrides old
prompts, conversations, branch names, and historical planning text.

Last verified: 2026-09-17
Accepted baseline: `main` at `1a355107eb7a3ed7845fa3a569dbff80da2778bb` (Sprints 0--4,
accepted pre-Sprint-5 repairs, the shared Sprint 5 evidence-graph foundation, accepted 5A EC2/EBS
evidence, accepted 5B network evidence, accepted 5C IAM evidence, and accepted 5D IAM Access
Analyzer evidence)

## Current state

| Sprint | Outcome | Status |
| --- | --- | --- |
| Sprint 0 | Application Foundation | **COMPLETE** |
| Sprint 1 | AWS Resource Inventory | **COMPLETE** |
| Sprint 2 | Security Rules Engine | **COMPLETE** |
| Sprint 2.1 | Assessment Framework / NIST / Control Contracts | **COMPLETE** |
| Sprint 3 | Persistence / History / Evidence / Findings / Exceptions / Audit | **COMPLETE** |
| Sprint 4 | Service Layer / Authentication / Authorization / REST API / Scan Execution | **COMPLETE** |
| Sprint 5 | AWS Evidence Expansion | **IN PROGRESS** |
| Sprint 6 | Production Security Controls | **PLANNED** |
| Sprint 7 | Dashboard / NIST Technical Posture | **PLANNED** |
| Sprint 8 | Human-Approved Remediation | **PLANNED** |
| Sprint 9 | Hardening / Scanner Validation | **PLANNED** |
| Sprint 10 | AWS Deployment / v1.0 | **PLANNED** |
| Optional post-v1 | AI Security Investigation Agent | **DEFERRED** |

Sprint 5 is currently `IN PROGRESS`. Its shared 5G relationship/source-outcome evidence
foundation and 5A EC2/EBS, 5B VPC/network, 5C IAM, and 5D IAM Access Analyzer evidence slices are
accepted on `main`. The bounded 5E S3 evidence-expansion preflight is complete and the slice is
authorized for implementation but has not started. No Sprint 6 control has been enabled.

## In progress: Sprint 5 — AWS Evidence Expansion

Sprint 5 collects the normalized evidence needed by the Sprint 6 production control library; it
does not implement those controls. Approved roadmap scope includes EC2 and EBS facts, VPC/network
facts, IAM account and policy evidence, IAM Access Analyzer evidence where available, expanded S3
and CloudTrail facts, explicit global-versus-regional execution scope, and resource relationships.

The approved requirements are preserved in `docs/exec-plans/active/sprint-5.md`. Its analysis-only
preflight and reviewable execution sequence are complete. The shared 5G
relationship/source-outcome evidence foundation passed its acceptance gate as
`FOUNDATION_READY_FOR_5A`; 5A was accepted and merged in pull request 16, 5B in pull request 17,
5C in pull request 18, and 5D in pull request 20. Slice 5E is separately authorized to implement
only the approved direct S3 and referenced-KMS facts, source outcomes, provenance, and resource
relationships while preserving accepted pending-scan, Access Analyzer, and `S3-900` behavior.

Sprint 5 Phase 0 completed on 2026-09-15 against `main` commit
`feb0b5c2b517f51dd6c7b48eb38513cf92306164` with result `SPRINT_5_GO`. The first approved
implementation slice is the 5G relationship/source-outcome persistence foundation documented in
the active plan, followed by 5A through 5F and the 5G closure. This gate makes Sprint 5 ready to
start; the approved foundation implementation branch has now begun and moved the sprint to
`IN PROGRESS`.

The shared foundation gate completed on 2026-09-15 at migration head `20260915_0003`. Domain,
migration, PostgreSQL, authenticated API, full-regression, lint, format, container, and independent
review gates passed with no remaining review findings. The separately authorized 5A slice passed
its acceptance gates and was merged on 2026-09-16. Slice 5B subsequently passed its acceptance
gates and was merged in pull request 17 at `66cadb20cd6a469d5a656628c27ae8cb569d8c69`.
Slice 5C subsequently passed its acceptance gates and was merged in pull request 18 at
`819f9ba3b26490ca23c69a6665b1baf9d7948975`. Slice 5D was merged in pull request 20 at
`1a355107eb7a3ed7845fa3a569dbff80da2778bb`, and the merged-main CI quality job succeeded. The
bounded 5E preflight is complete, but 5E implementation has not started. Sprint 6 remains
`PLANNED`.

## Pre-Sprint 5 attention

These accepted-baseline limitations were discovered during the governance audit. This register
records both reviewed repairs and remaining items that must be triaged before or explicitly within
an approved Sprint 5 plan:

- **RESOLVED — populated downgrade safety:** the accepted `20260904_0002` migration remains
  unchanged. Alembic now preflights any downgrade across it, blocks before DDL when retained scans
  cannot satisfy the older `NOT NULL` contract, and excludes concurrent PostgreSQL writers while
  checking and transitioning compatible data.
- **RESOLVED — assessment-profile versioning:** `ASSESSMENT_PROFILE_VERSION` explicitly selects a
  numeric immutable profile version for new scans. Changed content under an existing version is
  rejected with a sanitized conflict; a reviewed new version coexists with historical versions.
  Pending and recovered scans load their exact persisted profile instead of current deployment
  policy. The established schema already supports this roll-forward, so no migration was added.
- **RESOLVED — acceptance coverage:** the PostgreSQL integration suite now drives authenticated
  HTTP scan creation through deterministic fake AWS collection, real execution and persistence,
  and the principal read APIs. At the time of this repair, Sprint 5 remained `NEXT` and had not
  begun.
- **RESOLVED — collector failure contract:** existing Sprint 1 collectors now validate required
  identities, promoted nested evidence, pages, tags, permissions, and duplicate stable resources.
  Operational AWS failures remain `FAILED`, malformed evidence becomes sanitized `PARTIAL`, and
  programming defects remain visible. This repair added no Sprint 5 evidence and was completed
  before Sprint 5 began.
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
