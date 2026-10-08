# Sprint 8 analysis-only preflight

This retains the original 2026-10-06 baseline analysis and predictions, not current implementation
status. Subsequent accepted 8A scope and the remaining entry gates are recorded in ROADMAP and
the [active Sprint 8 plan](exec-plans/active/sprint-8.md).

## Verified baseline — 2026-10-06

The task checkout was clean on main at
`20c04665f89ae8c8cf9348603fd54e0e100b6076`. Read-only remote verification matched that exact
HEAD. Sprints 0--7 were COMPLETE and Sprint 8 NEXT, with no active execution plan. PR #52
reconciled documentation; merged-main CI 37354537175 passed. Migration head was
`20261001_0006`. Parent untracked `.agents/` skill files and existing worktrees/branches are
unrelated and must be preserved.

Sources inspected: AGENTS, ROADMAP, PRODUCT_REQUIREMENTS, ARCHITECTURE, SECURITY, THREAT_MODEL,
API/persistence/inventory/dashboard operations documents and the completed Sprint 7 plan.
Code/test inspection covered capability dependencies and all callers, evidence graph and
assessment history, finding occurrences/exceptions, append-only audit guards, migration
pre-DDL downgrade guards, scan submission/recovery and signed-identity HTTP acceptance.

## Integration findings

- `app/remediation/` has no workflow implementation. Existing capabilities already separate
  READ, PROPOSE, APPROVE and EXECUTE; their role mapping must not change.
- EC2-004 already has stable regional account assessment targets and FAIL finding occurrences.
  Collectors remain fact-only; adding synthetic collector resources is unnecessary.
- Read services are single-trust-domain, not tenant/account authorization. Preserve this model;
  future writes require an additional explicit account/Region/action allowlist.
- Scan persistence serializes Resource before Finding, and only completed explicit PASS
  evidence can resolve a finding. Reuse the ordering, not the read-only scanner executor.
- Exact profile/catalog recovery is already supported internally. Future verification must
  retain that policy instead of scanning with today's default deployment profile.
- Historical audit attribution lacks issuer/roles/capability. New remediation mutations must
  capture full verified context without rewriting old events.

## Bounded slices and decisions

Recommended first slice 8A: immutable proposals, decisions, idempotency, transactional audit and
generic authenticated APIs, with no AWS work. Then separately approve 8B isolated execution/
recovery, 8C exact-policy read-only rescan verification, 8D authenticated dashboard workflow and
8E whole-sprint acceptance.

User decisions: EC2-004 only; three distinct verified human principals for proposal, approval
and execution request; ADMIN has no bypass; any newer target/control assessment invalidates
approval; proposal lifetime is 24 hours from creation; approval revocation only, no proposer
withdrawal. Principal identity is the full verified issuer/subject pair.

The first action only enables regional EBS encryption by default. It never disables encryption,
changes the default KMS key, encrypts existing volumes or executes arbitrary AWS/shell input.
Bind exact persisted target, versions/checksums, evidence and KMS context to a proposal digest.
KMS completeness is a remediation prerequisite, not a change to EC2-004 assessment semantics.

## Risks and required validation

Later writes need a separate narrowly scoped credential source/process, disabled by default,
with no scanner fallback or scanner access to the writer role. Proposed permissions are STS
identity verification, the two EBS-default read actions and EnableEbsEncryptionByDefault only.
The AWS action needs Resource *; endpoint Region and explicit account allowlists are essential.
Its API has no conditional version or client token. Fresh precondition reads, durable intent,
bounded uncertain-outcome reconciliation, target exclusivity and rescan verification must be
planned before any execution. No automatic rollback or blind replay.

Human review must cover future-volume/workload and KMS compatibility; existing volumes remain
unchanged. Three IdP principals cannot alone prove three different physical people. No live
IdP/AWS/production validation is authorized. Use signed controlled-issuer identities and fake
AWS clients; never weaken fixed development authentication to bypass separation.

8A requires targeted security/domain/HTTP tests, migration/history/rollback tests on SQLite and
disposable PostgreSQL, concurrency tests, full Ruff and regression, startup/OpenAPI checks,
current owner documentation and independent review before acceptance. Publication, merge and
exact merged-main CI remain separate gates. Reviewer agents and Git publication are not
authorized by local implementation permission.

## Documentation reconciliation

Correct the persistence document's stale 0003 head and inventory document's outdated claim that
GOV-001 network-tag use is unimplemented. Record PR #52 as the current accepted baseline.
Preserve completed plans' original predictions and historical approval/acceptance receipts.
The [active plan](exec-plans/active/sprint-8.md) records subsequent implementation authorization.
