# Changelog

This project has no tagged releases yet. Until versioned releases begin, accepted sprint merges
record the development history. Sprint state itself is authoritative only in
[ROADMAP.md](ROADMAP.md).

## Unreleased

### Documentation

- Established permanent repository governance, source-of-truth ownership, roadmap transitions,
  architecture, product requirements, API documentation, security policy, threat model,
  execution-plan locations, and an explicit known-limitations register.

## Sprint 5 — 2026-09-23

- Added the shared, versioned source-outcome and relationship evidence graph, immutable history,
  generic authenticated read APIs, and Alembic revision `20260915_0003` with guarded rollback.
- Added fact-only EC2/EBS, VPC/network, IAM account/policy, Access Analyzer, S3/referenced-KMS,
  and CloudTrail evidence, with explicit ownership/scope, source uncertainty, provenance, and
  compatible persisted scan intent. All 25 planned control evidence prerequisites are current.
- Completed 5G closure with behavior-preserving target/provenance indexes, deterministic
  operation-count gates, constant PostgreSQL query counts, and the existing authenticated
  HTTP-to-persistence acceptance using offline AWS fakes.
- Closure merged in [pull request #25](https://github.com/jnc247s/cloud-security-automation/pull/25)
  at `ef4543d439ed3a33064c6bcf383db201a94d2881`. Merged-main CI passed all 1,396 tests, including
  20 PostgreSQL integration tests, Ruff, formatting, and the API image build. Independent review
  has no unresolved findings.
- Archived the [completed execution plan](docs/exec-plans/completed/sprint-5.md). No new Sprint 6
  rule, remediation, dashboard, production deployment, or AI functionality was implemented.

## Sprint 4 — 2026-09-05

- Added OIDC/JWT and explicitly constrained development authentication.
- Added role/capability authorization and authenticated `/api/v1` services for scans, resources,
  history, assessments, findings, controls, frameworks, and exceptions.
- Added durable HTTP 202 scan creation and a bounded, recoverable in-process `ScanExecutor`.
- Added the pending-scan migration and API, service, authentication, authorization, migration,
  and PostgreSQL coverage.
- Merged by pull request #5 at `1e190720c5c33a4edfc1cebe44c652e2ee17424f`.

## Sprint 3 — 2026-09-04

- Added Alembic-managed historical persistence for scans, scope, resources/snapshots,
  assessments, evidence, findings/occurrences, exceptions, and audit events.
- Added version/content integrity, finding reconciliation, transactional governance operations,
  and PostgreSQL integration tests.
- Merged by pull request #4 at `d9cda921911ae2cb476d5f3a0f03bcf051cf4edf`.

## Sprint 2.1 — 2026-09-03

- Added four-state assessment contracts, immutable evidence provenance, versioned organization
  profiles, technical control contracts, and validated NIST CSF 2.0 mappings.
- Reserved canonical S3 identifiers and moved legacy encryption behavior to `S3-900` before
  persistence.
- Merged by pull request #3 at `f2c884c2590a17f5608c62d90f5e50f2ceb6e46c`.

## Sprint 2 — 2026-09-02

- Added the deterministic, side-effect-free security rule engine and the initial five technical
  checks with offline tests.
- Merged by pull request #2 at `97549451c730b112965b213bc472aa59e5808af9`.

## Sprint 1 — 2026-09-02

- Added standard-chain AWS sessions/clients, STS identity, fact-only IAM, security-group, S3, and
  CloudTrail collectors, normalized inventory, CLI operation, and faked collector tests.
- Merged by pull request #1 at `529c41c5589a44fcbbb7ac9b8d7817441f7a1904`.

## Sprint 0 — 2026-09-02

- Established the FastAPI, configuration, SQLAlchemy/PostgreSQL, Docker Compose, pytest, Ruff,
  GitHub Actions, documentation, and Git repository foundation.
- Initial commit: `b1560ff1d3f54371014cc98a1a30a708e6528d11`.
