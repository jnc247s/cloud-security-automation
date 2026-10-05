# Changelog

This project has no tagged releases yet. Until versioned releases begin, accepted sprint merges
record the development history. Sprint state itself is authoritative only in
[ROADMAP.md](ROADMAP.md).

## Unreleased

### Documentation

- Established permanent repository governance, source-of-truth ownership, roadmap transitions,
  architecture, product requirements, API documentation, security policy, threat model,
  execution-plan locations, and an explicit known-limitations register.

### Sprint 7E — 2026-10-05

- Completed whole-Sprint-7 offline acceptance through
  [PR #50](https://github.com/jnc247s/cloud-security-automation/pull/50) at
  `7998e12786b817aa6de3abd63b37d22b5c4a99b6`, with zero unresolved exact-head independent-review
  findings, both green final-head CI runs, guarded ordinary merge and green merged-main CI.
  Acceptance passed 267 focused checks, 2,741 backend tests (287 PostgreSQL, no skips), 130 frontend
  units, 74 Chromium/Firefox journeys and quality/container gates; 40 original multi-tab repetitions
  also passed. Added combined signed-HTTP/browser retained-data, session-clearing, request-budget
  and scoped accessibility evidence. Restored normal Firefox site isolation only in the pinned
  test launcher; ineffective wait experiments were reverted and failed CI was not waived.
- Preserved application/API/auth/schema/dependencies, catalogs/defaults, mappings and migration
  `20261001_0006`. Reconciled README/domain owners, archived the plan with original predictions
  and updated the normative completion/path guard in a separately gated documentary closeout.
  Sprint 7 is COMPLETE; Sprint 8 is NEXT only, not started. Offline/scoped evidence is not live
  Cognito/AWS/MFA/TLS/production validation or formal accessibility certification. No live operation.

### Sprint 7D — 2026-10-04

- Added a client-only exact-scan NIST mapped-subset view with explicit historical release
  selection, separate four-state counts/control coverage, lazy hierarchy/contributor/mapping
  provenance disclosures, strict graph/identity/count validation and bounded escaped text.
  Framework selection/expansion adds no network calls. No score, full-Core/compliance outcome,
  manual attestation or exception-based result rewrite is introduced.
- Preserved API/BFF/session/bearer READ contracts, backend queries, mappings, dependencies,
  defaults and migration `20261001_0006`. Added synthetic/real-browser display, lifecycle,
  security, historical, malformed-response and deterministic scaling coverage. Accepted through
  [PR #48](https://github.com/jnc247s/cloud-security-automation/pull/48) at
  `8f58b2716a726fcefc5d89567b0dff882f7502ea`, with exact-head REVIEW_PASS and zero unresolved
  findings. Both final-head CI runs and merged-main CI passed 2,731 backend tests (283 PostgreSQL,
  no skips), 130 frontend units, 54 Chromium/Firefox journeys and quality/image gates.
  7D is COMPLETE; Sprint 7 remains IN PROGRESS. 7E and later work are not started; no live operation.

### Sprint 7C — 2026-10-04

- Accepted read-only exact-scan investigation through
  [PR #45](https://github.com/jnc247s/cloud-security-automation/pull/45) and
  [test-only CI repair PR #46](https://github.com/jnc247s/cloud-security-automation/pull/46) at
  `f10c450478cce3ec962d2f45d249f57147443c32`, with zero unresolved exact-head review findings,
  both green final-head CI runs, explicit guarded merge approval and green merged-main CI.
  Acceptance passed 2,728 backend tests (283 PostgreSQL, no skips), 54 frontend units,
  32 Chromium/Firefox journeys and quality/image gates; 20 repeated expiry journeys also passed.
- Added on-demand assessment, version/checksum-bound control and historical snapshot/evidence
  detail, known typed source/relationship navigation and separately labeled current findings/
  server-reference-time exception eligibility. Missing evidence remains insufficient; exceptions
  and ACCEPTED_RISK do not rewrite FAIL. Unresolved endpoints and unknown proofs have no inferred links.
- Added an optional exact-scan resource-history filter using the existing unique index and an
  explicit typed GET-only BFF allowlist. Preserved generic services, existing schemas and omitted
  behavior, bearer/READ/session boundaries, dependencies, defaults and migration `20261001_0006`.
  No live IdP/AWS/production work, NIST hierarchy, mutations, remediation or 7D+ implementation.
  Sprint 7 remains IN PROGRESS; 7D/7E remain PLANNED.

### Sprint 7B — 2026-10-04

- Accepted the opt-in authenticated, read-only dashboard shell through
  [PR #43](https://github.com/jnc247s/cloud-security-automation/pull/43) at
  `9ace4e65f15be678d3f05c4b5ef3a9896d4ea187`, after explicit user merge approval,
  exact-head independent REVIEW_PASS with zero unresolved findings, both final-head CI runs
  and green merged-main CI. Main passed all 2,676 tests (277 PostgreSQL, no skips,
  19 existing warnings), 15 frontend units, 14 Chromium/Firefox journeys and quality/image gates.
- Added exact historical scan selection, retained scope/lifecycle and report availability,
  with same-origin server-side OIDC tokens, opaque HttpOnly sessions, CSRF/Origin protection,
  expiry/logout and expected-session/cross-tab invalidation. All reads use the real bearer/READ API.
- Preserved existing API schemas, roles/capabilities, catalogs/profiles/framework artifacts,
  persistence and migration head `20261001_0006`; dashboard enablement remains explicit and
  disabled by default. No live Cognito/MFA/TLS/production validation, investigation/NIST views,
  remediation or 7C+ implementation is included. Sprint 7 itself remains IN PROGRESS.

### Sprint 7A — 2026-10-03

- Accepted exact-scan READ technical-posture reporting through
  [PR #42](https://github.com/jnc247s/cloud-security-automation/pull/42), manually merged at
  `bd639f48095ef63e658abd284ce25c927998c0fb`. Exact-head review passed with zero unresolved
  findings; both branch/PR CI and merged-main CI passed all 2,601 tests, including 277 PostgreSQL
  cases, with no skips and all quality/image gates.
- Added four-state unique assessment counts, explicit control/target coverage, retained
  profile/catalog/control/framework provenance and deduplicated mapped technical context.
  Reports do not evaluate rules, call AWS, write transactions, expose evidence payloads, rewrite
  results through exceptions or claim compliance. Existing APIs, defaults, migrations and
  bearer/capability authorization remain unchanged. This is reporting foundation, not a browser
  client or completion of Sprint 7.

### Sprint 6 — 2026-10-01

- Accepted the versioned assessment foundation and opt-in IAM, EC2, network, and S3 controls
  through slices 6A--6E. The default five-control catalog remains `0.2.1`; cumulative opt-in
  catalog `0.10.0` adds S3-004 after the preceding releases.
- S3-004 merged in pull request #35 at
  `c861713a665669da09d5bc7b5b282b04c16cac1d`. Its merged-main workflow passed on the unchanged
  retry after a transient dependency-download timeout.
- Accepted 6F.1 LOG-002/003 in opt-in catalog `0.11.0` through
  [pull request #37](https://github.com/jnc247s/cloud-security-automation/pull/37), merged at
  `3a053ff396a2c112aa254842cb25730fe3879ecc`. Exact source-bound coverage/integrity proofs and
  strict JSON scalar checks preserve previous catalog behavior. The separately approved
  migration `20261001_0005` retains unresolved regional references without inventing identity;
  complete identities and guarded downgrade remain strict. Merged-main CI passed 2,125 tests,
  including 171 PostgreSQL cases, with no skips, plus quality/image gates.
- Accepted 6F.2 LOG-004 in opt-in `0.12.0` through
  [pull request #38](https://github.com/jnc247s/cloud-security-automation/pull/38), merged at
  `3e5963fc57ca95041618dd0e571b1237892baadf`. Exact same-invocation S3-002 destination composition
  preserves historical/default behavior without new AWS calls, permissions or migrations.
  Local acceptance and merged-main CI passed 2,212 tests, including 201 PostgreSQL cases,
  no skips and all quality/container gates; exact final-head review passed with zero findings.
- Accepted 6G GOV-001 in opt-in `0.13.0` through
  [pull request #39](https://github.com/jnc247s/cloud-security-automation/pull/39), merged at
  `5043f61b384c8c4499710d2033f7636676705deb`. Exact required tags across all 11 canonical families
  use closed profile/source-bound proofs, explicit empty/failed population coverage, and bounded
  private indexes. The approved additive governance category and migration `20261001_0006`
  preserve history, constraints, triggers and guarded downgrade. Local and merged-main gates
  passed 2,491 tests including 238 PostgreSQL cases, no skips; final-head independent review had
  zero unresolved findings. Default/historical catalogs and operator policy remain unchanged.
- Accepted whole-sprint 6H through
  [pull request #40](https://github.com/jnc247s/cloud-security-automation/pull/40), merged at
  `19c4cd10d0e22ca526fb9a6e94af967cc8ff0a97`. Added all-26 combined-control, immutable catalog /
  historical rollforward, every-supported-release restart and real bearer-authenticated generic
  API acceptance on SQLite and disposable PostgreSQL; only AWS is offline. Local and merged-main
  gates passed 2,533 tests, including 252 PostgreSQL cases, no skips and all quality/image gates.
  Exact-head independent review had zero unresolved findings after two LOW documentary fixes.
  No application, migration, default, operator policy, permission or security behavior changed.
- Archived the completed Sprint 6 plan with its original predictions and implemented differences,
  updated README/owners, marked Sprint 6 COMPLETE and promoted Sprint 7 NEXT without implementing it.

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
