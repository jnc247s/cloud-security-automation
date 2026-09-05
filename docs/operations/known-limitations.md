# Known limitations after Sprint 4

This register records accepted implementation reality discovered during the 2026-09-05
governance audit. These items were not silently repaired by documentation work. `ROADMAP.md`
identifies the items that require pre-Sprint 5 triage; security consequences belong in
`THREAT_MODEL.md`.

## Data and migration integrity

### Populated downgrade from `20260904_0002` — HIGH

Sprint 4 intentionally allows an early `FAILED` scan to retain null `aws_account_id` and
`inventory_sha256` when AWS identity or inventory was never available. The `20260904_0002`
downgrade restores those columns to `NOT NULL` without a backfill or rejection preflight. A
database containing such a legitimate row can therefore fail to downgrade.

Do not run this downgrade against important or populated data until a reviewed rollback strategy
defines whether to preserve, transform, archive, or explicitly block those rows. Existing
round-trip tests exercise empty databases; the forward upgrade from populated Sprint 3 history is
covered.

### Fixed profile version with configurable content — HIGH

Asynchronous scans always construct assessment profile `default` version `1.0.0`.
`REQUIRED_TAGS` and `STALE_ACCESS_KEY_DAYS` alter that profile's checksummed immutable content.
After one version is stored, changing either value against the same database causes the next scan
to conflict with the stored version. There is no runtime profile-version selector or automatic
roll-forward.

For the current baseline, keep those values stable for a persistent database. Before policy
changes, implement and review an explicit new-version/selection workflow; never overwrite the
stored version.

### Stable resource ARN can be first-seen data — LOW

Stable resource identity excludes ARN and stores the ARN from its first insert. Each immutable
snapshot stores the ARN actually observed during that scan. If a resource retains its identity
but its ARN changes, use the latest snapshot as current observed state; the top-level resource ARN
may be historical. Define the intended projection before relying on it for mutable-name resources.

## API and authorization

### Single trust domain — MEDIUM

All recognized roles have `READ`, and reads are not restricted by AWS account or tenant claim.
Filters narrow queries but are not authorization. Operate one database/API within one trusted
security organization; do not expose it as multi-tenant SaaS without object-level policy and
denied-path tests.

### Audit identity context — MEDIUM

The authenticated scan request records `Principal.subject` in `SCAN_STARTED`, but not issuer,
roles, or the capability that authorized the action. Reads and denied authentication/authorization
attempts are not application audit events. Subject uniqueness must currently be enforced by the
deployment's identity-provider policy.

Direct database writes can also bypass governance helper semantics even though history tables are
protected. Restrict application/database roles and use the service/governance functions.

### Exception expiry presentation — MEDIUM

Exception expiry/revocation is an explicit helper operation; no scheduler updates persisted
`ACTIVE` status automatically. Governance checks exclude an exception whose `expires_at` has
passed, but a general list can still show its stored status as `ACTIVE` until expiry processing
runs. Consumers must consider both status and timestamp.

### Offset pagination — LOW

List ordering is deterministic, but `total`, `limit`, and `offset` do not create a frozen database
snapshot. Concurrent writes may shift items between page requests.

## Collection and execution

### In-process executor only — MEDIUM

Capacity is two workers and 32 outstanding scans per process. Recovery queries persisted
`RUNNING` work at startup and drains the discovered backlog, but there is no periodic recovery,
claim lease, heartbeat, request quota, per-user rate limit, cancellation, timeout, or caller
idempotency key. Multiple API processes can perform duplicate AWS work and have independent
capacity limits.

Run one API process. Before horizontal scaling, implement a durable ownership/lease-capable
executor behind the existing `ScanExecutor` protocol.

### Unexpected collector response shapes — MEDIUM

Known botocore errors become `FAILED`; declared evidence-shape failures become `PARTIAL` and leave
other collectors running. Some unexpected `KeyError`, validation, or malformed-shape failures can
escape a collector and fail the whole scan or print a CLI traceback. Sprint 5 collector expansion
must define and test the error boundary for every new AWS response.

### Single-region request model — PLANNED LIMIT

The API accepts one Region. IAM and S3 discovery are account/global-style; security groups are
regional; CloudTrail starts account-wide and enriches in each trail's home Region. Cross-account
assume-role and full multi-region orchestration are not implemented.

## Verification and reproducibility

### Fragmented acceptance coverage — MEDIUM

API, service, executor, collectors, rules, persistence, authentication, authorization, migrations,
and PostgreSQL behavior have focused tests. There is no single acceptance test that starts with an
authenticated HTTP `POST /api/v1/scans`, runs the executor with fake AWS, persists the result, and
queries scans/resources/assessments/findings. Add that acceptance boundary without using a real AWS
account before completing Sprint 5.

### Build provenance and dependency reproducibility — LOW

Persisted `scanner_version` is package version `0.1.0`; no Git/build identifier distinguishes
different commits with that version. Dependencies use bounded ranges, GitHub Actions use major
tags, and no lockfile/SBOM exists. CI currently proves lint, format, full tests with PostgreSQL 16,
and an image build—not reproducible supply-chain provenance or comprehensive security scanning.

### Equal observation timestamps — LOW

The latest resource snapshot projection chooses the maximum `observed_at`. Exact timestamp ties do
not add an explicit snapshot-ID tie-breaker, so relationship load order can decide which tied
snapshot is shown as latest.

## Deferred by design

There is no dashboard, production Terraform deployment, governance mutation API, remediation,
distributed worker, multi-account orchestration, or AI runtime. Their absence is roadmap scope,
not an incomplete Sprint 4 implementation.
