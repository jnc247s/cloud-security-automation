# Known limitations after Sprint 4

This register records accepted implementation reality discovered during the 2026-09-05
governance audit. These items were not silently repaired by documentation work. `ROADMAP.md`
identifies the items that require pre-Sprint 5 triage; security consequences belong in
`THREAT_MODEL.md`.

## Data and migration integrity

### Guarded populated downgrade from `20260904_0002` — RESOLVED

Sprint 4 intentionally allows a `RUNNING` scan, and an early `FAILED` scan, to retain null
`aws_account_id` or `inventory_sha256` when AWS identity or inventory was never available. The
accepted `20260904_0002` downgrade restores those columns to `NOT NULL`; the older schema cannot
represent such legitimate history.

The current Alembic environment now preflights every online downgrade path that would execute the
`20260904_0002` downgrade. It checks all scan statuses and blocks before any migration step when
either legacy-required value is null. The error is intentionally sanitized: it reports the
incompatibility and this runbook, but no scan ID, account ID, digest, row contents, or connection
details. The revision, schema, constraints, triggers, and retained rows remain unchanged. On
PostgreSQL, Alembic takes an `ACCESS EXCLUSIVE` lock on `scans` before the check and holds it
through the established `ALTER COLUMN` operations, so a concurrent writer cannot invalidate the
decision. Offline SQL generation across this boundary is blocked because it cannot inspect data.

Before any planned rollback:

1. Stop or quiesce the API and scan workers, and use the current repository checkout so this
   preflight is active.
2. Take and verify a restorable database backup. Preserve that backup outside the database being
   changed.
3. In a non-production rehearsal or explicitly approved maintenance window, use this read-only
   query to identify incompatible history without returning identity or digest values:

   ```sql
   SELECT
       scan_id,
       status,
       started_at,
       completed_at,
       aws_account_id IS NULL AS missing_aws_account_id,
       inventory_sha256 IS NULL AS missing_inventory_sha256
   FROM scans
   WHERE aws_account_id IS NULL OR inventory_sha256 IS NULL
   ORDER BY started_at, scan_id;
   ```

4. If the query returns no rows, the online Alembic downgrade may use the established migration
   path. The preflight repeats the check while PostgreSQL excludes writers.
5. If rows are returned, keep the database at `20260904_0002`. A `RUNNING` scan may be allowed to
   finish normally and then be rechecked. For permanent incompatible history, either retain the
   current schema, restore a known-compatible backup into an isolated environment, or design a
   separate reviewed history-preserving transition.

Never fabricate AWS identity or inventory digests, rewrite a terminal scan, delete failed scan or
audit history, disable the guard, or stamp around the revision merely to force rollback. No
destructive data-conversion procedure is currently approved or documented.

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

### Sprint 0–4 HTTP acceptance coverage

The PostgreSQL integration suite contains one authoritative acceptance test that starts with real
development bearer authentication and authorization, drives `POST /api/v1/scans` through the real
service and executor boundaries with only AWS replaced by deterministic fakes, and verifies the
persisted graph through the public read API. Run it against a dedicated disposable PostgreSQL
database with:

```text
python -m pytest tests/integration/test_persistence_postgres.py::test_authenticated_http_scan_persists_and_exposes_sprint_0_to_4_graph
```

`TEST_DATABASE_URL` must be set as described in the repository test instructions; CI supplies
PostgreSQL 16. This coverage remains an integration regression test, not live-AWS validation.

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
