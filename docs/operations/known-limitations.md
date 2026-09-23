# Current known limitations

This register records accepted Sprint 0--4 implementation reality and the in-progress Sprint 5
shared evidence-graph foundation. These items are not silently repaired by documentation work.
`ROADMAP.md` owns project status; security consequences belong in `THREAT_MODEL.md`.

## Data and migration integrity

### Guarded populated downgrade from `20260915_0003` — RESOLVED

Revision `20260915_0003` adds the shared source-manifest, source-artifact/outcome, relationship,
and controlled resource-owner/Region provenance boundary. Its predecessor cannot represent any
evidence-graph row or source-manifest identity. It also cannot represent a snapshot whose owner or
Region was admitted only by the new identity-authoritative source evidence rules.

The Alembic environment preflights every online downgrade path that would execute the
`20260915_0003` downgrade. It blocks before any migration step if it finds either category of
incompatible history. The error is sanitized: it reports only the incompatible category and this
runbook, never a scan, resource, source-outcome, relationship, account, artifact, digest, payload,
or connection value. On PostgreSQL, Alembic takes `ACCESS EXCLUSIVE` locks on `scans`,
`scan_scope_manifests`, `resources`, `resource_snapshots`, and all four graph tables before the
check, then holds them through a compatible transition. Offline SQL generation is always blocked
because it cannot inspect retained data.

Before any planned rollback:

1. Stop or quiesce the API and scan workers, and use the current repository checkout so this
   preflight is active.
2. Take and verify a restorable database backup. Preserve that backup outside the database being
   changed.
3. In a non-production rehearsal or explicitly approved maintenance window, use this read-only
   PostgreSQL query to determine compatibility without returning identifiers or evidence:

   ```sql
   SELECT
       EXISTS (
           SELECT 1
           FROM scan_scope_manifests
           WHERE source_manifest_schema_version IS NOT NULL
              OR source_manifest_checksum IS NOT NULL
           UNION ALL SELECT 1 FROM scan_source_contracts
           UNION ALL SELECT 1 FROM source_evidence_artifacts
           UNION ALL SELECT 1 FROM source_evidence_outcomes
           UNION ALL SELECT 1 FROM resource_relationship_observations
       ) AS retained_evidence_graph,
       EXISTS (
           SELECT 1
           FROM resource_snapshots AS rs
           JOIN resources AS r ON r.resource_id = rs.resource_id
           JOIN scans AS s ON s.scan_id = rs.scan_id
           WHERE r.aws_account_id <> s.aws_account_id
              OR r.scope <> rs.scope
              OR (
                   r.scope = 'global'
                   AND (r.region <> 'global' OR rs.region IS NOT NULL)
              )
              OR (
                   r.scope = 'regional'
                   AND (
                       r.region <> rs.region
                       OR (
                           r.service NOT IN ('s3', 'cloudtrail')
                           AND NOT EXISTS (
                               SELECT 1
                               FROM jsonb_array_elements_text(s.requested_regions) AS region(value)
                               WHERE region.value = rs.region
                           )
                       )
                   )
              )
       ) AS snapshots_incompatible_with_previous_guard;
   ```

4. If both values are false, the online Alembic downgrade may use the established migration path.
   The preflight repeats the check while PostgreSQL excludes writers.
5. If either value is true, keep the database at `20260915_0003`. Preserve the history and either
   retain the current schema, restore a known-compatible backup into an isolated environment, or
   design a separate reviewed history-preserving transition.

Never delete graph rows, clear manifest fields, rewrite a resource owner or Region, fabricate
provenance, disable the guard, or stamp around the revision merely to force rollback. No
destructive data-conversion procedure is approved. Passing this preflight does not authorize a
production downgrade; production database mutation still requires explicit human approval.

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

### Explicit profile roll-forward and pending-scan provenance — RESOLVED

`ASSESSMENT_PROFILE_VERSION` now selects the immutable `default` profile definition for new scans
and accepts only numeric `X.Y.Z` values. Existing installations with the original
`REQUIRED_TAGS=Owner,Environment` and `STALE_ACCESS_KEY_DAYS=90` policy can explicitly retain
version `1.0.0`.

Treat a policy-content and version change as one reviewed deployment operation:

1. Identify every policy input being changed. The current environment-controlled inputs are
   `REQUIRED_TAGS` and `STALE_ACCESS_KEY_DAYS`.
2. Choose a new numeric profile version, such as `1.1.0`; do not reuse an identity that has
   already represented different content.
3. Deploy the new policy inputs and `ASSESSMENT_PROFILE_VERSION` together, then create a scan.
4. Verify the new scan reports the intended profile version. Prior scans and assessments continue
   to reference the retained old definition.

Identical content under the same version remains idempotent. Changed content under a stored
version is rejected before scan creation with sanitized HTTP 409 code
`assessment_profile_version_conflict`; the stored profile remains unchanged. Do not edit profile
rows, rewrite historical scan references, generate a version from wall-clock time, or delete
history to force the change.

Pending work is insulated from deployment configuration changes. On normal execution and startup
recovery, the executor loads and checksum-verifies the complete profile referenced by each scan;
it does not reconstruct policy from current settings or choose the latest version. No migration
or destructive recovery is required because the established schema already retains both versions
and their scan/assessment references. Version selection and policy approval remain operator-owned;
the application intentionally does not auto-increment or compare semantic precedence.

### Stable resource ARN can be first-seen data — LOW

Stable resource identity excludes ARN and stores the ARN from its first insert. Each immutable
snapshot stores the ARN actually observed during that scan. If a resource retains its identity
but its ARN changes, use the latest snapshot as current observed state; the top-level resource ARN
may be historical. Define the intended projection before relying on it for mutable-name resources.

## API and authorization

### Single trust domain — MEDIUM

All recognized roles have `READ`, and reads are not restricted by AWS account or tenant claim.
Filters narrow queries but are not authorization. Operate one database/API within one trusted
security organization; this includes normalized source artifacts and relationship topology, even
when a resource owner differs from the verified collection account. Do not expose it as
multi-tenant SaaS without object-level policy and denied-path tests.

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

### Generic graph reads are bounded projections — LOW

The relationship and source-outcome APIs provide authenticated, filterable list/detail reads.
They do not expose arbitrary graph-query syntax, recursive or multi-hop traversal, a standalone
source-contract view, or a standalone artifact list. Clients must compose bounded requests and
must not infer reverse edges or treat an unresolved target reference as an observed resource.

## Collection and execution

### In-process executor only — MEDIUM

Capacity is two workers and 32 outstanding scans per process. Recovery queries persisted
`RUNNING` work at startup and drains the discovered backlog, but there is no periodic recovery,
claim lease, heartbeat, request quota, per-user rate limit, cancellation, timeout, or caller
idempotency key. Multiple API processes can perform duplicate AWS work and have independent
capacity limits.

Run one API process. Before horizontal scaling, implement a durable ownership/lease-capable
executor behind the existing `ScanExecutor` protocol.

### Existing collector response boundaries — RESOLVED

The four accepted Sprint 1 collectors now validate required identities, promoted primitive facts,
nested tags/configuration/permissions, paginator pages, and stable-resource duplicates before
normalization. Known botocore errors become `FAILED`; malformed required evidence becomes a
sanitized `PARTIAL`; and programming defects are not hidden as AWS evidence problems. Malformed
STS identity also fails closed without coercing null fields or printing response material.

### Collector-level partial granularity — LOW

Collection remains all-or-nothing for most Sprint 0--4 collectors. One malformed or inaccessible
item discards that collector's otherwise valid in-memory resources, marks its coverage incomplete,
and leaves independent collectors running. The 5A EC2/EBS, 5B network, 5C IAM, 5D Access
Analyzer, and accepted 5E S3/KMS producers validate, persist, and return source-level
outcomes and artifacts while retaining independently valid sibling facts; no current rule
consumes that new evidence. Each later collector slice must integrate its declared source
manifest atomically, and Sprint 6 must
add separately reviewed result-sensitive rule behavior. Existing graph support is never
permission to reinterpret `PARTIAL` as complete.

The 5F feature branch adds matching per-source CloudTrail behavior through a shared bundle while
preserving the accepted direct and pending pre-5F paths. It remains pending acceptance and merge;
the accepted `main` runtime is still collector-granular for CloudTrail.

### Single-region request model — PLANNED LIMIT

The API accepts one Region. IAM and S3 discovery are account/global-style; security groups are
regional; CloudTrail starts account-wide and enriches in each trail's home Region. Cross-account
assume-role and full multi-region orchestration are not implemented.

## Verification and reproducibility

### Sprint 0–5F HTTP acceptance coverage

The PostgreSQL integration suite contains one authoritative acceptance test that starts with real
development bearer authentication and authorization, drives `POST /api/v1/scans` through the real
service and executor boundaries with only AWS replaced by deterministic fakes, and verifies the
persisted graph through the public read API. Run it against a dedicated disposable PostgreSQL
database with:

```text
python -m pytest tests/integration/test_persistence_postgres.py::test_authenticated_http_scan_persists_and_exposes_sprint_0_to_5f_graph
```

`TEST_DATABASE_URL` must be set as described in the repository test instructions; CI supplies
PostgreSQL 16. This coverage remains an integration regression test, not live-AWS validation.
The 5F branch extends the same authenticated PostgreSQL boundary through CloudTrail source and
relationship readback. The implementation remains pending acceptance until that test and CI pass;
this document does not claim those pending results before the gate runs.

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
