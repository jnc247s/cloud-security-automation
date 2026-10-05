# Current known limitations

This register records accepted Sprints 0--7 implementation reality, including
the shared evidence graph, evidence producers, and opt-in production controls. These items are
not silently repaired by documentation work.
Whole-sprint 6H acceptance did not remove these limitations or authorize production operations;
Sprint 7 is COMPLETE: 7A READ reporting is accepted through PR #42, with zero unresolved
independent-review findings and green merged-main CI. The opt-in 7B browser/session shell is
accepted through PR #43; 7C is accepted through PR #45/46 and 7D through PR #48 with the same
review/CI gates. 7E is accepted through PR #50 with exact-head review and green main CI; its
tests/documentation and Firefox test-launch repair remove none of these application limits.
Its [evidence matrix](../sprint-7e-acceptance.md) records unverified accessibility
and live-provider/production coverage explicitly.
See [dashboard operation](dashboard.md),
[6H acceptance](../controls/sprint-6h-acceptance.md) and the
[completed Sprint 7 plan](../exec-plans/completed/sprint-7.md).
`ROADMAP.md` owns project status; security consequences belong in `THREAT_MODEL.md`.

Accepted 7C provides read-only exact-scan investigation. Its bounded lists and display
limits do not bound existing resource-history hydration or unpaginated finding detail payloads.
Current operational pages can drift; server response time labels exception eligibility at that
read, not historic/atomic coverage. Unknown proof schemas are raw evidence without inferred links,
and unresolved endpoints remain references. Display truncation is not full evidence review.
Accepted 7D NIST hierarchy reports only exact retained
mapped technical context, not the full CSF Core or a compliance result. Display validation does
not certify unseen source bytes or bound upstream report size. Account/tenant isolation and
live provider/production validation remain absent.

## Data and migration integrity

### Governance category transition — ACCEPTED 6G

Revision `20261001_0006` adds only `governance` to the existing control-version category CHECK.
Before an explicitly authorized rollback across that boundary, quiesce writers, verify a
restorable backup and use the current online Alembic environment. PostgreSQL takes the parent
control-version exclusive lock; SQLite reserves the writer. The guard checks the entire downgrade
path before DDL and refuses category history the predecessor cannot represent. This read-only
diagnostic reports only compatibility:

```sql
SELECT EXISTS (
    SELECT 1 FROM control_versions WHERE category = 'governance'
) AS incompatible_governance_history;
```

If true, remain at the current revision; do not delete or recategorize immutable history or
bypass the guard. Offline downgrades crossing this boundary are blocked. SQLite retains FK
enforcement and requires an online checked transactional rebuild; PostgreSQL changes only the
CHECK. This code work authorizes no production migration or rollback. See
[6G metadata](../controls/sprint-6g-metadata.md).

### Unresolved regional relationship persistence — REPAIRED

6F.1 acceptance testing on 2026-10-01 exposed an accepted-baseline discrepancy: the relationship
domain and CloudTrail collector permit an unresolved regional S3 destination reference with no
known owner or Region, but the database scope/Region constraint requires a Region for every
regional target, including unresolved references. Persistence rolls back; real HTTP scan
execution reports sanitized `SCAN_EXECUTION_FAILED`. This is not a LOG-002/003 decision
dependency and must not be hidden by fabricating a Region or dropping retained relationships.
The user separately approved the bounded repair. Local revision `20261001_0005` now permits
null Regions only for unresolved references, retaining all existing complete-identity,
provenance and immutable-history rules. Original migrations, collector and mapper are unchanged.
6F.1 acceptance and PR #37 merge are complete at accepted main
`3a053ff396a2c112aa254842cb25730fe3879ecc`; merged-main CI passed. This discrepancy is repaired.
The operational downgrade safety requirements below remain applicable.

Before any authorized downgrade across `20261001_0005`, stop/quiesce writers, take and verify
a restorable backup, and use the current Alembic environment. It checks compatibility before
any DDL, taking PostgreSQL graph locks in parent-to-child order or a SQLite reserved writer lock.
This read-only diagnostic returns only whether incompatible history exists:

```sql
SELECT EXISTS (
    SELECT 1 FROM resource_relationship_observations
    WHERE target_scope = 'regional' AND target_region IS NULL
) AS incompatible_relationship_history;
```

If true, remain at this revision. Do not delete observations, invent identity fields or bypass
the guard. Offline downgrade generation is blocked; SQLite constraint repair must run online.
Compatible populated downgrades and re-upgrades preserve history and triggers. Production
migration/rollback still requires explicit human authorization. See
[6F.1 checkpoint](../controls/sprint-6f1-metadata.md#acceptance-blocker--2026-10-01).

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
outcomes and artifacts while retaining independently valid sibling facts. Accepted opt-in
Sprint 6 controls consume only their explicitly versioned source and relationship proofs;
unrelated failures do not waive a required source, and graph support is never permission to
reinterpret `PARTIAL` as complete.

Accepted 5F adds matching per-source CloudTrail behavior through a shared bundle while preserving
the accepted direct and pending pre-5F paths. It was merged in pull request 24 at `main` commit
`29aeea59b9cceff957adac4fba75cb8ca2c4a592`; Sprint 5 is `COMPLETE`, its 5G closure was
accepted in pull request 25, and the accepted controls through 6E preserve these fail-closed
source boundaries. LOG-002/003 and LOG-004 are accepted through 6F.1 and 6F.2 in opt-in catalogs
`0.11.0` and `0.12.0`; see [6F.1 metadata](../controls/sprint-6f1-metadata.md) and
[6F.2 metadata](../controls/sprint-6f2-metadata.md). Their acceptance does not change the
collector-granularity limitation above.

### Single-region request model — PLANNED LIMIT

The API accepts one Region. IAM and S3 discovery are account/global-style; security groups are
regional; CloudTrail starts account-wide and enriches in each trail's home Region. Cross-account
assume-role and full multi-region orchestration are not implemented.

## Verification and reproducibility

### Assessment foundation downgrade

Migration `20260924_0004` adds extended profile, policy artifact, and execution-contract storage.
An online downgrade crossing this revision is blocked before any DDL if retained profiles have
extension content, artifact registry entries exist, control versions have execution metadata, or
Regional account-setting resources exist. The error is sanitized; no incompatible history is
rewritten or deleted. PostgreSQL holds exclusive locks through the check and transition. SQLite
reserves its writer lock and keeps the transition in a transaction. Offline downgrade across this
boundary is rejected because retained data cannot be checked.

During an authorized maintenance window, stop writers and take a verified restorable backup of
the database, including exact profile/catalog/artifact history. Inspect incompatible identities
using read-only queries (results are sensitive security metadata):

```sql
SELECT profile_id, version FROM assessment_profiles
WHERE schema_version IS NOT NULL OR policy_extensions IS NOT NULL;
SELECT artifact_kind, artifact_id, version FROM assessment_policy_artifacts;
SELECT control_version_id FROM control_versions WHERE execution_contract IS NOT NULL;
SELECT resource_id FROM resources WHERE resource_type = 'aws_account' AND scope = 'regional';
```

Safe choices are to retain the current schema with a compatible application release, roll forward
with a reviewed repair, or evaluate a verified pre-transition backup in a separate isolated
environment without discarding current history. A compatible legacy-only database may follow the
tested Alembic downgrade path. Do not fabricate policy values, strip metadata, delete failed scans,
disable history guards, or stamp revisions merely to force rollback. This is not permission to
mutate production or overwrite a live database from backup.

### Current HTTP acceptance coverage

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
Accepted 5F extends the same authenticated PostgreSQL boundary through CloudTrail source and
relationship readback. Subsequent Sprint 6 slices preserve real authentication, execution,
persistence and public reads while replacing only AWS with deterministic offline fakes. Accepted
6E.3 validation passed 1,957 tests including 122 PostgreSQL integration cases, and its merged-main
CI passed the complete workflow. This does not remove the operational limitations documented here
or authorize live AWS mutation.

### Build provenance and dependency reproducibility — LOW

Persisted `scanner_version` is package version `0.1.0`; no Git/build identifier distinguishes
different commits with that version. Most backend dependencies use bounded ranges, GitHub Actions use major
tags, and no backend lockfile/SBOM exists. Accepted 7B adds exact frontend dependencies and a
lockfile plus pinned Node/pnpm; it does not make the entire supply chain reproducible. Accepted
CI proves lint, format, full tests with PostgreSQL 16 and an image build. Accepted 7B
adds frontend and real browser gates in [PR #43](https://github.com/jnc247s/cloud-security-automation/pull/43);
both exact-head and merged-main CI passed. Neither is comprehensive security
scanning or supply-chain provenance.

### Equal observation timestamps — LOW

The latest resource snapshot projection chooses the maximum `observed_at`. Exact timestamp ties do
not add an explicit snapshot-ID tie-breaker, so relationship load order can decide which tied
snapshot is shown as latest.

## Deferred by design

Accepted 7B/7C/7D provide an opt-in authenticated shell, exact-scan investigation and retained
NIST mapped-subset context; whole-Sprint-7 acceptance remains
separate. Sessions are process-local and lost on restart; no refresh-token retention,
global IdP logout, account/tenant isolation or validated production Cognito tenant is provided.
There is no production Terraform deployment, governance mutation API, remediation,
distributed worker, multi-account orchestration, or AI runtime. Their absence is roadmap scope,
not an incomplete Sprint 4 implementation.
