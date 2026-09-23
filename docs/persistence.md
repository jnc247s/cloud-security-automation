# Persistence and assessment history

Sprint 3 established durable history for already-collected and already-assessed results. The
Sprint 5 shared foundation extends that history with an optional, versioned evidence graph. The
accepted 5A EC2/EBS, 5B network, 5C IAM, 5D IAM Access Analyzer, 5E S3/referenced-KMS, and 5F
CloudTrail producers supply AWS graph fragments through the same persistence boundary. Slices 5D
through 5F add no schema migration. The persistence boundary does not call AWS, run controls,
schedule scans, or commit transactions on behalf of its caller. The inventory command still
prints a summary only; it does not persist anything.

The five executable controls are unchanged. 5A through 5F add documented read-only evidence calls
but do not register a control. `S3-900` remains the legacy
explicit-encryption-configuration
prototype, not a new production encryption or public-exposure control. The technical meanings
documented in the [control catalog](controls/catalog.md) and
[Assessment framework](assessment-framework.md) still apply.

## Stable identity and historical state

| Record | Responsibility |
| --- | --- |
| `Resource` | Stable AWS identity: provider, account, service, resource type, scope, region, and AWS resource ID. |
| `ResourceSnapshot` | One scan's observed ARN, name, region, tags, normalized configuration, observation time, and state digest. |
| `Scan` and `ScanScopeManifest` | Run identity, timestamps, scanner/input versions, declared scope, and actual collection coverage. |
| `ScanSourceContract`, `SourceEvidenceArtifact`, and `SourceEvidenceOutcome` | The exact source manifest, normalized digest-bound artifacts, and one explicit result for every declared source in a graph-enabled scan. |
| `ResourceRelationshipObservation` | One immutable, directional, per-scan relationship observation with typed resolution and source provenance. |
| `ControlAssessment` and `EvidenceArtifact` | The exact technical result, target snapshot, profile/control versions, structured evidence, and provenance. |
| `Finding` and `FindingOccurrence` | One current operational issue plus the historical failed assessments that produced it. |
| `FindingException` and `AuditEvent` | Time-bounded handling decisions and an append-only record of domain changes. |

Regional resources with the same AWS ID in different regions are distinct identities. Global
resources use the non-null `global` sentinel in the stable identity key so database uniqueness
does not depend on nullable-column behavior. Their observed snapshot region remains `None`.

A new scan inserts a new `ResourceSnapshot`; it never overwrites yesterday's tags or configuration.
The stable resource row is not a "latest configuration" cache. Its ARN is retained as identity
metadata, while each snapshot preserves the ARN actually observed during that scan. A snapshot is
unique for a resource within a scan, and its normalized state carries a SHA-256 digest. Raw AWS
response dictionaries are not copied wholesale into the persistence model.

Account-scoped absence or coverage assessments retain an explicit account-target snapshot so
their evidence and result still have a historical target. This does not mean a collector
discovered an additional AWS resource.

The migrations install database guards that reject updates and deletion of historical records,
including direct SQL changes to snapshots, assessments, evidence, versioned inputs, and audit
events. Terminal scans are immutable. Findings and exceptions retain their explicit mutable
operational lifecycle. These guards are not a claim of tamper-proof storage against a privileged
database administrator who can alter the schema.

## Scan identity and exact scope

`InventoryService.collect()` allocates a UUID before any identity or evidence collection call.
A caller can allocate the ID itself and pass `collect(scan_id=scan_id)`. The resulting
`InventorySnapshot.scan_id` is authoritative: assessment, snapshot, evidence, and database records
refer to that same run. It is no longer a hash-derived substitute for a future scan record.
Resource-snapshot and assessment IDs are deterministic within that scan. Identical facts from a
new scan still belong to a new historical observation.

`ScanScopeManifestInput` records:

- the AWS account;
- requested and successful regions;
- requested services and collectors;
- exactly one `SUCCEEDED`, `FAILED`, or `PARTIAL` outcome for every requested collector;
- resource types and enabled controls; and
- exact assessment-profile and control-catalog identities, versions, and profile checksum.

For a graph-enabled inventory, persistence additionally derives and stores
`source_manifest_schema_version` and `source_manifest_checksum` from the complete declared source
contracts in the validated `EvidenceGraph`. These fields are both null for a graphless scan; one
cannot be present without the other. They are not caller-supplied substitutes for the graph and
completeness is never inferred from whichever outcome rows happen to exist.

The persistence boundary checks that the manifest matches the inventory, profile, catalog, and
assessment targets. Duplicate targets, inconsistent provenance, missing enabled-control results,
and decisive results without successful-collector evidence are rejected.

Coverage determines the stored terminal status:

| Status | Meaning when recording a result bundle |
| --- | --- |
| `COMPLETED` | Every requested region and every requested collector succeeded. |
| `PARTIAL` | Coverage is incomplete, but not every requested collector failed. |
| `FAILED` | Every requested collector is explicitly `FAILED`. |

Sprint 4 uses `RUNNING` as a durable handoff to the scan executor. `ScanService` commits the scan
identity, exact persisted assessment-profile reference, and authenticated start audit before
submitting AWS work. The executor reloads and checksum-verifies that stored profile rather than
reconstructing it from its current environment. Collection and assessment run without an open
database transaction; `persist_scan_result` then locks and verifies that exact pending row,
records all immutable children, and terminalizes it atomically. Direct callers can still persist
an already finished bundle in one transaction as before.

The accepted 5D implementation also treats the pending scan's persisted `requested_services` as
immutable execution intent. A newly created scan includes `access-analyzer` and receives the 5D
collector and resource-type scope. A pre-5D `RUNNING` scan without that marker resumes with the accepted
pre-5D scope instead of silently adding AWS work or failing after collection. Completed pre-5D
graphs remain valid without Analyzer contracts, outcomes, resources, or relationships; no stored
row or source manifest is rewritten.

Accepted 5E similarly uses `kms` in its exact tuple to select the S3/KMS graph while preserving
5D and pre-5D paths. Accepted 5F uses exact tuple
`("access-analyzer", "cloudtrail", "cloudtrail-evidence", "ec2", "iam", "kms", "s3")`.
`cloudtrail-evidence` is execution intent, not an AWS service or permission. It ensures a pre-5F
`RUNNING` scan cannot silently gain selectors, CloudTrail graph contracts, or new API calls; no
existing scan or source manifest is rewritten.

Scope is an explicit caller claim, not something inferred from the absence of findings. A single
inventory invocation region does not prove account-wide or multi-region coverage. Existing S3 and
CloudTrail collection can return resources whose actual region differs from the invocation
region; the declared scope must account for those results. Do not mark unverified regions as
successful or silently drop out-of-scope resources to make a bundle pass validation. Multi-region
orchestration and expanded AWS collection are not part of Sprint 3.

## Versioned inputs and evidence

Each persisted assessment points to the exact technical control version and assessment-profile
version used. The database separately retains:

- stable control IDs and versioned technical contracts;
- complete profile policy inputs and checksums;
- framework versions and their Function → Category → Subcategory hierarchy;
- mapping rationale, source, source version, verification time, and checksum; and
- source-manifest retrieval time and digest.

Reusing an existing profile or catalog version with different content raises a version-content
conflict. Introduce a reviewed new version instead of editing historical inputs. Older findings
and assessments therefore remain explainable after policy or mapping changes. The scan also
stores the normalized-inventory digest used by evaluation, while each candidate is bound to that
digest and the canonical full-catalog digest before persistence accepts it.

For the default API profile, `ASSESSMENT_PROFILE_VERSION` is an explicit, validated numeric
`X.Y.Z` selector with a backward-compatible default of `1.0.0`. The same content and version can
be ensured repeatedly. When policy content
changes, the operator must roll forward to a new version; both definitions coexist and new scans
reference the new one while earlier scans and assessments retain their old references. A pending
scan always loads its own persisted definition—even after a configuration change and executor
restart—and never uses a query for the latest profile. No schema migration is needed for this
workflow because the existing model already stores complete profile content, unique identity,
checksums, and scan/assessment relationships.

Evidence remains structured JSONB in PostgreSQL, with a portable JSON representation in SQLite
tests. Every artifact retains its payload digest, collector, source API, schema/version,
collection time, scan, resource snapshot, assessment, and control version. Composite foreign keys
prevent an artifact or finding occurrence from being attached to an unrelated scan, resource, or
control. `PASS`, `FAIL`, `INSUFFICIENT_EVIDENCE`, and `NOT_APPLICABLE` are stored separately;
missing evidence never becomes `PASS`.

NIST mappings remain reporting metadata parallel to technical evaluation. Persisting a mapping
does not make a passing technical check proof of organization-wide CSF compliance.

### Source manifests, outcomes, artifacts, and relationships

The Sprint 5 shared foundation implements the
[result-sensitive source-outcome contract](design-decisions/0002-result-sensitive-evidence-outcomes.md)
and [generic relationship contract](design-decisions/0001-generic-resource-relationships.md) as an
optional `EvidenceGraph` on `InventorySnapshot`. A graph is bound to one scan ID, verified
collection account, and collection timestamp. Graphless Sprint 0--4 snapshots preserve their
existing serialized shape, digest behavior, persistence behavior, and null source-manifest
fields.

A graph-enabled scan persists four append-only record families:

- `ScanSourceContract` records every source promised for the execution, including contract
  key/version, discovery or enrichment subject, evidence kind, collector/API version, cardinality,
  and the controlled owner and supplemental-Region admission flags.
- `SourceEvidenceArtifact` stores one immutable normalized JSON object identified by its scan and
  `normalized://` reference. Its artifact ID is recomputed from the scan and reference, and its
  SHA-256 digest is recomputed from the canonical payload; sensitive key names, non-finite values,
  and non-JSON values are rejected.
- `SourceEvidenceOutcome` records exactly one controlled state and optional failure category for
  one declared source. It binds the declaration, subject, artifact ID, reference, digest,
  collector/API provenance, and collection time without retaining raw provider exceptions.
- `ResourceRelationshipObservation` stores one directional observation with a stable logical
  `relationship_id`, a per-scan `observation_id`, controlled endpoint types and resolution,
  collection-account attribution, and provenance tied to one `PRESENT` source outcome.

Validation requires a non-empty set of contracts, artifacts, and outcomes whenever a graph is
present. Every contract has exactly one outcome; every outcome resolves to an exact digest-bound
artifact; every artifact is referenced; and all records use the graph's scan, collection account,
and timestamp. A relationship source always references its exact same-scan resource snapshot. A
`RESOLVED` target also references its exact same-scan snapshot. Other typed resolutions may retain
a complete stable target without a snapshot, while `TARGET_IDENTITY_INCOMPLETE` uses only a
deterministic unresolved reference. No unresolved reference creates a placeholder `Resource`.

`persist_scan_result` validates and writes the graph, stable resources, snapshots, assessments,
evidence, findings, scope, and audit history inside the caller's existing transaction. It folds
the graph into both the inventory digest and idempotent result checksum. Database foreign keys and
provenance guards bind contracts, artifacts, outcomes, relationships, and snapshots to the same
`RUNNING` scan; append-only guards reject graph updates and deletes; and scan terminalization is
rejected when a graph or manifest is incomplete. Retrying identical content remains idempotent,
while changed graph content under the same scan ID is a conflict.

The verified collection account remains distinct from resource-owner identity. Same-account
resources use the established path. The `aws` sentinel is admitted only for the controlled
AWS-managed IAM policy and policy-version resource types with identity-authoritative `PRESENT`
source evidence. A different 12-digit owner additionally requires exact identity-authoritative
evidence and a resolved same-scan relationship containing that snapshot. A resource outside the
requested Region requires the established S3/CloudTrail exception or an explicit
supplemental-Region source contract with a `PRESENT` outcome. These are closed evidence-admission
rules, not expansion of scan scope or caller authorization.

For the accepted 5D implementation, supplemental discovery is narrower than that general snapshot
admission flag: only the canonical Access Analyzer discovery contracts may claim it, and each
additional Region must be present on an exact same-scan normalized S3 bucket. The Analyzer
artifact also binds the sorted required-Region set and whether the S3 discovery that supplied it
was complete. Graph validation rejects an arbitrary or unproved discovery Region, and persisted
coverage reconstruction keeps the collector incomplete when bucket-Region discovery was not
complete.

The accepted 5E path further closes S3 and KMS admission. A collection-account S3 bucket
represented by the 5E manifest is accepted outside the requested Region only when its exact
same-scan `GetBucketLocation` observation is `PRESENT` and identity-authoritative. A `kms_key`
snapshot requires a `PRESENT`, identity-authoritative `DescribeKey` contract and an exact resolved
same-scan `s3_bucket --encrypted_with--> kms_key` relationship. The returned KMS ARN is the
stable AWS resource ID, and the separately retained collection account never replaces the key's
validated 12-digit owner. These proofs are reconstructed from persisted contracts, outcomes,
artifacts, and relationships rather than from a permissive supplemental-Region flag.

For 5B discovery schemas, a canonical non-empty `unadmitted_resources` list and
`admission_complete = false` are digest-bound operational coverage inputs. They preserve the full
AWS enumeration and its truthful source state while making the collector's `PARTIAL` projection
reconstructable after persistence. Graph writes and reads validate that reconstructed result
against the stored scope-manifest collector outcome. They also require the exact versioned
discovery-source set for every integrated graph collector and reject graph sources whose
operational collector was omitted from the requested scope or outcome map. Accepted 5A history
with a legacy graphless `security_groups` outcome remains readable.

Authenticated generic services and API projections can list/read relationship observations and
source outcomes; outcome detail includes its normalized artifact. Source contracts have no direct
public route, and artifacts have no standalone route. The accepted 5A EC2/EBS, 5B network, and 5C
IAM producers emit source and relationship history through this boundary. The accepted 5D
producer uses the same tables for Regional analyzer/finding source evidence, normalized
`access_analyzer_finding` snapshots, and finding-to-S3 `references_resource` observations.
Analyzer summaries remain artifacts rather than top-level resources, and the normalized AWS
finding resource is not a control-plane `Finding`. Accepted 5E adds direct S3 source
history, `kms_key` snapshots, and bucket-to-key `encrypted_with` observations without a schema
migration or service-specific table. The accepted 5F implementation reuses these tables
for `cloudtrail.trails.discovery`; per-trail `identity`, `configuration`, `status`,
`event-selectors`, and `tags` source families; and CloudTrail-to-S3/KMS relationships. An
external-owner organization trail remains only in its
digest-bound source artifact and is omitted from both 5F resource projections with incomplete
coverage unless it satisfies the existing exact resource-admission proof. Remaining legacy
collectors remain graphless. No current technical
result consumes the Sprint 5 graph.

The planned [S3-002 approval artifact](controls/s3-002-exposure-aggregation.md) and
[S3-004 classifier](controls/s3-004-sensitive-bucket-classifier.md) each carry their own immutable
ID, schema version, policy version, and content checksum. Before either future rule is enabled,
profile/persistence integration must bind a scan and assessment to the complete selected artifact,
reject changed content under an existing logical version, and retain older artifacts for replay.
Their standalone strict history containers already make version reuse and exact historical
reconstruction testable in memory. Exact bucket entries include account, home Region, ARN/name,
and canonical stable resource ID; persistence must not reduce them to the account-less ARN.
That integration requires a reviewed profile/schema transition; it does not mutate the existing
default profile `1.0.0` or the accepted persisted rows. The standalone contracts are sufficient
for Sprint 5 fact collection because classification and exposure evaluation remain later,
deterministic rule work.

## Finding deduplication and resolution

A deterministic fingerprint combines the account, stable resource identity, control ID, and
region. Repeated failures update one finding and append a `FindingOccurrence` for each failed
assessment instead of creating unlimited duplicate findings.

The canonical finding states are `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `FALSE_POSITIVE`, and
`ACCEPTED_RISK`. Remediation approval and execution states do not belong here.

Reconciliation uses observation time rather than database arrival order. Only an explicit `PASS`
from a `COMPLETED` scan is eligible to resolve a finding. An eligible later failure can reopen a
resolved finding. Older observations remain in history without overriding a newer eligible
technical result. If conflicting `PASS` and `FAIL` observations have the same timestamp, `FAIL`
wins deterministically regardless of arrival order.

The following never resolve an existing finding:

- a resource or control missing from a later result bundle;
- a resource control returning `NOT_APPLICABLE` because no targets were found;
- `INSUFFICIENT_EVIDENCE`;
- failed or partial collection; or
- even an explicit `PASS` when the scan's declared scope is incomplete.

Absence is not evidence of a fix. Sprint 3 does not infer deletion, remediation success, or
resolution from disappearance.

## Exceptions and operational handling

`create_finding_exception` records an approved reason, approver identity, resource/control scope,
creation time, expiry time, and `ACTIVE` status. `expire_exceptions` and `revoke_exception` record
explicit lifecycle changes. They must be invoked by a caller; no background expiry scheduler is
running yet.

`set_finding_disposition` supports operational decisions such as acknowledgment, false-positive
classification, and accepted risk. `ACCEPTED_RISK` requires an active, in-scope, unexpired
exception. `RESOLVED` is not a manual disposition, and a resolved finding can reopen only through
a subsequent technical failure.

Creating, expiring, or revoking an exception does not silently change the finding's disposition.
The exception's validity and the finding's operational status are separate records. Most
importantly, no exception or disposition changes an assessment from `FAIL` to `PASS`, removes
evidence, or rewrites a prior assessment.

Approver and actor IDs on the internal governance functions remain explicit programmatic inputs.
Sprint 4 authenticates API callers and records the verified subject that starts a scan, but it
does not expose governance mutation endpoints yet.

## Transactions and programmatic use

Apply migrations first. Prepare the inventory, exact scope, profile, catalog, and assessments
before opening the write transaction; do not hold a database transaction open while calling AWS.
Capture timezone-aware start and completion times that enclose the snapshot's observation time.

For example, this small caller accepts a prepared bundle and owns commit/rollback:

```python
from collections.abc import Sequence
from datetime import datetime
from importlib.metadata import version
from uuid import UUID

from app.assessment.controls import ControlCatalog
from app.assessment.models import AssessmentCandidate
from app.assessment.profiles import AssessmentProfile
from app.database.persistence import persist_scan_result
from app.database.session import SessionLocal
from app.schemas.inventory import InventorySnapshot
from app.schemas.persistence import ScanScopeManifestInput


def save_assessed_scan(
    snapshot: InventorySnapshot,
    scope: ScanScopeManifestInput,
    profile: AssessmentProfile,
    catalog: ControlCatalog,
    assessments: Sequence[AssessmentCandidate],
    *,
    started_at: datetime,
    completed_at: datetime,
) -> UUID:
    with SessionLocal.begin() as session:
        scan = persist_scan_result(
            session,
            snapshot=snapshot,
            scope=scope,
            profile=profile,
            catalog=catalog,
            assessments=assessments,
            started_at=started_at,
            completed_at=completed_at,
            scanner_version=version("cloud-security-automation"),
            actor_type="system",
            actor_id="local-assessment-caller",
        )
        scan_id = scan.scan_id
    return scan_id
```

Use `build_default_control_catalog()` and `create_default_assessment_profile()` for the existing
reviewed inputs, or supply explicitly versioned organization inputs. Assess with
`RuleEngine(build_default_registry()).assess(snapshot, profile)`. Construct the scope manifest
from the caller's declared intent and confirmed outcomes, not by assuming all requested work
succeeded.

`SessionLocal.begin()` commits only when the entire block succeeds and rolls back on an exception.
The persistence, catalog, and governance helpers may flush but never commit or roll back the
caller's transaction. Do not catch a write error inside the block and then commit partial work.

Retrying an identical scan ID and result bundle is idempotent. Reusing the ID with changed facts,
scope, versions, or timestamps is rejected. A genuinely new observation needs a new scan ID.
Findings, occurrences, evidence, and audit events participate in the same transaction as the scan.

## Audit history

Scan persistence and governance append events such as `SCAN_STARTED`, `SCAN_COMPLETED`,
`FINDING_ACKNOWLEDGED`, `EXCEPTION_CREATED`, and `EXCEPTION_EXPIRED`. Each event stores an actor,
target, timestamp, and structured metadata. The corresponding action and event succeed or roll
back together. Later actions append new records rather than updating an earlier event.

The migration-installed history guards protect audit rows from ordinary updates and deletion.
Audit metadata, evidence, and normalized configurations can still contain sensitive infrastructure
or organizational information; protect database access and backups accordingly.

## Migrations and startup

The initial canonical revision is `20260903_0001`; the current head is `20260915_0003`. All schema
changes belong in reviewed Alembic revisions; application startup does not call
`metadata.create_all()`.

For local Python development, configure `DATABASE_URL` in the environment or local `.env`, then:

```powershell
docker compose up -d db
alembic upgrade head
alembic current
uvicorn app.main:app --reload
```

`alembic check` verifies that model metadata and the migrated database have no pending
autogeneration changes. `/ready` checks database connectivity only; it does not verify that
migrations are current.

`docker compose up --build` starts PostgreSQL, waits for its health check, runs the one-shot
`migrate` service, and starts the API only after `alembic upgrade head` succeeds. Inspect
`docker compose logs migrate` if startup is blocked by migration failure. The API container does
not receive host AWS credentials by default. `POST /api/v1/scans` exists, but it can collect only
when an appropriate read-only workload credential chain is supplied explicitly.

The PostgreSQL volume survives `docker compose down`. Downgrading to `base` drops the assessment
schema, and `docker compose down --volumes` deletes local database data; neither is a routine
upgrade or troubleshooting step. Back up important data before schema changes.

Revision `20260915_0003` adds the four evidence-graph tables, nullable source-manifest identity on
the scan scope, append-only and provenance guards, and the closed exceptional-owner and
supplemental-Region snapshot admission rules. Its downgrade intentionally removes only an empty,
backward-compatible foundation. Before any downgrade path executes `0003` downgrade DDL, the
Alembic environment blocks if it finds source-manifest metadata, any graph table row, or any
snapshot that the `0002` owner/scope/Region guard cannot represent. PostgreSQL takes exclusive
locks on all inspected parent and graph tables before the check and holds them through the
transition. Offline SQL generation across this boundary always fails closed. See the
[evidence-graph downgrade runbook](operations/known-limitations.md#guarded-populated-downgrade-from-20260915_0003--resolved)
for the compatibility query and safe response to a block.

The accepted `20260904_0002` migration remains unchanged. Before Alembic executes its downgrade,
the migration environment now rejects retained rows with a null `aws_account_id` or
`inventory_sha256`, because the older `NOT NULL` schema cannot represent them safely. The check
runs before any migration step; PostgreSQL excludes concurrent scan writers until the compatible
downgrade transaction completes. Offline SQL generation across this boundary is rejected because
it cannot inspect retained rows. See the
[downgrade recovery runbook](operations/known-limitations.md#guarded-populated-downgrade-from-20260904_0002--resolved)
for the read-only compatibility query, backup expectations, and safe choices after a block.

## Tests

Run the default suite and quality checks:

```powershell
python -m pytest
ruff check .
ruff format --check .
```

AWS tests use injected fakes. Database unit tests apply the real Alembic migrations to isolated
SQLite databases and exercise history, source-manifest and evidence-graph provenance,
idempotent retries, rollback, four-state results, finding lifecycle safety, governance, and
version-content conflicts. Service and authenticated API tests cover bounded source-outcome and
relationship reads. No real AWS account is required.

PostgreSQL-specific integration tests are in `tests/integration/test_persistence_postgres.py`.
They are skipped unless `TEST_DATABASE_URL` is supplied. Against a dedicated disposable database
they verify empty-database migration upgrade/downgrade and metadata parity, JSONB, timezone-aware
timestamps, append-only audit and evidence-graph enforcement, compatible populated downgrades,
blocked incompatible downgrade integrity, immutable assessment-profile roll-forward and conflict
behavior, persisted profile use after executor restart, committed pending-scan finalization,
pre-5D pending-scan and graph readback compatibility, early failure before AWS identity, and
concurrent finding/scan deduplication. The acceptance path uses deterministic fake AWS responses
and now covers the accepted 5E S3/KMS and 5F CloudTrail graphs when
PostgreSQL is configured; it does not contact live AWS.

With the unchanged development username and password from `.env.example`, an example setup is:

```powershell
docker compose up -d db
docker compose exec db createdb -U cloudsec cloudsec_test
$env:TEST_DATABASE_URL = "postgresql+psycopg://cloudsec:change-me@localhost:5432/cloudsec_test"
python -m pytest tests/integration
```

Create the test database once, and adjust the URL for your actual local username, password, and
port. On macOS/Linux, use `export TEST_DATABASE_URL='postgresql+psycopg://...'`. Never use a
production database or credentials here.

The test role needs permission to create and drop its own schemas. Each test creates a unique
`sprint4_test_<uuid>` schema, applies migrations there, and drops only that generated schema during
cleanup; existing schemas are not targeted. CI provides a PostgreSQL test service and sets
`TEST_DATABASE_URL`, so these checks run alongside the offline suite.

## Current boundary and deferred work

Sprint 4 provides authorized read/query services, versioned REST endpoints, and a bounded,
recoverable in-process scan executor. The accepted Sprint 5 foundation adds the optional
evidence-graph domain, transactional persistence, authenticated generic reads, and safe migration
boundary. The accepted 5A producer emits EC2/EBS source outcomes and relationships, and the
accepted 5B producer extends that graph with security groups, VPCs, subnets, and VPC Flow Logs.
The accepted 5C implementation extends the same generic graph with IAM account, identity, policy,
and relationship evidence and requires no schema migration. The accepted 5D implementation
extends that graph with fact-only Access Analyzer evidence, bucket-backed supplemental Regional
coverage, and finding-to-S3 relationships; it also requires no migration. Accepted 5E adds
fact-only direct S3 and referenced-KMS evidence through the same schema. Accepted 5F adds fact-only
CloudTrail graph evidence through that schema and also requires no migration. The 5G closure
remains unstarted. Sprint 6 production controls, Terraform infrastructure, governance mutation
APIs, remediation, dashboards/frontend, and AI functionality remain outside this slice.
