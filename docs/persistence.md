# Persistence and assessment history

Sprint 3 established durable history for already-collected and already-assessed results. The persistence
boundary does not call AWS, run controls, schedule scans, or commit transactions on behalf of its
caller. The inventory command still prints a summary only; it does not persist anything.

The five existing controls and their AWS permissions are unchanged. `S3-900` remains the legacy
explicit-encryption-configuration prototype, not a new production encryption or public-exposure
control. The technical meanings documented in the [control catalog](controls/catalog.md) and
[Assessment framework](assessment-framework.md) still apply.

## Stable identity and historical state

| Record | Responsibility |
| --- | --- |
| `Resource` | Stable AWS identity: provider, account, service, resource type, scope, region, and AWS resource ID. |
| `ResourceSnapshot` | One scan's observed ARN, name, region, tags, normalized configuration, observation time, and state digest. |
| `Scan` and `ScanScopeManifest` | Run identity, timestamps, scanner/input versions, declared scope, and actual collection coverage. |
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
identity and authenticated start audit before submitting AWS work. Collection and assessment run
without an open database transaction; `persist_scan_result` then locks and verifies that exact
pending row, records all immutable children, and terminalizes it atomically. Direct callers can
still persist an already finished bundle in one transaction as before.

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

Evidence remains structured JSONB in PostgreSQL, with a portable JSON representation in SQLite
tests. Every artifact retains its payload digest, collector, source API, schema/version,
collection time, scan, resource snapshot, assessment, and control version. Composite foreign keys
prevent an artifact or finding occurrence from being attached to an unrelated scan, resource, or
control. `PASS`, `FAIL`, `INSUFFICIENT_EVIDENCE`, and `NOT_APPLICABLE` are stored separately;
missing evidence never becomes `PASS`.

NIST mappings remain reporting metadata parallel to technical evaluation. Persisting a mapping
does not make a passing technical check proof of organization-wide CSF compliance.

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

The initial canonical revision is `20260903_0001`. All schema changes belong in reviewed Alembic
revisions; application startup does not call `metadata.create_all()`.

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

Do not downgrade a populated Sprint 4 database until the known `20260904_0002` early-failure issue
has a reviewed rollback plan. A legitimate `FAILED` scan may have null AWS identity/inventory,
while that downgrade restores `NOT NULL` columns without transforming those rows. See
[Known limitations](operations/known-limitations.md#populated-downgrade-from-20260904_0002--high).

## Tests

Run the default suite and quality checks:

```powershell
python -m pytest
ruff check .
ruff format --check .
```

AWS tests use injected fakes. Database unit tests apply the real Alembic migrations to isolated
SQLite databases and exercise history, provenance, idempotent retries, rollback, four-state
results, finding lifecycle safety, governance, and version-content conflicts. No real AWS account
is required.

PostgreSQL-specific integration tests are in `tests/integration/test_persistence_postgres.py`.
They are skipped unless `TEST_DATABASE_URL` is supplied. Against a dedicated disposable database
they verify empty-database migration upgrade/downgrade and metadata parity, JSONB, timezone-aware
timestamps, append-only audit enforcement, committed pending-scan finalization, early failure
before AWS identity, and concurrent finding/scan deduplication.

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
recoverable in-process scan executor. AWS evidence expansion, additional production controls,
Terraform infrastructure, governance mutation APIs, remediation, dashboards/frontend, and AI
functionality remain outside this sprint.
