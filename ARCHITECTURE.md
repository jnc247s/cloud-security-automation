# Architecture

This document describes the accepted implementation after Sprint 4. It documents repository
reality; later roadmap components are not presented as implemented.

## System context

```text
AWS environment
    -> standard AWS credential chain and STS identity
    -> fact-only boto3 collectors
    -> normalized InventorySnapshot
    -> deterministic rules + versioned AssessmentProfile
    -> ControlAssessment candidates + structured EvidenceArtifacts
    -> transactional PostgreSQL persistence
    -> query and scan services
    -> authentication + capability authorization
    -> FastAPI /api/v1
    -> trusted CLI, dashboard, integration, or future tool adapter

versioned NIST CSF catalog
    -> ControlFrameworkMapping metadata
    -> reporting context only
```

The NIST path is parallel to technical evaluation. A framework mapping cannot set severity or
change a technical result. The application performs NIST CSF 2.0-aligned AWS technical security
assessment; it does not certify organization-wide NIST compliance.

## Component boundaries

| Component | Responsibility | Must not do |
| --- | --- | --- |
| `app/aws/` | Lazy boto3 session/client access, timeouts/retries, cached STS identity | Store static credentials or make security decisions |
| `app/collectors/` | Collect and normalize AWS facts | Assign severity, PASS/FAIL, NIST status, findings, or remediation |
| `InventoryService` | Run independent collectors and build a deterministic snapshot | Persist or evaluate controls |
| `app/rules/` | Evaluate normalized evidence against technical contracts | Call AWS, persist data, or use framework mappings as policy |
| `app/assessment/` | Four-state result, evidence, profile, control, and framework contracts | Claim full framework compliance |
| `app/database/` and `app/models/` | Validate and persist versioned history in caller-owned transactions | Call AWS or hide partial scope |
| `app/services/` | Own query projections and scan transaction/orchestration boundaries | Put HTTP concerns into domain logic |
| `app/security/` | Normalize a verified `Principal` and enforce capability policy | Issue tokens or store passwords |
| `app/api/` | Validate HTTP input and delegate to services | Contain core scanning or persistence logic |

## Scan execution

```text
POST /api/v1/scans (EXECUTE)
    -> ScanService validates and persists the configured immutable profile version
    -> creates RUNNING scan referencing that exact profile + SCAN_STARTED audit event
    -> transaction commits durable scan ID
    -> ScanExecutor.submit(scan_id)
    -> HTTP 202 response

InProcessScanExecutor worker
    -> reload RUNNING scan
    -> load and checksum-verify the exact persisted profile referenced by that scan
    -> build region-bound AWS provider
    -> InventoryService.collect(scan_id)
    -> RuleEngine.assess(snapshot, profile)
    -> build exact scope manifest
    -> persist_scan_result in one transaction
    -> COMPLETED, PARTIAL, or FAILED + audit

unhandled execution failure
    -> fail_pending_scan in a separate transaction
    -> FAILED + sanitized failure metadata + audit
```

The accepted executor is a replaceable protocol backed by a two-worker, 32-outstanding in-process
thread pool. The production application resubmits persisted `RUNNING` scans once at startup and
drains a bounded backlog. It waits for accepted work during graceful shutdown. It is not a
distributed queue: run one API process, and replace the adapter before horizontal or multi-process
execution.

Configuration selects the profile used only when a new scan is created. The executor never
reconstructs policy for a pending scan from current environment settings and never selects a
"latest" profile. Startup recovery therefore evaluates a retained `RUNNING` scan with the exact
policy accepted at creation, even when a deployment has since rolled forward to another profile
version. Missing, malformed, or checksum-inconsistent stored provenance fails closed before AWS
collection.

The executor currently scans one requested Region while collecting regional and global-style
services through the Sprint 1 collectors. Formal multi-region/global execution is Sprint 5 scope.

## Persistence and history

`Resource` is deterministic stable identity. `ResourceSnapshot` is immutable state observed in one
scan. Assessments, evidence, finding occurrences, exact profile/control/framework versions, scan
scope, collection outcomes, exceptions, and audit events are retained separately. Repeated failed
assessments reuse a deterministic finding fingerprint and append occurrences. Only an explicit
later `PASS` from complete coverage can resolve a finding; missing resources, partial scans,
`NOT_APPLICABLE`, and `INSUFFICIENT_EVIDENCE` cannot.

The database transaction boundary never spans AWS calls. Alembic owns schema evolution; startup
does not call `metadata.create_all()`. Revisions are linear:

```text
20260903_0001  canonical assessment history
    -> 20260904_0002  pending scan before AWS identity/inventory
```

The established revisions remain unchanged. The Alembic execution environment preflights any
downgrade path that crosses `20260904_0002` before running a migration step. It blocks when
retained scan history cannot satisfy the older identity/digest `NOT NULL` contract; PostgreSQL
holds an exclusive table lock from that decision through the DDL. See `docs/persistence.md` for
the complete model and operator runbook.

Assessment-profile roll-forward uses the existing immutable profile table and scan foreign-key
contract; it requires no new migration. A `(profile_id, version)` pair names exactly one policy
definition. New content requires an operator-selected new numeric version, while old profiles,
scans, and assessments remain unchanged.

## Authentication and authorization

All `/api/v1` routes use HTTP bearer authentication. Production mode verifies a signed OIDC JWT
against configured JWKS, issuer, audience, expiration, subject, asymmetric algorithm allowlist,
and roles claim. Development mode accepts only the documented local marker and is rejected unless
`APP_ENV` explicitly names a local/development/test environment. Production configuration fails
closed unless OIDC is complete.

The normalized principal contains subject, issuer, and roles. Roles map to capabilities:

```text
VIEWER    -> READ
ANALYST   -> READ, PROPOSE
APPROVER  -> READ, PROPOSE, APPROVE
ADMIN     -> READ, PROPOSE, APPROVE, EXECUTE
```

Current read routes require `READ`; scan creation requires `EXECUTE`, so only `ADMIN` can start a
scan. No governance or remediation mutation routes exist. Authorization is control-plane-wide,
not tenant/account-scoped; see `THREAT_MODEL.md`.

## API boundary

Health and readiness remain unversioned and unauthenticated. The authenticated interface lives at
`/api/v1` and exposes scans, resources/history, assessments/evidence, findings/occurrences,
controls, frameworks/mappings, and exceptions. Routes delegate to `ScanService`,
`ResourceService`, `AssessmentService`, `FindingService`, `ControlService`, `FrameworkService`,
and `ExceptionService`. `AuditService` exists as a service abstraction but has no public route.

`docs/api.md` is the authoritative interface document. Future clients must use services/API data,
not direct database access.

## Runtime and deployment

Local Compose starts PostgreSQL 16, runs `alembic upgrade head` as a one-shot service, then starts
one API process. API and database ports bind to loopback by default. `/ready` verifies database
connectivity with `SELECT 1`; it does not verify migration head. Compose does not mount host AWS
credentials. Production TLS, ingress, identity provider, secret storage, database backups, and
workload-role configuration remain deployment responsibilities.

## Accepted limitations

- No tenant/account object authorization, request rate limiting, scan cancellation, timeout, or
  caller idempotency key.
- Startup-only pending-scan recovery and no multi-process claim/lease protocol.
- Scan audit attribution stores subject but not issuer, roles, or authorizing capability.
- Stable `Resource.arn` is first-seen data; each snapshot carries the actually observed ARN.
- No frontend, Terraform deployment, remediation, or AI runtime.

Operational detail and required follow-up are recorded in
`docs/operations/known-limitations.md` and `ROADMAP.md`.
