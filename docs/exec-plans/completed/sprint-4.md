# Sprint 4 — Service Layer, Authentication, Authorization, REST API, and Scan Execution

Status: **COMPLETE**
Accepted merge: `1e190720c5c33a4edfc1cebe44c652e2ee17424f`
Implementation commit: `ce40878b8b53f2b62d75ede9044c08e5892e3186`
Pull request: [#5](https://github.com/jnc247s/cloud-security-automation/pull/5)
Completed: 2026-09-05

This is a retrospective completion record. No Sprint 4 execution-plan file existed in
`docs/exec-plans/active/` to archive when permanent governance was introduced.

## Objective

Create a secure, stable service and HTTP boundary for persisted security-control-plane data and
non-blocking scan execution without adding AWS evidence, controls, remediation, dashboard, or AI
scope.

## Implemented

- Focused `ScanService`, `ResourceService`, `AssessmentService`, `FindingService`,
  `ControlService`, `FrameworkService`, `ExceptionService`, and `AuditService` boundaries.
- OIDC/JWT authentication with verified signature, issuer, audience, expiry, subject, asymmetric
  algorithm allowlist, roles, and a bounded JWKS cache.
- Explicit local development identity rejected outside local/development/test environments.
- `VIEWER`, `ANALYST`, `APPROVER`, and `ADMIN` mapped to `READ`, `PROPOSE`, `APPROVE`, and
  `EXECUTE` capabilities.
- Authenticated `/api/v1` list/detail APIs for scans, resources/history, assessments/evidence,
  findings/occurrences, controls/mappings, frameworks, and exceptions.
- HTTP 202 scan creation that commits a durable identity and audit event before submission.
- Replaceable `ScanExecutor` protocol with a bounded in-process implementation, graceful shutdown,
  startup resubmission, and automatic bounded backlog draining.
- Transactional finalization of pre-created scans and sanitized early terminal failure.
- Alembic revision `20260904_0002` for pending scan identity before AWS evidence is available.
- API/service/authentication/authorization/executor/migration tests, PostgreSQL cases, updated
  Compose settings, and operator/API documentation.

## Accepted request flow

```text
authenticated ADMIN (EXECUTE)
    -> POST /api/v1/scans
    -> durable scan ID + HTTP 202
    -> ScanExecutor
    -> existing collectors and deterministic rules
    -> transactional persistence
    -> READ scans/resources/assessments/findings
```

The AWS account is derived from STS and cannot be supplied by the HTTP caller.

## Implemented Differences

- A representative governance example named `ANALYST` as the scan caller, but the accepted
  capability policy requires `EXECUTE`; only `ADMIN` currently has it. Authorization was not
  weakened to fit the example.
- The executor is an intentionally bounded in-process thread pool, not Celery, Kafka, or a durable
  distributed worker. One API process is the supported topology.
- The exceptions API is list-only. `AuditService` exists but no audit endpoint is exposed.
- `PROPOSE` and `APPROVE` are defined for later workflows but are unused by current routes.
- `/ready` checks database connectivity only; it does not verify migration revision, executor,
  OIDC, AWS credentials, or collector health.
- No single end-to-end HTTP/fake-AWS/persistence acceptance test was added; accepted coverage is
  composed from focused layers. This gap is tracked before Sprint 5.

## Validation and review

Merged-baseline validation on 2026-09-05:

```text
python -m ruff check .                                      PASS
python -m ruff format --check .                             PASS (152 files)
python -m pytest                                            406 passed, 6 skipped, 2 warnings
docker compose config --quiet                               PASS
GitHub Actions quality job on merged main                   PASS
```

GitHub Actions supplied PostgreSQL 16, ran the complete suite including all six integration tests,
and built the API image. It is the PostgreSQL integration and image-build validation evidence. The
local Docker daemon was unavailable during the governance audit, and CI did not start the image or
the Compose stack, so container runtime behavior was not exercised.

Independent review found no unresolved Sprint 4 implementation blocker before merge. The later
governance audit identified accepted limitations in `docs/operations/known-limitations.md`; this
retrospective does not rewrite or silently repair them.

## Deferred

AWS evidence expansion, production controls, Terraform, dashboard, governance mutations,
remediation, distributed execution, and AI functionality were not implemented.
