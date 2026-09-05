# Service API

This is the authoritative human-readable contract for the accepted Sprint 4 API. OpenAPI at
`/openapi.json` is the exact generated schema; `/docs` and `/redoc` render it. Future interface
changes must update this document and tests in the same change.

The API is read-only apart from creating a scan. It cannot modify AWS resources, finding status,
exceptions, controls, mappings, or audit history.

## Authentication

All `/api/v1` operations require an HTTP bearer token. `/health`, `/ready`, `/docs`,
`/docs/oauth2-redirect`, `/redoc`, and `/openapi.json` remain unauthenticated for platform probes
and API discovery and must never expose resource evidence.

Production uses `AUTH_MODE=oidc`. The application validates the JWT signature against configured
JWKS and requires an explicitly allowed asymmetric algorithm, exact issuer and audience, an
unexpired `exp`, a non-empty `sub`, and a recognized roles claim:

```text
APP_ENV=production
AUTH_MODE=oidc
OIDC_ISSUER=https://identity.example.com/
OIDC_AUDIENCE=cloud-security-control-plane
OIDC_JWKS_URL=https://identity.example.com/.well-known/jwks.json
OIDC_ALGORITHMS=RS256
OIDC_ROLES_CLAIM=roles
```

The roles claim may be one string or an array. The application stores neither passwords nor
bearer tokens. Token issuance, revocation policy, TLS, and ingress belong to the deployment and
identity provider.

For local development only, `AUTH_MODE=development` uses the configured fixed identity and still
requires this explicit non-secret marker:

```http
Authorization: Bearer local-development
```

Development authentication is rejected unless `APP_ENV` explicitly names a local, development,
or test environment. Docker Compose binds the API to loopback by default. OIDC issuer and JWKS
URLs require HTTPS unless localhost HTTP is explicitly enabled in a non-production environment.

## Authorization

| Role | Capabilities |
| --- | --- |
| `VIEWER` | `READ` |
| `ANALYST` | `READ`, `PROPOSE` |
| `APPROVER` | `READ`, `PROPOSE`, `APPROVE` |
| `ADMIN` | `READ`, `PROPOSE`, `APPROVE`, `EXECUTE` |

All current `/api/v1` GET operations require `READ`. `POST /api/v1/scans` requires `EXECUTE`, so only
`ADMIN` can start a scan in the current mapping. `ANALYST` receives HTTP 403; do not weaken that
boundary when writing examples or tests. `PROPOSE` and `APPROVE` are reserved for later explicit
workflows.

Authorization is control-plane-wide. A principal with `READ` can query all accounts persisted in
this database; tenant/account claims and row-level object authorization are not implemented. The
accepted deployment assumption is one trusted security domain.

## Endpoints

| Capability | Method and path | Purpose |
| --- | --- | --- |
| `EXECUTE` | `POST /api/v1/scans` | Persist and submit a single-region scan |
| `READ` | `GET /api/v1/scans` | List scan lifecycle records |
| `READ` | `GET /api/v1/scans/{scan_id}` | Read exact scan provenance and scope |
| `READ` | `GET /api/v1/resources` | List stable AWS resource identities |
| `READ` | `GET /api/v1/resources/{resource_id}` | Read identity and latest observation |
| `READ` | `GET /api/v1/resources/{resource_id}/history` | Read immutable observations |
| `READ` | `GET /api/v1/assessments` | List four-state technical results |
| `READ` | `GET /api/v1/assessments/{assessment_id}` | Read evidence and framework mappings |
| `READ` | `GET /api/v1/findings` | List current finding state |
| `READ` | `GET /api/v1/findings/{finding_id}` | Read occurrences and exceptions |
| `READ` | `GET /api/v1/controls` | List stable controls and versioned definitions |
| `READ` | `GET /api/v1/controls/{control_id}` | Read definitions and mappings |
| `READ` | `GET /api/v1/frameworks` | List immutable framework versions |
| `READ` | `GET /api/v1/frameworks/{framework_id}` | Read hierarchy and control mappings |
| `READ` | `GET /api/v1/exceptions` | List explicit operational exceptions |

There is no exception-detail route, audit route, finding/exception mutation, rescan/retry,
cancellation, remediation, or arbitrary AWS-call endpoint. `AuditService` is an internal service
boundary only.

## Filtering and pagination

| List | Optional filters |
| --- | --- |
| scans | none |
| resources | `account_id`, `service`, `resource_type`, `region` |
| resource history | none beyond `resource_id` in the path |
| assessments | `scan_id`, `resource_id`, `control_id`, `result` |
| findings | `account_id`, `resource_id`, `control_id`, `status`, `region` |
| controls | `category`, `severity`, `resource_type`, `catalog_key` |
| frameworks | `framework_key`, `version` |
| exceptions | `finding_id`, `resource_id`, `control_id`, `status` |

Every list uses offset pagination with `limit` defaulting to 50, a maximum of 100, and `offset`
defaulting to 0. Responses contain `items`, `total`, `limit`, and `offset`. Service queries use
deterministic ordering, but offset pages and totals are not a transactionally frozen snapshot;
concurrent writes can move items between requests. Control filters select controls with at least
one matching version and return all versions for each selected stable control.

Enum values, UUID formats, request constraints, and exact response fields are defined by OpenAPI.

## Machine-readable results

The API keeps IDs and facts in explicit fields, including `scan_id`, `resource_id`, `snapshot_id`,
`assessment_id`, `finding_id`, `control_id`, result/status values, structured evidence payloads,
occurrences, profile/catalog checksums, collection outcomes, and framework mappings. Clients must
not parse prose to recover these relationships.

`Resource` is stable identity and `latest_snapshot` is the newest observed state. History returns
immutable snapshots. The top-level stable resource ARN is first-seen metadata; when an ARN changes,
the latest snapshot's ARN is the current observed value.

Evidence and normalized configurations can contain sensitive infrastructure data. A caller with
`READ` is trusted to receive it.

## Starting and following a scan

Apply migrations and configure the API process's read-only AWS credential chain first. In local
development:

```powershell
$headers = @{ Authorization = "Bearer local-development" }
$scan = Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:8000/api/v1/scans `
  -Headers $headers `
  -ContentType application/json `
  -Body '{"region":"us-east-1"}'

Invoke-RestMethod `
  -Uri "http://localhost:8000/api/v1/scans/$($scan.scan_id)" `
  -Headers $headers
```

The request body permits only optional `region`; omission uses `AWS_REGION`. Extra fields are
rejected. The API never accepts an AWS account ID from the caller.

The POST operation writes a `RUNNING` scan and authenticated `SCAN_STARTED` audit event before
submitting work, then returns HTTP `202 Accepted`. STS resolves the account in the background;
collection, deterministic assessment, and transactional persistence follow. Poll the scan detail
until `COMPLETED`, `PARTIAL`, or `FAILED`:

- `RUNNING`: durable identity exists; account, inventory digest, and scope may not exist yet.
- `COMPLETED`: all requested collectors and the requested Region succeeded.
- `PARTIAL`: a result bundle was persisted with incomplete requested collection, but not every
  requested collector failed.
- `FAILED`: every requested collector failed, or execution/persistence could not produce a normal
  result bundle; only bounded safe failure detail is returned.

The accepted executor uses a bounded in-process thread pool, startup resubmission, and graceful
shutdown. It is not a distributed queue. Run one API process; a horizontally scaled deployment
must provide a claim/lease-capable executor behind the same interface.

## Error behavior

The API does not currently use one universal error envelope:

| Status | Behavior |
| --- | --- |
| `401` | Missing/invalid bearer token: `detail.code=authentication_required`; token-validation detail is not exposed |
| `403` | Valid principal without capability: `detail.code=insufficient_capability` |
| `404` | Missing service entity: `detail.code=entity_not_found` with entity and identifier |
| `422` | FastAPI request/path/query validation response |
| `503` | Scan executor unavailable/capacity/submission failure, or database readiness failure |
| `500` | Unexpected domain, catalog, database, or server failure; no stable application envelope is promised |

If submission fails after the scan row is committed, the 503 response uses
`detail.code=scan_submission_failed` and returns the durable `scan_id`. The service makes a
best-effort transition to `FAILED`. If the executor is absent from application state, the code is
`scan_executor_unavailable`.

Failure messages are sanitized; raw AWS responses and stack traces stay server-side. OIDC/JWKS
lookup or verification failure fails closed as 401.

## Health and readiness

`GET /health` reports process liveness without database or AWS calls. `GET /ready` executes a
database `SELECT 1` and returns 503 when connectivity fails. Readiness does not verify Alembic
revision, executor capacity, OIDC/JWKS availability, AWS credentials, or collector health.

## Compatibility rule

Before changing a method, path, capability, enum, request field, response field, pagination
behavior, error contract, or stable identifier, search all clients/tests and evaluate persistence
and backward-compatibility implications. Update code, tests, this document, architecture, and
security sources atomically, then run the complete regression suite.

No permissive CORS middleware is configured. Production clients require deployment-provided TLS,
controlled ingress, and an explicit CORS policy only when a trusted browser origin needs one.
