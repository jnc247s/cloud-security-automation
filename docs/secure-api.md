# Secure service API

Sprint 4 exposes the persisted control-plane state through a versioned, authenticated API. The
API is intended for a dashboard, CLI, integration, or future agent tool. It remains read-only
apart from creating a scan; it cannot modify AWS resources, findings, exceptions, or controls.

## Authentication

All `/api/v1` endpoints require an HTTP bearer token. `/health`, `/ready`, and the OpenAPI
document remain unauthenticated so platform health probes and API discovery can operate.

Production must use `AUTH_MODE=oidc`. The application validates a JWT signature against the
configured JWKS and requires an exact issuer, audience, unexpired `exp`, and non-empty `sub`.
Only explicitly configured asymmetric algorithms are accepted. Configure:

```text
APP_ENV=production
AUTH_MODE=oidc
OIDC_ISSUER=https://identity.example.com/
OIDC_AUDIENCE=cloud-security-control-plane
OIDC_JWKS_URL=https://identity.example.com/.well-known/jwks.json
OIDC_ALGORITHMS=RS256
OIDC_ROLES_CLAIM=roles
```

The roles claim may contain one role string or an array. Recognized roles and capabilities are:

| Role | Capabilities |
| --- | --- |
| `VIEWER` | `READ` |
| `ANALYST` | `READ`, `PROPOSE` |
| `APPROVER` | `READ`, `PROPOSE`, `APPROVE` |
| `ADMIN` | `READ`, `PROPOSE`, `APPROVE`, `EXECUTE` |

The application stores neither passwords nor bearer tokens. TLS termination and token issuance
belong to the deployment and its external identity provider.

For local development only, `AUTH_MODE=development` provides the configured fixed identity. It
still requires the explicit non-secret marker:

```http
Authorization: Bearer local-development
```

Development authentication is accepted only when `APP_ENV` explicitly names a local, development,
or test environment. Never expose development mode on a public interface. Docker Compose binds the
API port to loopback by default.
OIDC issuer and JWKS URLs must use HTTPS; plain HTTP can only be enabled explicitly for a
localhost development provider with `OIDC_ALLOW_INSECURE_HTTP=true`.

## Endpoints

| Capability | Method and path | Purpose |
| --- | --- | --- |
| `EXECUTE` | `POST /api/v1/scans` | Persist and submit a single-region scan |
| `READ` | `GET /api/v1/scans` | List scan lifecycle records |
| `READ` | `GET /api/v1/scans/{scan_id}` | Read exact scan provenance and scope |
| `READ` | `GET /api/v1/resources` | List stable AWS resource identities |
| `READ` | `GET /api/v1/resources/{resource_id}` | Read a resource and latest observation |
| `READ` | `GET /api/v1/resources/{resource_id}/history` | Read immutable observations |
| `READ` | `GET /api/v1/assessments` | List four-state technical results |
| `READ` | `GET /api/v1/assessments/{assessment_id}` | Read evidence and framework mappings |
| `READ` | `GET /api/v1/findings` | List current finding state |
| `READ` | `GET /api/v1/findings/{finding_id}` | Read finding occurrences and exceptions |
| `READ` | `GET /api/v1/controls` | List versioned technical controls |
| `READ` | `GET /api/v1/controls/{control_id}` | Read definitions and framework mappings |
| `READ` | `GET /api/v1/frameworks` | List immutable framework versions |
| `READ` | `GET /api/v1/frameworks/{framework_id}` | Read hierarchy and control mappings |
| `READ` | `GET /api/v1/exceptions` | List explicit operational exceptions |

List endpoints use deterministic offset pagination with `limit` (default 50, maximum 100) and
`offset`. OpenAPI at `/docs` describes supported filters and response fields. Identifiers,
assessment results, structured evidence, checksums, occurrence relationships, and framework
mappings are separate fields; clients do not need to parse prose to recover them.

## Starting and following a scan

Apply migrations before using the API. With development authentication and the AWS credential
chain configured for the API process:

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

The POST operation writes a `RUNNING` scan and its authenticated `SCAN_STARTED` audit event before
submitting work. It returns HTTP `202 Accepted`; AWS collection, deterministic assessment, and
transactional persistence happen after the request returns. The AWS account ID comes from STS in
the executor and is never trusted from request input. Poll the scan detail until its status is
`COMPLETED`, `PARTIAL`, or `FAILED`. Failures expose only a bounded error code and safe message;
stack traces and raw AWS responses remain server-side.

The v1 executor is an explicitly bounded in-process thread executor with graceful shutdown and
durable scan identities. On application startup it can resubmit persisted `RUNNING` scans. The
Docker deployment intentionally runs one API process; multi-process or horizontally scaled
deployments should replace this implementation with a durable worker/ECS-task adapter behind the
same `ScanExecutor` boundary. No Celery, Kafka, or other queue has been introduced in this sprint.

## Security notes

- Use a workload role or short-lived credentials for AWS access; never put AWS keys in `.env`.
- Put the service behind TLS and normal ingress controls outside local Compose.
- Treat evidence and normalized resource configuration as sensitive infrastructure metadata.
- Grant `ADMIN` only to callers allowed to consume scan capacity.
- Authentication proves application identity; AWS permissions still come from the API process's
  configured credential chain and should remain read-only.
- Sprint 4 adds no remediation endpoint and makes no AWS changes.
