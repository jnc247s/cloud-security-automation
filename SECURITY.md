# Security policy and engineering boundaries

This document defines permanent repository security rules and the accepted Sprint 4 security
boundary. Threats and residual risks are tracked in [THREAT_MODEL.md](THREAT_MODEL.md).

## Authentication

Every `/api/v1` operation requires an HTTP bearer token. Production must use `AUTH_MODE=oidc` and
valid HTTPS issuer/JWKS URLs. JWT verification requires a trusted JWKS signature, an explicitly
allowed asymmetric algorithm, exact issuer and audience, expiration, non-empty subject, and only
recognized roles. The application does not issue tokens or store passwords.

`AUTH_MODE=development` accepts the fixed non-secret `local-development` marker only when
`APP_ENV` explicitly names a local, development, or test environment. Production configuration
fails validation unless OIDC is enabled. Never expose development mode on a public interface or
weaken this fail-closed check.

`/health`, `/ready`, `/docs`, `/docs/oauth2-redirect`, `/redoc`, and `/openapi.json` are
intentionally unauthenticated. They must not return secrets or resource evidence.

## Authorization

| Role | Capabilities |
| --- | --- |
| `VIEWER` | `READ` |
| `ANALYST` | `READ`, `PROPOSE` |
| `APPROVER` | `READ`, `PROPOSE`, `APPROVE` |
| `ADMIN` | `READ`, `PROPOSE`, `APPROVE`, `EXECUTE` |

Current query endpoints require `READ`; `POST /api/v1/scans` requires `EXECUTE`, which only
`ADMIN` currently holds. `PROPOSE` and `APPROVE` are reserved for later explicit workflows. Do not
collapse the four capabilities into a generic administrator permission.

The accepted application is a single-trust-domain control plane. A reader can query all persisted
AWS accounts; there is no tenant/account claim enforcement or row-level isolation. Do not deploy
it as multi-tenant SaaS without designing and testing object-level authorization.

## Network exposure and CORS

Local Compose binds the API and PostgreSQL ports to `127.0.0.1`. No permissive CORS middleware is
configured. Production must provide TLS termination, controlled ingress, appropriate security
headers, network isolation for PostgreSQL, and explicit CORS policy only if a trusted browser
client requires it. Never treat the development bearer marker as a secret or an Internet-facing
security control.

## AWS access and least privilege

- Prefer a workload role, role assumption, or short-lived IAM Identity Center credentials.
- Never accept AWS access keys as application settings or mount a complete host credential store
  into the default container.
- Grant only the read actions documented in `docs/operations/aws-inventory.md` and update that
  policy whenever a collector changes.
- Keep scanner and remediation identities separate. Scanner access remains read-only; future
  remediation gets narrowly scoped write actions for explicit handlers only.
- Never create root credentials, remove root MFA, or disable important account-wide safeguards to
  test the scanner. Use fakes, botocore Stubber, or safe isolated resources.
- Treat every AWS response as untrusted input. Validate required identities and decision-relevant
  nested facts before normalization; do not coerce null or wrong-type values into plausible
  strings.

## Secrets

Never commit, print, log, or place in API errors:

- AWS access keys, secret keys, or session credentials;
- JWTs, OIDC client secrets, signing material, or private keys;
- database, API, or deployment secrets; or
- credential-process, SSO cache, or secret-manager output.

`.env` and local credential artifacts remain ignored. `.env.example`, Compose defaults, and CI
database values are development/test placeholders and must never be reused in production. Use the
deployment platform's secret store and rotate an exposed credential immediately with explicit
human authorization.

## Sensitive data, logging, and errors

Treat account identifiers, ARNs, topology, policies, normalized configurations, evidence,
findings, exceptions, audit metadata, database dumps, and backups as sensitive security data.
Grant database and backup access on least privilege.

Application logs and HTTP failures must use bounded codes and sanitized messages. Do not include
raw AWS responses, tokens, stack traces, policy documents, or configuration payloads in routine
logs. A successful or failed authentication decision must not reveal token-validation detail.
Reusing an assessment-profile version with different policy content returns the fixed
`assessment_profile_version_conflict` response; it must not reveal either checksum, stored policy
content, database detail, or a traceback.

Collector evidence failures expose only an operation name and structural fact path. They never
include the rejected AWS value or raw response. Operational botocore failures, malformed evidence,
and programming defects remain separate categories: do not add a broad exception handler that
hides an application defect as incomplete AWS evidence.

Audit events are append-only evidence, not a general log sink. Record the verified actor context
needed to reconstruct sensitive mutations. The current scan-start event retains only subject;
issuer/role/capability attribution is a known gap tracked in `ROADMAP.md`.

## Database and migration safety

- Use Alembic for schema changes; never rewrite an accepted migration.
- Validate upgrades with populated representative history and PostgreSQL, not only an empty
  database or SQLite.
- Back up important data and approve rollback/data-conversion plans before destructive changes.
- Never run tests, migration experiments, or downgrade commands against production.
- Preserve append-only audit and immutable historical evidence guards.

The current Alembic environment blocks downgrade across `20260904_0002` when any retained scan
has a null AWS identity or inventory digest that the older schema cannot represent. PostgreSQL
locks the scan table before checking so concurrent writes cannot create a time-of-check race, and
offline SQL generation across the boundary fails closed. This guard does not authorize a
production rollback: quiesce writers, verify a restorable backup, and follow the documented
recovery runbook. Never fabricate or delete history to satisfy an older constraint.

Assessment profiles are immutable security policy. `ASSESSMENT_PROFILE_VERSION` is explicit,
operator-controlled provenance: deploy a new numeric `X.Y.Z` value whenever policy content
changes, and never edit a stored version or rewrite scan references. Pending scans load and verify
their persisted profile rather than current environment policy, so a restart cannot silently
change an accepted assessment definition.

## Production authorization

Writing code or configuration never authorizes execution against production. Explicit human
authorization is required for production deployment, Terraform apply, destructive AWS action,
database migration or mutation, remediation, IAM or secret changes, and credential rotation. Do
not infer approval from a sprint request, a passing test, or repository access.

## Security validation and reporting

Security-boundary changes require updates to this file, `THREAT_MODEL.md`, architecture where
material, tests for both allowed and denied behavior, and the full regression suite. Do not weaken
tests or defaults to make CI pass.

Report suspected vulnerabilities privately to the repository owner with reproduction conditions,
affected versions/commits, impact, and any known safe mitigation. Do not include real credentials
or sensitive customer/cloud evidence in an issue or test fixture.
