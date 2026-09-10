# Threat model

Status: living model for the accepted Sprint 4 baseline
Baseline: `main` commit `1e190720c5c33a4edfc1cebe44c652e2ee17424f`
Last reviewed: 2026-09-10

## Scope and security objectives

The model covers AWS credential use, fact collection, deterministic assessment, PostgreSQL
history, the service layer, OIDC/development authentication, capability authorization, FastAPI,
and the in-process scan executor. No production deployment, frontend, Terraform infrastructure,
remediation execution, or AI agent is implemented.

Protect:

- AWS workload credentials and identity;
- normalized resource configuration and structured evidence;
- profile, control, and framework integrity;
- assessment, finding, exception, and audit history;
- API tokens and authorization decisions; and
- service/database availability and scan capacity.

Security objectives are confidentiality of cloud evidence and credentials, integrity and
reproducibility of technical assessments, authorized access, append-only auditability, and bounded
failure behavior.

## Trust boundaries and assumptions

```text
external identity provider -> untrusted bearer token -> API authentication boundary
authenticated principal -> capability check -> service/API data boundary
API process -> database credentials -> PostgreSQL history boundary
API/worker process -> AWS workload identity -> AWS account boundary
AWS API responses/resource metadata -> untrusted input -> collector normalization boundary
```

The current deployment assumes one trusted security organization controls every account stored in
one database. TLS, ingress, OIDC issuance, secret storage, PostgreSQL network isolation, backups,
and runtime workload identity are supplied by the deployment environment.

## Threats, controls, and residual risk

| ID | Threat | Risk | Current controls | Residual risk / required action |
| --- | --- | --- | --- | --- |
| T01 | Unauthenticated access | High | Bearer dependency on every `/api/v1` operation; uniform sanitized 401 | Health, readiness, and API schema are public by design; keep their output non-sensitive |
| T02 | Authorization bypass | High | Central role-to-capability map; route dependencies; denied-path tests | Future mutation routes must test every role and object scope; `PROPOSE`/`APPROVE` are not yet exercised by APIs |
| T03 | IDOR or cross-account disclosure | High in multi-tenant use | UUID validation and authenticated `READ` | No tenant/account object authorization exists; deploy only within one trust domain until designed |
| T04 | JWT forgery, confusion, replay, or stale keys | High | JWKS signature; exact issuer/audience; `exp`/`sub`; asymmetric allowlist; bounded JWKS caching | Revocation, replay detection, token-age policy, and IdP operations are external; use short-lived tokens and TLS |
| T05 | Development auth in production | Critical | Configuration rejects development mode outside explicit local/test environments; Compose binds loopback | Misconfigured network exposure remains dangerous in local mode; never publish it |
| T06 | Scan abuse or denial of service | High | `EXECUTE` required; bounded two-worker/32-outstanding executor; 503 on capacity exhaustion | No rate limit, quota, cancellation, timeout, caller idempotency key, or global multi-process capacity control |
| T07 | Sensitive evidence exposure | High | Authentication, read capability, structured projections, sanitized failures | Every reader can see all stored accounts and detailed configuration; add field/object policy before broader tenancy |
| T08 | Audit tampering or ambiguous attribution | High | Transactional append-only audit guards and explicit actor subject on scan start | Guards reject audit UPDATE/DELETE but cannot prevent a privileged direct INSERT or require direct finding/exception writes to have a paired audit event; issuer, roles, and capability are not retained. Restrict database roles to service-only writes and protect operator access. |
| T09 | AWS credential theft or scanner overprivilege | Critical | Standard credential chain; no key settings; documented read-only calls; no AWS mutation code | Deployment owns role scope, rotation, metadata-service controls, and secret isolation |
| T10 | Assessment or history corruption | High | Checksums, composite foreign keys, immutable version checks, caller-owned transactions, history guards, fail-closed populated-downgrade preflight | Backups and operator access remain privileged; current migration tooling and an approved maintenance window are still required |
| T11 | Duplicate or abandoned scan execution | Medium | Durable IDs, startup resubmission, in-process de-duplication, idempotent persistence | Recovery is startup-only; multiple API processes can duplicate AWS work; no lease/heartbeat/periodic recovery |
| T12 | Malicious or malformed AWS metadata | Medium | Explicit typed response-boundary validation, strict identities and promoted nested facts, sanitized evidence errors, duplicate consistency checks, Pydantic normalization, deterministic rules | New evidence fields must add matching validation; malformed data makes the affected collector incomplete and currently discards that collector's otherwise valid items |
| T13 | Profile or mapping substitution | High | Explicit numeric profile version, content checksums, fail-closed version-content conflict, exact persisted-profile loading for pending scans, source manifest digest, mapping/reference validation | Operators must deploy a reviewed new profile version whenever policy content changes; no automatic semantic ordering or policy approval workflow exists |
| T14 | Dependency, image, or CI compromise | High | Minimal dependencies, bounded dependency ranges, least-privilege CI, tests/PostgreSQL/image build | No lockfile/SBOM/security scans or immutable action/image pins; review every dependency, action, and base-image update |
| T15 | Database exposure or destructive migration | Critical | Loopback local port, migrations, PostgreSQL constraints, no automatic schema creation | Production network/backup/credential controls are external; never mutate production without explicit approval |

## Future-boundary threats

Remediation will introduce stale-proposal, approval-bypass, confused-deputy, privilege-escalation,
and partial-change risks. It must use separate `PROPOSE`, `APPROVE`, and `EXECUTE` principals,
current-state revalidation, narrowly coded handlers, a limited write role, audit, rescan, and
deterministic verification. Finding status must remain separate from remediation status.

A future investigation agent may initially receive only controlled `READ` and `PROPOSE`
interfaces. Treat cloud metadata as untrusted prompt content. An agent must not determine
technical results, official mappings, evidence sufficiency, authorization, or remediation success.

## Required review triggers

Update this model when authentication, role/capability mappings, object scope, API exposure, AWS
permissions, collected evidence, persistence, audit, executor topology, deployment, dashboard,
remediation, or agent tooling changes. Rank independent review findings `CRITICAL`, `HIGH`,
`MEDIUM`, or `LOW`; resolve all `CRITICAL` and `HIGH` findings before sprint completion.
