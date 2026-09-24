# Security policy and engineering boundaries

This document defines permanent repository security rules and the accepted Sprint 0--4 boundary,
the accepted Sprint 5 shared evidence-graph foundation, and the merged 5A EC2/EBS, 5B network, 5C
IAM, 5D IAM Access Analyzer, 5E S3/referenced-KMS, and 5F CloudTrail evidence producers at the
accepted `main` baseline `ef4543d439ed3a33064c6bcf383db201a94d2881`, which merged the bounded
5G closure in pull request #25. Sprint 5 is complete. Threats and residual risks are tracked in
[THREAT_MODEL.md](THREAT_MODEL.md).

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

Current query endpoints—including source-outcome/artifact and resource-relationship reads—require
`READ`; `POST /api/v1/scans` requires `EXECUTE`, which only `ADMIN` currently holds. `PROPOSE` and
`APPROVE` are reserved for later explicit workflows. Do not collapse the four capabilities into a
generic administrator permission.

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
source manifests, source outcomes, normalized source artifacts, resource relationships, findings,
exceptions, audit metadata, database dumps, and backups as sensitive security data. Grant
database and backup access on least privilege. A `READ` principal is trusted to receive normalized
artifact payloads from source-outcome detail; there is no field-level or account-level policy.

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

The graph-aware 5A EC2/EBS producer records controlled source states and failure categories for
instance discovery, volume discovery, Regional encryption-by-default, and Regional default-KMS
evidence. The 5B implementation adds independently paginated Regional security-group, VPC,
subnet, and Flow Log sources. `security_groups` and `vpc_network_evidence` remain separate
collector boundaries so failure of one source family cannot falsely complete—or unnecessarily
erase—the other. One failed or malformed source does not authorize omission of its outcome or
promotion of the collector to complete. Independently validated sibling resources may be retained
with a `PARTIAL` rollup; unknown evidence remains unknown and no Sprint 6 rule consumes it yet.

The accepted 5D implementation applies the same boundary to Regional IAM Access Analyzer
evidence. It queries only the requested Region and additional Regions proved by same-scan
normalized S3 bucket identity, records the S3 Region-discovery completeness input, and preserves independent
`ListAnalyzers`, `ListFindingsV2`, and `GetFindingV2` artifacts and outcomes. Malformed,
inaccessible, conflicting, or pagination-incomplete data remains sanitized and incomplete while
valid siblings are retained. Analyzer findings are investigation facts only: they do not decide
`S3-002`, create a control-plane `Finding`, or substitute for direct S3 evidence.

The accepted 5E collector treats bucket policy, ACL, tags, Block Public Access, encryption,
topology, source artifacts, and KMS metadata as sensitive `READ` data. It validates exact bucket
home Regions before enrichment, strictly decodes policy JSON with duplicate-key rejection,
separates expected absence from provider failure, and never places raw evidence or AWS error text
in routine logs. Referenced KMS resources require validated returned identity plus an exact
same-scan `encrypted_with` relationship; incomplete lookups retain only a typed unresolved
reference and cannot invent a key, owner, ARN, Region, or manager. These facts do not authorize
AWS writes or make an S3 compliance decision.

The accepted 5F implementation preserves the same fail-closed boundary for CloudTrail. A
persisted `cloudtrail-evidence` execution marker prevents accepted pending scans from silently
gaining new AWS calls. Trail ARNs must prove owner and home Region; the verified collection
account never substitutes for a management-account owner on an organization trail. An
external-owner trail without the existing exact admission proof is retained only in its
digest-bound discovery artifact, omitted from both 5F resource projections, and makes coverage
incomplete. Existing `LOG-001` semantics then fail closed as `INSUFFICIENT_EVIDENCE`. Selector,
destination, KMS,
status, and tag evidence is sensitive `READ` data; raw provider payloads and failures must remain
out of routine logs. Its only permission delta is read-only
`cloudtrail:GetEventSelectors`; `cloudtrail-evidence` is not an AWS service name or permission.

Evidence-graph persistence accepts only normalized object-shaped JSON artifacts, binds each
artifact to a canonical digest, rejects known credential/authorization key names, and exposes
controlled source failure categories instead of raw provider exceptions. Relationship provenance
must identify exactly one `PRESENT` source outcome. These controls reduce accidental secret and
fabricated-edge exposure; they do not make normalized cloud configuration non-sensitive.
Arbitrary AWS tag names are encoded as sorted `key`/`value` entries inside 5A, 5B, 5E, and 5F
artifacts rather than becoming artifact object keys, so untrusted metadata cannot alter the
artifact's structural field vocabulary or be mistaken for a credential-bearing structural field.
Tag values remain sensitive evidence.

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

The environment also blocks downgrade across `20260915_0003` before DDL when the older schema
would lose source-manifest or evidence-graph history, or cannot represent an exceptional-owner or
supplemental-Region snapshot admitted by the new provenance contract. PostgreSQL excludes writers
across the inspected scan, scope, resource, snapshot, and graph tables while deciding and
transitioning compatible data. Offline generation across this boundary fails closed. Keep the
current revision after a block and follow the documented backup and recovery runbook; never erase
graph rows, rewrite resource ownership/Region, or stamp around the revision to force rollback.

Collection-account identity is not resource ownership or caller authorization. The controlled
`aws` owner and a different 12-digit owner are admitted only with exact, same-scan,
identity-authoritative source evidence; an external owner also requires a resolved relationship.
Persisting or returning such an observation does not expand the scan principal, grant AWS access,
or create tenant isolation.

For 5A, the authenticated account is authoritative for collected instances and volumes.
`DescribeInstances` references remain owner-incomplete at their collector boundary. In 5B,
security-group, VPC, and subnet resource owners come only from strictly validated AWS `OwnerId`
values; an observed external owner is preserved rather than rewritten as the collection account.
Flow Logs remain bound to the verified collection account because their inventory response does
not supply a separate owner field.

Inventory assembly may refine an owner-incomplete target only when exactly one same-scan resource
matches every known service, type, resource ID, scope, and Region component and has a matching
`PRESENT`, identity-authoritative source contract/outcome. A graphless resource, non-authoritative
observation, missing proof, or ambiguous owner set cannot authorize resolution. External-owner
admission still requires the accepted resolved-relationship proof and does not expand caller or
scan authorization.

Assembly excludes an external-owner observation that has no exact resolved-edge proof rather than
weakening that admission rule or aborting unrelated evidence. Its resource-scoped graph records
are excluded; the complete discovery artifact preserves the AWS-observed ID and separately
records its canonical identity under `unadmitted_resources` with `admission_complete = false`.
The AWS source remains truthfully `PRESENT`, while the owning collector's `PARTIAL` state is
reconstructable from the persisted outcome and digest-bound admission metadata. Existing and
future rules fail closed instead of treating the pruned resource set as complete or treating
`PRESENT` alone as proof of an admitted projection.

The accepted 5B through 5F collectors preserve facts and
provenance only. They do not decide whether a default group, Flow Log, public-IP setting, network
permission, IAM policy, root-account flag, tag, external-access finding, bucket policy, ACL,
Block Public Access setting, encryption configuration, or CloudTrail configuration passes a
planned control, and they do
not add an executable Sprint 6 rule. The IAM collector retains access-key identifiers only as
resource identity and evidence; it never requests or stores secret access-key material. Provider
failures and malformed facts remain sanitized. Sprint 5 is `COMPLETE`; its foundation, 5A through
5F, and bounded 5G closure are accepted on `main`. Sprint 6 is `NEXT`, not started.

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
