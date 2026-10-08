# Security policy and engineering boundaries

This document defines permanent repository security rules for accepted Sprints 0--7 and
Sprint 8A/8B1 authority below. The accepted `main` baseline is
`0c6005827ae765fe2b2669e4f503af6ca58cdc15` (8B1 admission PR #55;
exact-commit independent review, both final-head CI and main CI 37726113041 passed).
Accepted 8B1 database admission is not deployment or AWS execution authority.
That baseline includes the versioned assessment
foundation and opt-in IAM, EC2, network, S3 and CloudTrail controls; default catalog `0.2.1`
remains unchanged. Threats and residual risks are tracked in [THREAT_MODEL.md](THREAT_MODEL.md).

Accepted 6F.2 composition admits only validated same-scan/profile/catalog/inventory S3-002 results
for the exact resolved bucket snapshot. Missing/disabled/nondecisive prerequisites or partial
required collectors cannot pass. Source/edge/dependency evidence IDs/digests and explicit approval
identity are bound in a strict-type proof. Persistence reconstructs context before any SQL and
never trusts caller order/context. Operator approval artifacts remain unchanged; exceptions never
become approvals or rewrite FAIL. No AWS call/write, permission/auth or migration change.
Acceptance and merged-main CI passed; see [6F.2 metadata](docs/controls/sprint-6f2-metadata.md).

Accepted 6G required-tag validation binds complete governed-family discovery, exact target identity,
tag-source IDs/digests and retained profile checksum. Incomplete/malformed evidence cannot pass;
rehashed forged results and strict-type proof substitutions reject atomically before SQL.
Lossless hex tag encoding preserves exact strings and is not secrecy protection: source/proof
tags remain sensitive. Tags prove configuration presence, not ownership truth or authorization.
The initial profile is explicit opt-in; no deployed policy, credential, capability or AWS
permission changes. The approved category migration preserves integrity and blocks lossy
downgrades before DDL. Independent review and merged-main CI passed; see
[6G metadata](docs/controls/sprint-6g-metadata.md). Accepted 6H verified combined controls,
historical releases and real authenticated APIs with only AWS offline; no security behavior or
production operation changed. Sprint 7 is COMPLETE; 7A READ reporting is accepted and merged,
with zero unresolved independent-review findings and successful merged-main CI.
Accepted 7B adds the separate opt-in browser boundary below; it does not validate live IdP
or production setup. Accepted 7C adds read-only exact-scan investigation through the same boundary,
with independent review and green merged-main CI, not live-provider or production validation.
The subsequent 7D/7E acceptance and PR #51 documentary closeout passed their required
review/CI/merge gates. All 7A--7E states are COMPLETE; no security boundary or live-operation
authority is changed by recording final completion.

## Authentication

Accepted 6F.1 LOG-002/003 use same-scan source-bound management coverage and
explicit integrity settings, not inferred delivery or verified digest integrity. Missing
required evidence cannot pass. New-schema projection/proof validation preserves exact JSON types;
numeric substitutes for booleans do not match, even when a forged artifact is rehashed.
No credential, permission, authentication or AWS-write change
was introduced. The separately approved migration `20261001_0005` repairs unresolved-reference
persistence without inventing a Region, owner or stable target. Complete identities stay strict;
lossy downgrades are blocked before DDL and error messages remain sanitized. See
[6F.1 metadata](docs/controls/sprint-6f1-metadata.md).

S3-004 in opt-in `0.10.0` evaluates only classified sensitive buckets' default KMS
configuration. Missing classifier inputs or required key evidence cannot prove PASS. Exact
same-scan key/source/edge and classifier checks prevent substituted owners or policy versions;
both AWS-managed and customer-managed KMS are approved, not customer-managed-only.
No key access/availability, object-encryption or compliance claim is made. No AWS write,
credential, API/auth or permission change; real classifier/policy files remain outside Git.
See [6E.3 metadata](docs/controls/sprint-6e3-metadata.md).

S3-002 in opt-in `0.9.0` evaluates configured policy/ACL exposure against explicit immutable
bucket-scoped approvals; it is not a complete effective-permissions simulation. Same-owner
principals are not external, uncertainty cannot become PASS, and missing approvals cannot
silently become an empty policy. Assessment proofs bind historical policy/profile checksums
without copying unrelated approval records. No AWS write, permission or authentication change;
operator policy files remain sensitive and outside Git. See
[6E.2 metadata](docs/controls/sprint-6e2-metadata.md).

The approved 6A policy-file boundary is operator configuration, not an HTTP input. Store the
complete policy envelope outside Git with restrictive permissions and mount it read-only in
containers. It contains sensitive security policy, never credentials. Only local UTF-8 JSON up
to 1 MiB is accepted; duplicate keys, invalid checksums, unsupported versions, and unreadable files
fail closed with a fixed diagnostic. There is no network fetch, hot reload, or fallback policy.
Restart validates exact retained profile/artifact/catalog content before constructing AWS clients.
See [assessment foundation](docs/assessment-foundation.md) for the unchanged legacy defaults.

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
`READ`; `POST /api/v1/scans` requires `EXECUTE`, which only `ADMIN` currently holds. Accepted 8A
`POST /api/v1/remediations` requires `PROPOSE`; its decision and revocation routes require
`APPROVE`. Roles and scan authorization are unchanged. Do not collapse the four capabilities
into a generic administrator permission.

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

6E.1 consumes only retained S3 facts. Combined BPA never borrows another owner's account settings;
missing source evidence cannot be substituted with false settings. HTTPS PASS requires bounded
explicit denial, not an HTTPS Allow or inferred effective authorization. An independently proved
result may retain another unavailable BPA source, without relaxing complete-scan finding resolution.
Engine and persistence bind and re-evaluate immutable source proofs. No AWS writes, new permissions,
public endpoint, authentication change or automated remediation is added. Configuration remains
sensitive READ data; operator guidance requires dependency review and separate change approval.

6D.2 NET-006 uses retained facts only. Exact VPC/log owner, Region, source and edge membership
are checked before results; collection-account enumeration cannot prove external-owner coverage.
Environment/traffic policy must be explicit. No log delivery, retention or monitoring assurance
is inferred; an authorized operator must review dependencies and costs before changing logging.
No AWS write, new permission, endpoint or capability change is introduced.

6D.1 evaluates only retained security-group/VPC facts. Source/edge identities, complete discovery,
snapshot content and exact policy are validated at engine and persistence boundaries. Public
permission checks are not end-to-end reachability claims. Guidance requires dependency review and
separately authorized changes; no AWS writes, new permissions or remediation handlers are added.
NET-001/002, authentication and capability separation remain unchanged.

6C consumes only retained EC2/EBS evidence and adds no AWS permissions or write capability.
EC2-002 approvals use exact stable resource UUIDs, binding account, Region and instance; bare IDs
are rejected only for profiles enabling that control. Approval is immutable assessment policy,
not an operational finding exception. IMDS tokens, public addressing and encryption facts do not
prove compromise, reachability, full data protection or KMS-policy correctness. Operator guidance
requires compatibility checks and separately approved changes; no automatic remediation is added.

6B.1 adds no AWS permissions or write handlers. Its opt-in IAM evaluators use only retained,
same-scan facts and explicit versioned policy. Key age/last-use checks do not establish compromise,
and root summary flags do not establish centralized root-access posture. Operator guidance must
not encourage creating root credentials or weakening MFA to satisfy or test a control. Existing
authentication, capability separation, sanitized errors, and historical-integrity guards remain.

6B.2 similarly adds only retained-evidence IAM policy evaluation. A literal unrestricted Allow
pattern is not an effective-access result: a boundary grants nothing, and conditions or other
policies may constrain access. Guidance requires an authorized review and approved change;
the scanner neither edits policies nor assumes new permissions. Incomplete enumeration, usage,
document identity or digest proof cannot become PASS. Policy documents remain sensitive data.

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

Accepted 7A technical-posture aggregates are also sensitive READ data. The exact-scan service
omits configurations, evidence payloads, tags and mutable finding/exception handling, and never
calls AWS, evaluates rules, flushes caller objects or commits. Counts cannot substitute current
versions, multiply assessments through mappings, treat unavailable coverage as zero failures,
or convert exceptions into PASS. Version/profile/hierarchy conflicts fail closed with a fixed
sanitized `technical_posture_provenance_conflict` 409. Success and that conflict set no-store;
this does not make other existing API responses no-store or create tenant/field authorization.
Existing bearer validation and READ/EXECUTE separation remain the enforcement boundary.
The subsequently approved [7B proposal](docs/sprint-7b-preflight.md) defines the browser boundary;
local validation, independent review, final-head CI, explicit human merge approval and merged-main
CI passed through PR #43. No live provider or production setup is validated.

### Accepted opt-in 7B browser boundary

Dashboard enablement requires OIDC, an exact trusted origin, distinct client/API audiences,
server-only client credential and built assets; it never falls back to development access.
HTTP is accepted only with the existing explicit insecure flag and a loopback URL in a named
local/test environment. Production requires HTTPS. Startup errors hide configuration input.
Cognito login must request API resource binding; configure only recognized application groups,
never IAM role ARNs, as the roles claim. Provider credentials and live registration remain external.

Provider tokens, nonce and PKCE verifier remain server-side, bounded to 1,000 sessions and
100 five-minute login transactions. Session IDs are random opaque values; cookies are host-only,
HttpOnly, Secure under HTTPS and scoped to `/dashboard`. Sessions use SameSite Strict, login
correlation Lax for the top-level callback. Login/logout need session-bound CSRF and exact Origin;
callback state is browser-bound and consumed once before exchange, with library nonce verification.
The session expires after 15 idle minutes, 60 absolute minutes or access-token expiry, whichever
comes first. Status checks do not extend idle time. No refresh token is retained or renewed.

The accepted 7B adapter revalidates bearer authentication for its three READ operations; the accepted
7C extension below uses the same boundary. The API
enforces READ again; cookie-only API calls, proxy mutations and arbitrary targets are denied.
Late reads fail after logout/expiry. The client aborts/ignores superseded reads, clears context on
sign-out/authentication failure and renders untrusted metadata as text. BFF reads require the
bootstrapped public session-context header and reject missing/mismatched context before
forwarding, without revoking a different valid session. Credential-free ephemeral same-origin
tab notifications clear old identity/data and pending requests on logout or identity replacement;
they are not an authentication boundary and grant no capability. No browser-storage,
service-worker, external analytics/font or token-bearing logout URL is used. Dashboard responses
have no-store, restrictive CSP, no-referrer and frame/resource protections. Callback query data is
removed from the shared ASGI scope before access logging, including unexpected 500 paths;
identity HTTP logs omit exchange details. Non-ASCII/incorrect-length state and CSRF values reject
safely before constant-time comparison. Unexpected dashboard failures return a fixed secured
500 and remain observable as server-side exceptions, not suppressed success.

Logout ends the local session, not the IdP session or previously issued external tokens. Restart
ends all sessions. One process only: no replicated store, HA or tenant/account isolation is added.
HttpOnly does not prevent XSS from issuing same-origin reads; CSP and safe rendering remain needed.
No live Cognito pool, secret/IAM modification, production deployment or AWS operation is authorized.

### Accepted 7C investigation safeguards

The approved extension exposes an explicit GET-only allowlist, with typed UUID/enums, 1..100
page limits (default 25), nonnegative offsets, no duplicate/unknown queries and no browser-selected
upstream URL, method or headers. Assessment/graph lists and BFF resource history require a scan UUID.
All requests retain origin, opaque session, expected public context, real bearer/READ and final
logout/expiry checks. Filters and client identity checks are not account/tenant authorization.

Snapshots, evidence, source artifacts and endpoints are sensitive security data. Render text only;
do not follow metadata URLs or infer links from reason prose/UUID-looking payloads. Exact identity,
control/version/checksum, profile, scan and typed citation bindings fail closed. Unknown proof
schemas stay readable as raw evidence without inferred navigation. Browser display truncation
does not bound upstream detail payloads or certify full evidence review.

`X-Dashboard-Read-At` is UTC response-production metadata on successful operational reads only;
it grants no authority and is not scan-time state or an atomic mixed-report timestamp.
Exception eligibility at this reference requires valid explicit-offset creation/expiry/revocation
times. Stored ACTIVE alone cannot establish eligibility, expiry equality is expired, and missing
reference/times remain unavailable. No expiry job, exception mutation or technical-result rewrite.
The client clears sensitive details on selection/identity replacement, errors, expiry and logout;
late responses cannot repopulate superseded state. No storage, exports, analytics or live operations.

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
with a `PARTIAL` rollup. Accepted opt-in Sprint 6 controls consume only their declared,
version-bound proofs; unknown or unrelated evidence never becomes an invented complete source.

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

### 7D NIST display safeguards — accepted

The client-only view adds no credential, permission, route, database or policy boundary. Existing
session/context/origin/bearer READ and final expiry checks remain authoritative. Nested display
validation checks canonical UUIDs, release-local parents/mappings, retained enablement and safe
counts; it does not authorize access or certify unseen checksum bytes. Invalid NIST context
fails closed separately from valid investigation. Graph construction uses bounded-depth Maps;
framework selection and disclosures require no extra network requests.

Render all metadata as escaped text, including hostile titles/rationales/source URLs. Never
navigate sources, execute HTML, persist security data in Web Storage or add telemetry/exports.
Text is truncated explicitly (2,048 characters per value, 512 per summary, 256 per release label);
UUIDs/checksums/counts are not truncated. This does not bound upstream JSON or prove full review.
Selection/refresh/session replacement resets context; logout/expiry/cross-tab changes clear it
through the accepted shell boundary. Counts are historical technical facts, never NIST results;
mutable findings, ACCEPTED_RISK and exceptions cannot rewrite them. Local validation,
exact-head independent review, both final-head CI runs, guarded merge and merged-main CI passed;
see the [acceptance record](docs/sprint-7d-preflight.md). Live-provider/production validation
remains separate. 7E whole-Sprint-7 offline acceptance passed exact-head independent review,
both final-head CI runs, guarded merge and merged-main CI; see the
[evidence matrix](docs/sprint-7e-acceptance.md). No application security boundary changed.

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

The accepted 5B through 5F collectors preserve facts and provenance only; they never decide
technical results. Separately versioned Sprint 6 rules through 6E now evaluate retained network,
EC2/EBS, IAM and S3 evidence without moving policy into collectors. The IAM collector retains
access-key identifiers only as resource identity and evidence; it never requests or stores secret
access-key material. Provider failures and malformed facts remain sanitized. Sprint 5 is
`COMPLETE`; Sprint 6 is `COMPLETE`, including whole-sprint 6H acceptance and documentary closeout.
Sprint 7A reporting is COMPLETE; no 7B or later slice, deployment or production operation
was started by that acceptance or the subsequent analysis-only preparation.
Subsequent approvals and gates accepted 7B/7C/7D and 7E whole-sprint acceptance; Sprint 7 is
COMPLETE. 7E adds tests/documentation and restores normal Firefox isolation only in the pinned
test launcher; application headers/authentication, dependencies, timeouts and all assertions are
unchanged. No live IdP/AWS/IAM/secret/deployment/remediation operation is authorized by acceptance.
At that historical closeout Sprint 8 was NEXT. Its subsequent bounded accepted 8A scope and
current status are recorded in ROADMAP and the active Sprint 8 plan; live-operation authority
remains separate and absent.

Assessment profiles are immutable security policy. `ASSESSMENT_PROFILE_VERSION` is explicit,
operator-controlled provenance: deploy a new numeric `X.Y.Z` value whenever policy content
changes, and never edit a stored version or rewrite scan references. Pending scans load and verify
their persisted profile rather than current environment policy, so a restart cannot silently
change an accepted assessment definition.

<a name="sprint-8a-authority--local-pending-acceptance"></a>

## Sprint 8A authority — accepted

The approved 8A boundary persists intent and human decisions only. There is no execution handler,
writer credential setting/acquisition, worker submission, automatic rescan or browser mutation.
Scanner identities and permissions remain read-only. The only proposal action is EC2-004 EBS
encryption-by-default false-to-true; callers cannot provide arbitrary AWS parameters, account,
Region, credentials, desired state or shell commands. Scope is derived from validated history.

Identity separation uses the full verified `(issuer, subject)` pair, not roles or display names.
APPROVE and REJECT require a different identity from the proposer, with no ADMIN override. Any
APPROVE principal may revoke an existing approval, including its approver or a proposer who also
has APPROVE; removal of authority does not require current eligibility. No withdrawal exists.
The later execution requester must be a third distinct human identity, and the worker must use
a separate service identity; neither execution path is implemented in 8A. IdP governance must
restrict human workflow roles to appropriate human accounts and prevent one person controlling
multiple approver identities. Token verification cannot prove distinct physical people. The fixed
development principal cannot self-approve; do not weaken authentication to simulate separation.

Creation/approval validates completed explicit FAIL, immutable source/configuration/policy
bindings, complete default-KMS context, eligible finding disposition and no active unexpired
exception. A 24-hour expiry, any later/equal target-control assessment and a changed governance
digest block approval. Stored APPROVED is historical authority, not a live configuration claim
or execution readiness. Reads derive blocking reasons without rewriting that history. Rejecting
an undecided proposal or revoking approval remains possible when stale/expired.
The governance digest includes append-only finding audit-event IDs, not just reversible status
or a maximum timestamp; a status round trip never renews old authority, even at equal event times.
READ rejects pending ORM changes before SQL and suppresses autoflush rather than flushing or
discarding a caller's work. It does not commit/rollback a clean caller-owned transaction.

Every mutation requires a UUID Idempotency-Key, current capability, typed digest/references and a
bounded nonblank reason. Keys are scoped to identity and operation, not just proposal; replay
checks normalized request content and current capability before returning original history.
Short locked transactions atomically append authority, idempotency and audit rows. New audit
events retain exact issuer, subject, roles and capability in schema `1.0.0` metadata; their
`actor_id` is SHA-256 of canonical JSON `[issuer, subject]`, avoiding subject truncation. They do
not store JWTs, session credentials or provider errors. Legacy scan/governance audit attribution
is unchanged and its gaps remain. Database guards block mutation and basic cross-reference/self-
decision corruption, not privileged schema changes or every privileged direct INSERT. Restrict
database writes to trusted services and protect backups/operator access.

See [API](docs/api.md), [operations](docs/operations/remediation.md) and the active plan for exact
contracts and remaining acceptance gates. Local validation is not live IdP, AWS or production
validation and grants no operational authorization.

<a name="sprint-8b1-admission-boundary--approved-local-candidate-pending-acceptance"></a>

## Sprint 8B1 admission boundary — accepted

Admission-only POST requires current EXECUTE and a third distinct verified issuer/subject pair;
ADMIN cannot bypass proposer/approver separation. READ history uses the existing shared trust
domain, not account tenancy. Closed input binds the exact proposal digest and approval ID plus
bounded reason/key; callers cannot choose AWS parameters, scope, credentials or endpoints.
Retained provenance, unrevoked approval, governance and any newer/equal target-control assessment
are rechecked under locks. Grant expiry is min(proposal expiry, admission time + five minutes).

`REMEDIATION_ADMISSION_ENABLED` defaults false. Enabling requires explicit
`REMEDIATION_ACCOUNT_ID` and `REMEDIATION_REGION`, never scanner profile/Region fallback. This flag
only permits database admission; it cannot start AWS execution. Identical retries require current
EXECUTE and return historical authority without requeue/renewal, including when admission is off.
Expiry/revocation is derived on READ without changing history or erasing reservations.

Immutable requests/events with full human context and paired audit, restrictive references,
protected coordination rows and a global 32-reservation cap constrain database effects. Cleanup
may release only validated no-dispatch QUEUED history, atomically with a successful new admission.
Future intent/unknown/quarantine phases must not inherit time-based release. Privileged INSERT
or schema changes remain outside these integrity guarantees; protect services, operators/backups.
Scanner credentials stay read-only. There is no worker, write credential setting/acquisition,
live AWS check, automatic rescan or browser mutation. Future worker/live-operation gates remain.

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
