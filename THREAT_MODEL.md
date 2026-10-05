# Threat model

Status: living model for accepted Sprints 0--7
Accepted baseline: `main` commit `b90bf08eeb79ba56d5308f19a942c6c10bf41b28` (Sprint 7 closeout PR #51)
Last reconciled: 2026-10-05; 7A--7E accepted with independent review and green merged-main CI

7E whole-sprint acceptance is COMPLETE; combined tests/documentation and a bounded Firefox
test-launch isolation repair change no application runtime or security boundary. Original
navigation/security assertions, COOP and other headers, dependencies, timeouts and zero retries
remain unchanged. Exact-head independent review, both final-head CI runs, guarded ordinary merge
and merged-main CI passed. Sprint 8 is NEXT only, not implemented; residual risks remain open.
See the [7E evidence matrix](docs/sprint-7e-acceptance.md) for offline coverage and explicit limits.

## Scope and security objectives

Accepted 6G addresses case-folded tag matches, blank values treated as usable, malformed/unavailable
tags treated as absence or safety, failed family discovery hidden by other successful targets,
and rehashed forged source/policy/applicability proofs. Exact same-scan source joins and shared
engine/persistence recomputation retain uncertainty. Ungoverned targets do not become governed;
AWS-reserved keys are ineligible. Lossless tag encoding is not redaction and preserves sensitive
data. Narrow category migration must retain all history/integrity/transaction boundaries and
reject incompatible downgrades before DDL. Configuration presence does not prove ownership,
CMDB truth or compliance. Independent review and merged-main CI passed; see
[6G metadata](docs/controls/sprint-6g-metadata.md).

Accepted 6F.2 addresses substituted destination/owner/Region snapshots, cross-scan/profile/catalog
dependency reuse, rehashed forged decisions/proofs and disabled prerequisites mistaken for safety.
Only an exact GetTrail-provenance destination consumes a separately validated same-invocation
S3-002 result; partial required collectors, ambiguous/unresolved destinations and unavailable
dependency evidence stay insufficient. An observed trail cannot become N/A. Read-only contexts
are independently reconstructed before persistence; no historical-result lookup or duplicate
exposure evaluator. No AWS calls/writes or policy overwrite. Acceptance/review and main CI passed.
See [6F.2 metadata](docs/controls/sprint-6f2-metadata.md).

Accepted 6F.1 implementation addresses fabricated trail coverage, incomplete discovery treated
as empty, cross-trail selector unions and substituted identity/source proofs. Shared engine/
persistence recomputation passed acceptance. LOG-003 does not mistake
an enabled setting for verified digests. Strict new-schema projection/proof type comparisons
reject boolean/numeric substitution even when an artifact's digest is recomputed; historical
schema behavior remains unchanged. The new acceptance path exposes a pre-existing
availability/integrity mismatch for unresolved regional destination references. The separately
approved migration `20261001_0005` retains unknown Regions only for unresolved references;
complete identities, provenance and immutability remain strict. Writer-serialized pre-DDL
downgrade checks prevent newly representable history from being lost or misrepresented.
No source proof can treat an unresolved reference as a resolved endpoint. See
[6F.1 metadata](docs/controls/sprint-6f1-metadata.md).

6E.3 addresses false-safe sensitive-bucket classification and unresolved/substituted KMS
references in opt-in `0.10.0`. Shared engine/persistence recomputation binds classifier
version/checksum, exact owner/home Region, matched inputs and same-scan key/source/edge proof.
Unknown tags are not empty tags, a disabled KMS requirement cannot hide unknown classification,
and bucket disappearance invalidates applicability. Historical classifier substitution and
rehashing a forged assessment do not bypass validation. Residual limits: default configuration
does not prove existing-object encryption, upload enforcement, key access/availability or
rotation. No new AWS write or authentication surface. See [6E.3 metadata](docs/controls/sprint-6e3-metadata.md).

6E.2 addresses false-safe S3 exposure aggregation and historical approval substitution in opt-in
`0.9.0`. Independent coherent violations outrank unknown channels; contradictory sources retain
uncertainty and detected disappearance invalidates the bucket snapshot. Exact home-Region/owner
identity, immutable policy checksums and shared engine/persistence recomputation prevent forged
exemptions or decisions from being accepted. Access Analyzer and operational exceptions do not
approve direct exposure. Residual exclusions include object ACLs, access points and full effective
IAM/SCP/RCP evaluation; see the [canonical contract](docs/controls/s3-002-exposure-aggregation.md).
No new AWS credential, write, authentication or authorization surface is introduced.

Approved 6A adds an operator-controlled local policy-file input and immutable artifact registry.
Threats include replacing policy content under reused versions, substituting current policy on
restart, fabricated evidence citations, and destructive rollback of extended history. Mitigations
are strict schema/checksum dispatch, exact persisted catalog verification before AWS work,
cross-profile artifact identity enforcement, shared source/target validation, and a pre-DDL
downgrade guard with writer exclusion. The file remains sensitive operator-managed configuration,
not an authentication input or remotely editable resource. The five existing controls retain
their whole-collector evidence guard; a partial scan cannot newly resolve a finding.

The model covers AWS credential use, fact collection, deterministic assessment, PostgreSQL
history, the source-outcome/relationship evidence-graph foundation, the service layer,
OIDC/development authentication, capability authorization, FastAPI, and the in-process scan
executor. It includes the merged 5A fact-only EC2/EBS producer, the merged 5B fact-only
security-group, VPC, subnet, and Flow Log implementation, the merged fact-only 5C IAM account,
identity, and policy implementation, and the merged fact-only 5D IAM Access Analyzer producer. No
production deployment, Terraform infrastructure, remediation execution, or AI agent is
implemented. The opt-in 7B frontend/session boundary below is accepted code, not a production
deployment or live-provider validation. The merged 5E and 5F producers collect facts only; accepted opt-in 6E evaluators
consume the 5E facts, while accepted 6F evaluates retained CloudTrail evidence.
6G required tags and whole-sprint 6H acceptance are accepted; Sprint 6 is complete and Sprint 7
is COMPLETE with accepted 7A--7E reporting, authenticated investigation, NIST context and
whole-sprint acceptance. Independent review passed with zero unresolved findings; required
implementation/documentary merges and final merged-main CI are complete.
6H changed no application/security behavior or residual risk. The 5F change adds no AWS write,
authentication, authorization, route, migration, or assessment-profile behavior. The bounded 5G
closure is accepted and merged without changing these boundaries.

Protect:

- AWS workload credentials and identity;
- normalized resource configuration and structured evidence;
- declared source manifests, normalized source artifacts/outcomes, and resource topology;
- profile, control, and framework integrity;
- assessment, finding, exception, and audit history;
- API tokens and authorization decisions; and
- service/database availability and scan capacity.

Security objectives are confidentiality of cloud evidence and credentials, integrity and
reproducibility of technical assessments, authorized access, append-only auditability, and bounded
failure behavior.

Accepted 7A adds only exact-scan technical-context READ aggregates. Sensitive count/account
metadata remains behind the real bearer/READ dependency in the same single trust domain (T03/T07).
Reports omit payloads/configurations/tags and live operational handling; success and report-specific
409 are no-store. Version/profile checks, exact same-scan snapshot joins and unique mapped-control
unions address T10/T13 reporting corruption without re-evaluating evidence or weakening persistence.
Collection gaps, four-state facts and unavailable coverage remain distinct; no score or framework
PASS is produced. A privileged database operator remains trusted. Tests use controlled test
JWKS but real production signature/issuer/audience/expiry/role verification, not dependency bypass.
No new AWS permission, tenant policy, browser/session or production boundary is introduced.
The [7B preflight](docs/sprint-7b-preflight.md) preserves the original analysis and subsequent
explicit design/implementation approval. Its boundary passed the required independent review.

Accepted 7B adds a same-origin, read-only browser shell and FastAPI BFF. Tokens remain
server-side; the existing bearer/READ API is re-entered with the user's verified access token.
Client-supplied roles, a dashboard cookie at `/api/v1`, arbitrary forwarding and mutation are
not authentication/authorization mechanisms. Cognito Essentials is the intended provider;
controlled-issuer tests do not prove live pool/MFA/ingress configuration. Defaults remain disabled,
with no development fallback, AWS permission, migration, tenant policy or accepted API change.
See [dashboard operations](docs/operations/dashboard.md) for configuration and residual limits.

The initial authorized 7B review found two medium issues: malformed non-ASCII state/CSRF and
unexpected callback failures could bypass query redaction/security headers, and cross-tab
logout/reauthentication could retain the old UI identity while using the new shared cookie.
Local repairs reject malformed opaque values safely, secure/redact unexpected dashboard 500s,
require a public expected-session context before READ forwarding, and clear pending UI through
credential-free ephemeral same-origin tab notifications. Context alone never authenticates a
request; scripts/extensions and the common READ trust domain remain existing residual risks.
Final local validation and the same reviewer's follow-up passed with zero unresolved findings;
both final-head CI runs, explicit human merge approval and merged-main CI passed through PR #43.
7B acceptance does not validate a live provider or production operations.

### Accepted 7C investigation extension

The accepted extension preserves T17--T19's bearer, session/context, origin, no-store/CSP and final
in-flight checks for an explicit bounded GET allowlist. Client binding checks do not authorize data.
New correctness threats include substituting latest/first-seen metadata for an assessed snapshot,
cross-scan/profile/control-version evidence, inferred graph links, invented unresolved endpoints,
and treating mutable ACCEPTED_RISK or stored ACTIVE as a historical technical result.
Exact snapshot/assessment/control-definition/checksum and typed artifact/digest/directional endpoint
binding checks reject mismatches. Text-only bounded disclosures never execute or follow metadata.
Selection/filter/identity changes clear prior details; abort/generation guards reject late reads.

Operational UTC response-production time is explicit and server-supplied; expiry equality is expired,
malformed/naive/missing times cannot yield eligibility. This is freshness-labeled current handling,
not an atomic report or exception state at scan time. No exception scheduler or mutation is added.
Residual risks remain organization-wide READ access, trusted same-origin scripts/extensions,
unpaginated resource/finding detail internals, offset-page drift, display truncation, one process
and unvalidated live IdP/TLS/MFA operations. NIST hierarchy work is not part of 7C.

### 7D display integrity — accepted

New client display risks are cross-release UUID/key substitution, orphan/cyclic hierarchy,
mapping fan-out inflating parent/headline counts, malformed scalar/coercive IDs and treating
disabled/unmapped/unavailable rows as passing outcomes. A separate validator checks exact
release/reference/control-version binding, strict types, safe counts and server-projected unions
before any hierarchy/count rendering. Invalid NIST data does not substitute previous data or
disable independently valid investigation. Selection/refresh/session changes reset disclosures;
the existing authenticated report's abort/generation and logout/expiry guards remain in force.

Explicit exact release selection and non-additive mapped-subset labels prevent implicit latest
or whole-CSF claims. Text-only bounded disclosures prevent metadata execution/navigation;
digests are retained provenance, not browser certification of unseen source bytes. No new
server route, query, AWS call, credential or mutation is introduced. Existing organization-wide
READ, trusted same-origin scripts/extensions, upstream payload size and live-provider/production
limitations remain. Local validation, exact-head independent review with zero unresolved findings,
both final-head CI runs, guarded merge and merged-main CI passed for 7D. Whole-Sprint-7
acceptance and documentary closeout are COMPLETE through PR #50/#51 with exact-head review
and green final main CI; live-provider/
production validation remains separate and unstarted.

## Trust boundaries and assumptions

Approved 6E.1 binds S3-001/003 results to complete discovery, authoritative same-owner bucket-home
Region, and exact retained configuration source states/digests. Unavailable BPA is neither false
nor permission to invent protection; only supported universal insecure-transport Deny coverage
proves HTTPS enforcement. Missing policy differs from inaccessible policy. Shared result/proof
validation rejects substituted evidence and forged PASS/FAIL/N/A atomically. Prior catalogs,
pending-scan policy recovery, API authorization and complete-scan finding resolution are preserved.
The controls do not compute general effective permissions or authorize an AWS configuration change.

6D.2 binds NET-006 results to complete same-scan VPC/Flow Log facts and exact zero-or-more
relationship membership. Omitted matching edges cannot fabricate absence, non-VPC logs cannot
fabricate coverage, and external-owner VPCs remain insufficient under collection-account-only
Flow Log discovery. Engine and persistence re-evaluate the retained explicit policy; forged
PASS/FAIL/N/A and substituted source proofs are rejected. Partial scans still cannot resolve
findings. Authentication, authorization and sensitive-evidence exposure are unchanged.

Approved 6D.1 rejects missing, wrong-owner/Region or unresolved VPC edges and incomplete discovery
before making a decisive network assessment. Shared source-bound proof and pure result validation
reject forged PASS/N/A, including N/A substituted from a different high-risk-port profile.
Old catalogs and their whole-collector/finding-resolution guards remain unchanged. Complete
required sources may support an assessment during an unrelated source failure, but cannot resolve
an existing finding through a partial scan. No new AWS or authorization boundary is introduced.

Approved 6C mitigates ambiguous cross-account/Region public-IP approvals by matching canonical
stable resource UUIDs only. Required discovery/admission/configuration facts and N/A applicability
are revalidated at engine and persistence boundaries. Regional EBS defaults cannot be collapsed
into global or volume targets. Source failure cannot prove empty inventory, and unavailable
optional KMS context cannot erase an independently proved encryption boolean. No new AWS,
authentication, authorization or deployment boundary is introduced.

Approved 6B.1 adds IAM-002/003/005/006 in opt-in catalog `0.3.0`, not the default catalog. Its
joined evidence boundary rejects incomplete enumeration, unresolved/missing key edges, mismatched
identity/provenance, and ambiguous last-use facts. Observation-time thresholds and exact catalog/
profile recovery preserve replay. New framework subset bytes have a separate identity and digest;
old mappings remain unchanged. These rules add no AWS calls or remediation handlers. Root-summary
presence checks do not establish centralized root-access posture or compromise.

Approved 6B.2 adds opt-in IAM-004 syntax evaluation. Its proof binds managed ARN/default version
or inline owner/name to retained snapshot/document digests and exact usage relationships.
Missing versions remain explicit insufficient targets; missing enumeration or usage cannot
masquerade as an empty policy population. Boundary-only documents remain in scope without
granting permissions. Old catalog/mapping bytes and historical artifacts are not rewritten.
No effective-authorization, remediation, or live AWS capability is added.

```text
external identity provider -> untrusted bearer token -> API authentication boundary
authenticated principal -> capability check -> service/API data boundary
browser -> untrusted cookie/metadata -> opt-in session/CSRF/BFF boundary -> real bearer API
trusted provider discovery/token/JWKS -> OAuth/OIDC verification -> process-local secret store
API process -> database credentials -> PostgreSQL history boundary
API/worker process -> AWS workload identity -> AWS account boundary
AWS API responses/resource metadata -> untrusted input -> collector normalization boundary
normalized source artifacts/outcomes -> provenance validation -> evidence-graph history boundary
```

The current deployment assumes one trusted security organization controls every account stored in
one database. TLS, ingress, OIDC issuance, secret storage, PostgreSQL network isolation, backups,
and runtime workload identity are supplied by the deployment environment.

## Threats, controls, and residual risk

| ID | Threat | Risk | Current controls | Residual risk / required action |
| --- | --- | --- | --- | --- |
| T01 | Unauthenticated access | High | Bearer dependency on every `/api/v1` operation; uniform sanitized 401 | Health, readiness, and API schema are public by design; keep their output non-sensitive |
| T02 | Authorization bypass | High | Central role-to-capability map; route dependencies; denied-path tests | Future mutation routes must test every role and object scope; `PROPOSE`/`APPROVE` are not yet exercised by APIs |
| T03 | IDOR or cross-account disclosure | High in multi-tenant use | UUID validation, authenticated `READ`, and explicit separation of collection account from observed resource owner | No tenant/account object authorization exists; graph filters are not policy, and persisted cross-account ownership does not create isolation. Deploy only within one trust domain until designed |
| T04 | JWT forgery, confusion, replay, or stale keys | High | JWKS signature; exact issuer/audience; `exp`/`sub`; asymmetric allowlist; bounded JWKS caching | Revocation, replay detection, token-age policy, and IdP operations are external; use short-lived tokens and TLS |
| T05 | Development auth in production | Critical | Configuration rejects development mode outside explicit local/test environments; Compose binds loopback | Misconfigured network exposure remains dangerous in local mode; never publish it |
| T06 | Scan abuse or denial of service | High | `EXECUTE` required; bounded two-worker/32-outstanding executor; 503 on capacity exhaustion | No rate limit, quota, cancellation, timeout, caller idempotency key, or global multi-process capacity control |
| T07 | Sensitive evidence exposure | High | Authentication, read capability, structured projections, sanitized failures, and no standalone artifact listing | Every reader can see all stored accounts, normalized source artifacts on outcome detail, topology, and detailed configuration; add field/object policy before broader tenancy |
| T08 | Audit tampering or ambiguous attribution | High | Transactional append-only audit guards and explicit actor subject on scan start | Guards reject audit UPDATE/DELETE but cannot prevent a privileged direct INSERT or require direct finding/exception writes to have a paired audit event; issuer, roles, and capability are not retained. Restrict database roles to service-only writes and protect operator access. |
| T09 | AWS credential theft or scanner overprivilege | Critical | Standard credential chain; no key settings; documented read-only calls; no AWS mutation code | Deployment owns role scope, rotation, metadata-service controls, and secret isolation |
| T10 | Assessment or history corruption | High | Checksums, composite foreign keys, immutable version checks, caller-owned transactions, audit/evidence-graph history guards, terminal graph-completeness checks, and fail-closed populated-downgrade preflights | Backups and operator access remain privileged; current migration tooling and an approved maintenance window are still required |
| T11 | Duplicate or abandoned scan execution | Medium | Durable IDs, startup resubmission, in-process de-duplication, idempotent persistence | Recovery is startup-only; multiple API processes can duplicate AWS work; no lease/heartbeat/periodic recovery |
| T12 | Malicious or malformed AWS metadata | Medium | Explicit typed response-boundary validation, strict identities and promoted nested facts, sanitized evidence errors, duplicate consistency checks, strict normalized source artifacts/outcomes, Pydantic normalization, deterministic rules; 5A isolates its four sources, 5B independently paginates network sources, 5C independently validates IAM sources, 5D validates and fully paginates Analyzer sources, 5E strictly validates independent S3/KMS sources, and 5F isolates CloudTrail identity/configuration/status/selector/tag sources while retaining valid siblings | Remaining legacy collectors still discard the affected collector's otherwise valid items on malformed data |
| T13 | Profile, mapping, or source-manifest substitution | High | Explicit numeric profile version, content checksums, fail-closed version-content conflict, exact persisted-profile loading for pending scans, graph-derived source-manifest version/digest, mapping/reference validation; accepted 5A through 5F emit digest-bound exact source manifests, with execution selected from exact persisted service intent | Operators must deploy reviewed new policy versions; no automatic semantic ordering or policy approval workflow exists; the 5F `cloudtrail-evidence` marker must remain exact and fail closed |
| T14 | Dependency, image, or CI compromise | High | Minimal dependencies, bounded backend ranges, exact frontend versions/lockfile, pinned Node/pnpm, least-privilege CI, tests/PostgreSQL/image build | No backend lockfile/SBOM or comprehensive security scans; action/base-image tags remain mutable. Review every dependency, action and base-image update |
| T15 | Database exposure or destructive migration | Critical | Loopback local port, migrations, PostgreSQL constraints, no automatic schema creation | Production network/backup/credential controls are external; never mutate production without explicit approval |
| T16 | Fabricated, misdirected, or overwritten graph evidence | High | Deterministic graph IDs; strict endpoint direction/scope/Region; exact scan/account/time binding; one outcome and an exact artifact reference per declared source; `PRESENT`-outcome relationship provenance; same-scan snapshot foreign keys; append-only guards; closed exceptional-owner admission; 5A never invents referenced owners; 5B refines owner-incomplete targets only with exact proof; 5C keeps collection account distinct from IAM policy owner; 5D admits supplemental discovery only with exact same-scan S3 Region proof; 5E requires authoritative bucket location and canonical returned KMS identity; 5F keeps collection account, trail owner, and organization context distinct and resolves S3/KMS edges only from exact same-scan evidence | A privileged database/schema operator remains trusted, and unresolved targets remain unavailable for any future rule that requires a resolved edge |
| T17 | Browser token/code theft, XSS and evidence caching | High | Accepted 7B: opaque HttpOnly host-only cookies; server-only tokens; scoped CSP/no-store/no-referrer including unexpected 500s; text-only metadata rendering; clean callback redirect and error-path access-log query removal; identity-client debug redaction; no Web Storage/offline cache/third-party assets | Controlled-issuer acceptance only; live setup unvalidated. HttpOnly does not prevent malicious same-origin scripts making reads. Ingress must also omit callback queries; process memory and browser extensions remain trusted |
| T18 | Login CSRF, code/session substitution and logout bypass | High | Accepted 7B: exact trusted origin, safely bounded ASCII CSRF/state, browser-bound one-time state/nonce/S256 PKCE; library ID-token verification plus real access-token verification; rotated opaque session; expiry and server-side logout | Controlled-issuer acceptance only; live setup unvalidated. Dashboard logout does not revoke the provider's login or issued token; short token lifetimes and live provider policy remain operator duties |
| T19 | BFF confused deputy, session exhaustion and stale UI identity | High | Accepted 7B/7C: explicit typed bounded scan/report/investigation GET allowlist through real READ dependencies; mandatory expected public session context; credential-free ephemeral cross-tab clearing; no upstream/header/method injection; 100 pending/1,000 session caps; 15-minute idle/60-minute absolute/token expiry; final in-flight read check and frontend abort/generation guards | Controlled-issuer acceptance only; live setup unvalidated. Single process only, restart requires login, no distributed session store/rate limit/tenant isolation. Every reader still sees the same trusted organization's data; same-origin scripts/extensions remain trusted |

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
