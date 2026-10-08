# Service API

This is the authoritative human-readable contract for the accepted Sprint 4 API, the accepted
Sprint 5 shared evidence-graph reads, and the accepted 5A EC2/EBS, 5B network, 5C IAM, and 5D IAM
Access Analyzer, 5E S3/referenced-KMS, and 5F CloudTrail evidence producers. The accepted 5F
producer projects through those same generic interfaces without adding a service-specific route.
OpenAPI at `/openapi.json` is the exact generated schema; `/docs` and `/redoc` render it.
All slices use the existing generic scan and read interfaces; fact-only collection does not
implicitly enable Sprint 6 controls. Accepted controls through `0.13.0` reuse those interfaces
without per-control routes. Future interface changes must update this document and
tests in the same change.

Accepted Sprint 7A adds the READ reporting contract below, merged through PR #42 with
independent review and merged-main CI passing. Exact acceptance is recorded in the
[completed Sprint 7 plan](exec-plans/completed/sprint-7.md). Existing interfaces retain their meanings.
Accepted 7B adds the separate opt-in browser interface below through PR #43, with independent
review, explicit merge approval and green merged-main CI; it does not change `/api/v1`.
Accepted 7C adds the optional exact-scan resource-history filter and explicit investigation
BFF GETs through PR #45 and test-only CI repair PR #46, with exact-head independent review and
green merged-main CI.
Existing response bodies, omitted-filter behavior, roles and capability checks remain unchanged.
Accepted 7E whole-Sprint-7 tests verify those unchanged interfaces through PR #50 with exact-head
independent review and green main CI. No new API schema or production-authentication behavior
is introduced; the [evidence matrix](sprint-7e-acceptance.md) records offline scope and limits.
The separate Sprint 7 documentary closeout is accepted through PR #51 with exact-head review,
both green final-head CI runs and green final merged-main CI at
`b90bf08eeb79ba56d5308f19a942c6c10bf41b28`. Subsequent documentation reconciliation PR #52
is accepted at `20c04665f89ae8c8cf9348603fd54e0e100b6076` with merged-main CI 37354537175;
it changes no interface or capability. The Sprint 8A proposal/decision extension below is accepted
through PR #53 at `691d8814c785feafc0d9d3b3b43d7d1af89542a0`, with exact-commit independent
review, both final-head CI and green exact main CI 37693245169. 8A added no execution endpoint.
The approved local 8B1 admission-only extension below is pending acceptance and cannot call AWS.

Accepted [6H](controls/sprint-6h-acceptance.md) verifies all 26 supported controls / 39 assessments
through the real authenticated asynchronous scan and public resource/history, evidence/source,
relationship, finding/exception and framework read APIs on SQLite and PostgreSQL. Only AWS is
offline in these tests; development bearer authentication remains explicit test-only. No API
shape, capability or production-authentication change was introduced by acceptance/closeout.

The pre-8A accepted baseline was read-only apart from creating a scan. Accepted 8A appends
remediation proposal/decision authority and paired audit history. It cannot modify AWS resources,
finding status, exceptions, controls, mappings or existing audit history.

## Authentication

Accepted opt-in catalog `0.12.0` (PR #38; merged-main CI passed) adds LOG-004 through the same generic
authenticated interfaces, without new request/response fields, routes or capabilities. Decisive
payloads contain strict-type proof `1.9.0`, exact source/destination relationship citations and
the validated same-scan S3-002 dependency result/target/evidence digests and policy/profile
identity. The new versioned execution metadata declares only that dependency; historical
definitions omit the additive metadata field. Missing/disabled dependencies remain insufficient;
no control is implicitly enabled. See [6F.2 metadata](controls/sprint-6f2-metadata.md).

Accepted opt-in catalog `0.11.0` adds LOG-002/003 through the same generic
interfaces. LOG-002 is a global account assessment; LOG-003 uses exact trail snapshots or the
complete-empty account fallback. Decisive payloads contain `source_proof` schema `1.8.0` and
`evaluation_version` `1.0.0`, with exact same-scan source citations and trail identity/facts.
N/A/insufficient retain the existing artifact convention. The approved persistence repair
lets the existing relationship union return unresolved regional references with a null Region;
it does not fabricate a stable resource, prove resolution or add response fields/routes.
Authentication/capabilities are unchanged. See [6F.1 metadata](controls/sprint-6f1-metadata.md).

Opt-in catalog `0.10.0` adds S3-004 through these same generic authenticated interfaces,
without new routes or fields. Decisive evidence binds classifier identity/version/checksum,
classification reason/matches, profile checksum and same-scan bucket/key/source/edge proofs.
N/A retains policy via immutable scan/profile history, not a new decisive evidence artifact.
ADMIN can scan; ANALYST remains denied. No default or role change.
See [6E.3 metadata](controls/sprint-6e3-metadata.md).

Opt-in catalog `0.9.0` adds S3-002 through the same authenticated generic interfaces, without
new routes or response fields. Its evidence payload includes exact source citations, bucket
identity, channel outcomes, effective BPA and historical approval/profile checksums. It does
not expose the approval records for unrelated buckets. ADMIN can scan; ANALYST remains denied.
See [6E.2 metadata](controls/sprint-6e2-metadata.md). Defaults and role capabilities are unchanged.

Opt-in catalog `0.8.0` adds S3-001/003 through the existing scan, resource/history,
assessment/evidence, finding and control/framework routes. Evidence binds exact same-scan
account/bucket sources and home-Region identity. No API, role or capability changes; ADMIN
can scan and ANALYST cannot. Default `0.2.1` remains unchanged.

Opt-in catalog `0.6.0` exposes NET-003/004/005 through the same scan, resource/history,
assessment/evidence, finding and control/framework routes. Proofs identify exact same-scan VPC
relationship observations and source artifacts. No route, request schema, role or capability
changes. ADMIN can scan; ANALYST remains denied.

Opt-in catalog `0.7.0` adds NET-006 through those same interfaces, with exact versioned environment
and traffic policy and retained VPC/Flow Log source/relationship IDs. No request/response field,
route, permission or authentication change is introduced; the default catalog is unchanged.

Opt-in catalog `0.5.0` adds EC2-001 through EC2-004 through the existing authenticated scan,
resource/history, assessment/evidence, finding and control/framework reads. No route or request
field is added. EC2-004 uses a Regional `ec2/aws_account` assessment-only target, with its own stable
resource and snapshot history, not a fabricated collector graph endpoint. EC2-002 approvals use
the existing `resource_id` UUID from generic resource reads, never the bare instance identifier.

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
boundary when writing examples or tests. Accepted 8A uses `PROPOSE` for proposal creation and
`APPROVE` for decisions and revocation; the role map and scan authorization are unchanged.

Authorization is control-plane-wide. A principal with `READ` can query all accounts persisted in
this database; tenant/account claims and row-level object authorization are not implemented. The
accepted deployment assumption is one trusted security domain.

## Endpoints

| Capability | Method and path | Purpose |
| --- | --- | --- |
| `EXECUTE` | `POST /api/v1/scans` | Persist and submit a single-region scan |
| `READ` | `GET /api/v1/scans` | List scan lifecycle records |
| `READ` | `GET /api/v1/scans/{scan_id}` | Read exact scan provenance and scope |
| `READ` | `GET /api/v1/scans/{scan_id}/technical-posture` | Read exact-scan counts, coverage and mapped technical context (accepted 7A) |
| `READ` | `GET /api/v1/resources` | List stable AWS resource identities |
| `READ` | `GET /api/v1/resources/{resource_id}` | Read identity and latest observation |
| `READ` | `GET /api/v1/resources/{resource_id}/history` | Read immutable observations |
| `READ` | `GET /api/v1/relationships` | List immutable directional relationship observations |
| `READ` | `GET /api/v1/relationships/{observation_id}` | Read one relationship observation and its provenance |
| `READ` | `GET /api/v1/source-outcomes` | List declared source evidence results |
| `READ` | `GET /api/v1/source-outcomes/{source_outcome_id}` | Read one outcome and its normalized artifact |
| `READ` | `GET /api/v1/assessments` | List four-state technical results |
| `READ` | `GET /api/v1/assessments/{assessment_id}` | Read evidence and framework mappings |
| `READ` | `GET /api/v1/findings` | List current finding state |
| `READ` | `GET /api/v1/findings/{finding_id}` | Read occurrences and exceptions |
| `READ` | `GET /api/v1/controls` | List stable controls and versioned definitions |
| `READ` | `GET /api/v1/controls/{control_id}` | Read definitions and mappings |
| `READ` | `GET /api/v1/frameworks` | List immutable framework versions |
| `READ` | `GET /api/v1/frameworks/{framework_id}` | Read hierarchy and control mappings |
| `READ` | `GET /api/v1/exceptions` | List explicit operational exceptions |
| `READ` | `GET /api/v1/remediations` | List stored proposals with derived validity (accepted 8A) |
| `READ` | `GET /api/v1/remediations/{proposal_id}` | Read immutable intent and decisions (accepted 8A) |
| `PROPOSE` | `POST /api/v1/remediations` | Append a proposal, not execute an action (accepted 8A) |
| `APPROVE` | `POST /api/v1/remediations/{proposal_id}/decisions` | Append the unique initial APPROVE or REJECT (accepted 8A) |
| `APPROVE` | `POST /api/v1/remediations/{proposal_id}/revocations` | Revoke an existing approval (accepted 8A) |
| `EXECUTE` | `POST /api/v1/remediations/{proposal_id}/executions` | Record a third-human request only (local 8B1, pending acceptance) |
| `READ` | `GET /api/v1/remediation-executions` | List requests and derived validity (local 8B1) |
| `READ` | `GET /api/v1/remediation-executions/{execution_id}` | Read request, journal and reservation state (local 8B1) |

There is no exception-detail route, audit route, finding/exception mutation, rescan/retry,
cancellation, proposal withdrawal, AWS remediation dispatch or arbitrary AWS-call endpoint.
`AuditService` is an internal service boundary only. The dashboard BFF allowlist is unchanged and
does not proxy these new authority routes; dashboard cookies never authenticate `/api/v1`.

<a name="sprint-8a-proposal-and-decision-contract--local-pending-acceptance"></a>

## Sprint 8A proposal and decision contract — accepted

All three POSTs require a bearer capability and a UUID `Idempotency-Key` header. Keys are scoped
to the full verified issuer/subject pair and operation (`CREATE`, `DECIDE`, `REVOKE`), across all
proposals. Reuse with identical normalized input returns the original immutable record with HTTP
200; first creation returns 201. Reuse with different input, including a different target proposal,
returns 409. Current capability is checked even on replay; a retry does not renew an expiry or
approval. Reasons are stripped, nonblank and at most 2,000 characters; unknown body fields fail
validation rather than becoming AWS parameters.

`POST /remediations` accepts only these body fields:

```json
{
  "finding_id": "<finding UUID>",
  "occurrence_id": "<occurrence UUID belonging to this finding>",
  "action_id": "aws.ec2.enable-ebs-encryption-by-default",
  "action_version": "1.0.0",
  "reason": "Reviewed workload and default-key compatibility."
}
```

The server derives account/Region and fixed false-to-true intent; only EC2-004 is supported.
Creation requires a completed explicit FAIL, false encryption default, validated complete
encryption/default-KMS sources, an OPEN/ACKNOWLEDGED finding and no active unexpired exception.
Complete expected absence of a default KMS key is recorded explicitly, not confused with
unavailable evidence. No control/profile is enabled by creating a proposal.

The response `ProposalView` contains immutable `content`, `proposal_sha256`, historical
`approval_status`, derived `blocking_reasons`, `validity_checked_at`, and immutable `decisions`.
Content includes the proposal/finding/resource/control IDs, action/risk, verified proposer,
reason, server creation and 24-hour expiry, governance digest and exact baseline: occurrence/
assessment/scan/snapshot IDs, observation/state/inventory digests, profile/catalog/control
versions/checksums, assessment evidence bindings, source-outcome/artifact/reference/digest
bindings, default KMS key ID and explicit expected-absence flag. OpenAPI owns the exact fields.
The digest covers canonical JSON of the whole immutable content, not only the action parameters.

`POST /remediations/{proposal_id}/decisions` accepts `proposal_sha256`, `decision` (exactly
`APPROVE` or `REJECT`) and `reason`. It returns an immutable `DecisionView` with decision/proposal
IDs, kind, proposal digest, nullable approval reference, verified actor, reason and server time.
The actor must differ from the proposer by verified issuer/subject, including ADMIN. APPROVE
requires current eligibility, exact bindings and unexpired lifetime. Any other assessment for
the stable target/control at a newer or equal observation time invalidates approval regardless
of result; a changed finding/exception governance digest also invalidates it. REJECT can close
an undecided stale/expired proposal. There can be only one initial decision; no reversal or
reapproval endpoint exists.
Governance binds append-only finding event IDs, not only current status. Returning to the original
finding status, including with equal-time events, cannot remove STALE_GOVERNANCE or revive old
approval. Pre-repair local proposals require new intent under the tightened digest rule.

`POST /remediations/{proposal_id}/revocations` accepts `proposal_sha256`, the exact
`approval_decision_id` and `reason`. Any APPROVE principal may append one terminal REVOKE of that
proposal's approval, even when stale/expired; a proposer with APPROVE may remove authority.
It returns `DecisionView`. References to a different approval/proposal conflict.

`approval_status` is one of `PROPOSED`, `APPROVED`, `REJECTED`, `REVOKED`; it is not a finding,
technical assessment or execution status. An APPROVED record stays historically APPROVED when
expired/stale, with blocking reasons `EXPIRED`, `STALE_TARGET`, `STALE_GOVERNANCE`,
`INELIGIBLE_FINDING`, `ACTIVE_EXCEPTION` or `INVALID_PROVENANCE` as applicable. GETs recompute
these checks from retained data without writes or AWS calls. Empty blocking reasons are not a
live-state guarantee or permission to execute. Only a new proposal can bind a refreshed baseline.

Missing/invalid bearer identity is 401, missing capability or self-decision is 403, unknown IDs
are 404, invalid typed requests/headers are 422, and state/digest/eligibility/idempotency conflicts
are sanitized 409. Database operational failures during mutations are sanitized 503; unexpected
read failures retain the ordinary sanitized 500 boundary. New success responses and
remediation-specific errors use `Cache-Control: no-store`; never cache sensitive proposal data.
No response carries AWS credentials, JWTs or raw SQL/provider failures. See
[remediation operations](operations/remediation.md) for identity and remaining workflow limits.

## Sprint 8B1 execution admission — local, pending acceptance

This approved addition records authority only. No worker, AWS call, write credential, verification
scan or dashboard mutation is implemented. The 8A proposal/decision responses stay unchanged.

`POST /api/v1/remediations/{proposal_id}/executions` requires current `EXECUTE`, a UUID
`Idempotency-Key`, and exactly `proposal_sha256`, `approval_decision_id`, `reason`. Reasons use
the same stripped, nonblank, 2,000-character bound. Account/Region/action, role ARN, credentials,
endpoint and desired state are not caller parameters. The requester must differ from both the
proposer and approver by verified issuer/subject; ADMIN has no override. The exact approval must
be unrevoked, unexpired and eligible against retained provenance, governance and newer/equal
target-control history. These are database checks, not fresh AWS checks.

New admission is disabled by default. An explicitly enabled, exact configured account/Region
must match retained intent; missing scope fails startup. First admission returns 202; authorized
identical replay returns 200 with original content, without renewed authority or duplicate audit.
The actor/key namespace spans proposals; changed normalized input returns 409. Replay remains
readable when new admission is disabled, expired or revoked, but still requires current EXECUTE.
It is not dispatch or renewed permission. Each proposal has at most one execution request.

`ExecutionView` contains immutable `content`, `execution_sha256`, journal-derived `phase`, current
derived `blocking_reasons`, `validity_checked_at`, `reservation_held`, and immutable `events`.
Content embeds the full accepted proposal and exact approval with their digests, requester,
reason, idempotency key, creation time and expiry: the earlier of proposal expiry or creation plus
five minutes. Events bind sequence, previous digest, actor and paired audit. The only phases are
`QUEUED`, `EXPIRED`, `BLOCKED`; QUEUED means no worker has dispatched anything, not AWS success.
Validity adds `EXECUTION_EXPIRED` and `APPROVAL_REVOKED` to existing proposal blockers. READ never
appends a terminal event: a QUEUED history can have current blockers and still hold its reservation.

One outstanding request per account/Region/action and 32 database-wide outstanding reservations
are enforced under serialized admission. A subsequent successful admission may journal and release
only validated expired/ineligible QUEUED requests; cleanup rolls back with any failed admission.
There is no timer or worker recovery here. Disabled admission/capacity/database failures return
sanitized 503, scope/reservation/state/provenance conflicts 409, separation/capability denial 403.
Ordinary 401/404/422 behavior remains unchanged. New success and remediation errors use no-store.

Execution list/detail requires READ; list accepts `proposal_id` UUID, limit 1--100 (default 50) and
nonnegative offset, ordered by creation descending then execution UUID. Like 8A, readers share
one trust domain; filtering is not tenant authorization. See [operations](operations/remediation.md).

## Filtering and pagination

| List | Optional filters |
| --- | --- |
| scans | none |
| resources | `account_id`, `service`, `resource_type`, `region` |
| resource history | optional `scan_id` UUID; omitted preserves all-history behavior |
| relationships | `collection_account_id`, `scan_id`, `relationship_id`, `source_resource_id`, `target_resource_id`, `target_reference_id`, `relationship_type`, `resolution` |
| source outcomes | `collection_account_id`, `scan_id`, `contract_key`, `collector`, `phase`, `subject_resource_id`, `evidence_kind`, `state` |
| assessments | `scan_id`, `resource_id`, `control_id`, `result` |
| findings | `account_id`, `resource_id`, `control_id`, `status`, `region` |
| controls | `category`, `severity`, `resource_type`, `catalog_key` |
| frameworks | `framework_key`, `version` |
| exceptions | `finding_id`, `resource_id`, `control_id`, `status` |
| remediations (accepted 8A) | `finding_id`, `account_id` (12 digits) |
| remediation-executions (local 8B1) | `proposal_id` UUID |

Accepted 6G adds the public control category `governance`. Existing category values, response
shapes, capabilities and generic control filtering are unchanged. The category migration and
GOV-001 are accepted through PR #39 with green merged-main CI. Its generic resource-type
filter uses the 11 declared execution families. No response field or route changes. See
[6G metadata](controls/sprint-6g-metadata.md).

Every list uses offset pagination with `limit` defaulting to 50, a maximum of 100, and `offset`
defaulting to 0. Responses contain `items`, `total`, `limit`, and `offset`. Service queries use
deterministic ordering, but offset pages and totals are not a transactionally frozen snapshot;
concurrent writes can move items between requests. Control filters select controls with at least
one matching version and return all versions for each selected stable control.

Enum values, UUID formats, request constraints, and exact response fields are defined by OpenAPI.

## Machine-readable results

The API keeps IDs and facts in explicit fields, including `scan_id`, `resource_id`, `snapshot_id`,
`assessment_id`, `finding_id`, `control_id`, `source_outcome_id`, `artifact_id`,
`relationship_id`, `observation_id`, result/status values, structured evidence payloads,
occurrences, profile/catalog/source-manifest checksums, collection outcomes, and framework
mappings. Clients must not parse prose to recover these relationships.

`Resource` is stable identity and `latest_snapshot` is the newest observed state. History returns
immutable snapshots. The top-level stable resource ARN is first-seen metadata; when an ARN changes,
the latest snapshot's ARN is the current observed value.

Evidence and normalized configurations can contain sensitive infrastructure data. A caller with
`READ` is trusted to receive it.

## Exact-scan technical posture — 7A

`GET /api/v1/scans/{scan_id}/technical-posture` requires the existing `READ` capability.
It performs retained-data reads only: no AWS call, evaluation, finding/exception change,
transaction write or selection of a latest catalog/profile. Successful responses and the
report-specific provenance-conflict response set `Cache-Control: no-store`. Account identifiers
and aggregate security facts remain sensitive; no tenant isolation is added.

The report's `schema_version` is `1.0.0` (a reporting schema, not an evaluator/proof version),
and its `interpretation` is `TECHNICAL_CONTEXT_ONLY`. It contains:

- `scan`: the unchanged exact `ScanDetail`, including lifecycle, collection account,
  requested/successful scope, checksums, retained scope/outcomes and sanitized failure context;
- `catalog`: exact persisted `catalog_id`, `catalog_key`, `version` and `content_checksum`;
- `assessment_profile_version_id` and sorted `enabled_controls`: the scan's exact retained
  profile, never the deployment's current default;
- `control_coverage`: registered/enabled/disabled definition counts, plus nullable
  assessed/unassessed enabled-control counts;
- `assessment_counts`: four-state unique-assessment counts, or null when unavailable;
- `targets`: assessed-snapshot groups, or null when unavailable;
- `controls`: definitions from that exact catalog, with enablement, assessment coverage/counts,
  exact control/version IDs, definition checksum and existing framework-mapping provenance; and
- `frameworks`: only exact framework releases mapped by those control definitions, with their
  retained hierarchy, source/retrieval/checksum metadata and mapped technical-context rows.

`availability` is separate from both scan lifecycle and technical assessment results:

| Availability | Meaning | Assessment counts / targets |
| --- | --- | --- |
| `IN_PROGRESS` | The scan is `RUNNING` | null / null |
| `AVAILABLE` | A terminal scan retains scope, inventory digest and result checksum | Four-state counts / assessed-snapshot groups |
| `UNAVAILABLE` | A terminal scan lacks retained result-bundle metadata | null / null |

A failure digest alone is not a result bundle. PARTIAL or FAILED scans with retained results
show those facts alongside collection gaps; an independently valid assessment is not discarded.
The reused scan-detail failure prose is not the reporting-availability indicator. Never interpret
null as zero failures or infer complete collection from `AVAILABLE`.

Each counts object has only `pass_count`, `fail_count`, `insufficient_evidence_count` and
`not_applicable_count`. Headline counts include each retained assessment exactly once, independent
of mapping fan-out. Control counts and target-assessment counts are different dimensions.
Control `assessment_coverage` is `ASSESSED`, `UNASSESSED`, `DISABLED` or `UNAVAILABLE`;
these are reporting labels, not new technical results. `unassessed_count` counts enabled controls
without retained assessments when a bundle is available. Disabled definitions are not N/A.
No overall PASS/FAIL, score or compliance percentage is returned.

An empty retained enabled-control set means none enabled, not a safe environment. Accepted
completed-scope validation still requires at least one enabled control and an explicit assessment
for every enabled control. The reporting labels do not relax these persistence contracts;
empty pending-profile coverage remains unavailable rather than a zero-failure terminal summary.

Each target group identifies `target_kind` (`ACCOUNT` or `RESOURCE`), actual resource-owner
`aws_account_id`, service/resource type, snapshot scope/Region, `assessed_snapshot_count`
and four-state counts. Global account, regional account-setting and resource groups stay distinct.
Multiple controls on one snapshot count once in snapshot coverage but once per assessment in
technical counts. Unassessed collected inventory is not target coverage. Supplemental/home
Regions and external owners do not imply full Region collection or account authorization.

Each framework has `interpretation=MAPPED_TECHNICAL_SUBSET`. Reference rows retain exact UUID,
display key, level, title and parent UUID. `mapped_control_version_ids` is the unique union of
direct and descendant mappings within that exact framework release; parent counts include each
contributing control's assessments once. A reference's coverage is over its mapped definitions,
not the whole catalog or CSF Core. Overlapping references/frameworks are not additive global
totals. Equal display keys in different local subset releases are never merged.
Unmapped or disabled-only rows have no assessed technical coverage, not a passing NIST outcome.
Unsupported/manual outcomes remain unassessed by the scanner; no manual-attestation store,
manual result enum or claim of whole-framework satisfaction is introduced.

The response omits configurations, tags, evidence payloads, assessment reasons and current
finding/exception handling. Use existing scan-filtered assessment and authorized detail APIs
for investigation. Exceptions never rewrite these historical technical counts.
Existing list pagination and filters are unchanged; this is a single-scan aggregate, not a
cross-account/latest-scan rollup. See [framework interpretation](frameworks/nist-csf-2.0.md).

## Evidence-graph reads

Relationship list and detail responses expose the controlled relationship type and resolution,
the complete source endpoint, either a complete target endpoint or a deterministic unresolved
target reference, the stable logical `relationship_id`, the per-scan `observation_id`, the source
outcome ID, schema version, and sanitized provenance. Direction is authoritative; clients must not
infer a reverse edge. A `RESOLVED` target identifies its exact snapshot from the same scan. An
unresolved target is a reference only and is not a discovered `Resource`.

Source-outcome list responses expose the discovery or enrichment subject, state, controlled
failure category, collector/source API provenance, artifact identity/reference/digest, and schema
version. The detail route additionally returns the referenced normalized JSON artifact, including
its evidence schema/version and digest. It does not return raw AWS responses or provider exception
text. There is no standalone artifact route and no source-contract list/detail route;
`contract_key` is only a source-outcome list filter.

`GET /api/v1/scans/{scan_id}` exposes `scope.source_manifest_schema_version` and
`scope.source_manifest_checksum` when that scan persisted an evidence graph. Both are null for
graphless scans. The checksum binds the exact declared source contracts; it is not inferred from
outcome rows, and the full contract manifest is not returned by a public route. A current scan
emits 5A source outcomes and artifacts for EC2 instance discovery, EBS volume discovery, both
Regional EBS default-setting calls, and each normalized instance or volume. The accepted 5B
producer adds independent Regional discovery and per-resource evidence for security groups, VPCs,
subnets, and VPC Flow Logs. Identity-authoritative same-scan network observations resolve 5A's
partial instance references without assuming the collection account owns the target. The generic
relationship API exposes instance-to-network, security-group-to-VPC, VPC-to-subnet, and exact
VPC-to-Flow-Log observations. The accepted 5C producer exposes IAM resources, source outcomes,
and relationships through the same interfaces.

In the accepted 5D implementation, a new scan also declares `access-analyzer` service intent and
the `access_analyzer_evidence` collector. Its Regional analyzer discovery, per-analyzer finding
discovery, finding-summary, and fully paginated finding-detail observations are available through
the source-outcome list/detail routes. Each external-access S3 finding is a generic
`access-analyzer/access_analyzer_finding` resource; its history is available through the existing
resource routes and its `references_resource` edge to the exact S3 bucket is available through
the relationship routes. The normalized AWS finding resource is not a control-plane `Finding` and
does not decide `S3-002`.

On the accepted 5E path, scan detail includes the `kms` service-intent marker and
`s3_evidence` collector. Direct S3 discovery, authoritative bucket location, independent bucket
facts, account Block Public Access, and referenced-KMS observations use the same generic
source-outcome routes. Validated KMS keys are generic `kms/kms_key` resources, and bucket-to-key
`encrypted_with` observations use the generic relationship routes. No S3- or KMS-specific API
route is added, raw policy content is returned only inside the authorized normalized artifact or
snapshot projections, and these facts are not executable `S3-001` through `S3-004` results.
Sprint 0--4 collectors that have not been upgraded remain graphless.

The accepted 5F path adds the exact `cloudtrail-evidence` persisted intent marker and a
`cloudtrail_evidence` collector outcome to these same generic projections.
“Account to trails” remains source-manifest coverage attached to the verified scan account, not a
new account-resource endpoint or API shape. CloudTrail resources, source outcomes/artifacts, and
S3/KMS relationship observations use the existing generic endpoints; 5F adds no service-specific
route, API schema, or authorization behavior.
The source-outcome routes expose account discovery and independent per-trail identity,
configuration, status, event-selector, and tag observations. Relationship reads expose
`delivers_to_bucket` and `encrypted_with` observations with the existing resolved or typed
unresolved target contract.

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

6A does not change the scan request or capabilities. An operator may select a complete protected
local policy file at startup as described in [assessment configuration](assessment-foundation.md);
HTTP callers cannot supply policy paths or select catalog releases. Generic control-version
responses include `execution_contract` only for extended definitions; legacy responses omit it.
The resource-type filter matches exact declared resource-family types for extended definitions,
`aws_account` for account targets, and the existing `resource_type` field for legacy definitions.

6B.1's opt-in catalog `0.3.0` adds IAM-002/003/005/006 without new routes or caller-selected policy.
Their persisted results, source proofs, findings, and mappings use these generic reads. IAM key
controls expose execution schema `1.1.0`; root controls use the existing account-target schema.
Default catalog `0.2.1` and HTTP capability requirements remain unchanged.

6B.2's opt-in catalog `0.4.0` adds IAM-004 through the same generic interfaces, with execution
schema `1.2.0`. Its exact target families include managed policy versions and inline policies;
parent managed-policy targets represent unavailable default versions as insufficient evidence.
Assessment evidence exposes snapshot/document digest and retained attachment/boundary contexts,
not an effective-authorization claim. No request/route/capability or default-catalog change occurs.

The requested Region remains the only caller-supplied Region. On the 5E path, inventory assembly
collects each bucket in the home Region established by exact same-scan S3 location evidence and
looks up an explicit KMS reference in its proved Region. Access Analyzer runs in the sorted unique
bucket Regions only when the corresponding discovery/location manifest supports them. This does
not broaden the HTTP request model or authorize an arbitrary Region: persisted source contracts
and generic graph validation require exact proof.

The POST operation validates and persists the configured assessment-profile definition, then
writes a `RUNNING` scan and authenticated `SCAN_STARTED` audit event referencing that exact
profile before submitting work and returning HTTP `202 Accepted`. STS resolves the account in the
background; collection, deterministic assessment, and transactional persistence follow. Poll the
scan detail until `COMPLETED`, `PARTIAL`, or `FAILED`:

- `RUNNING`: durable identity exists; account, inventory digest, and scope may not exist yet.
- `COMPLETED`: all requested collectors and the requested Region succeeded.
- `PARTIAL`: a result bundle was persisted with incomplete requested collection, but not every
  requested collector failed.
- `FAILED`: every requested collector failed, or execution/persistence could not produce a normal
  result bundle; only bounded safe failure detail is returned.

The accepted executor uses a bounded in-process thread pool, startup resubmission, and graceful
shutdown. It is not a distributed queue. Run one API process; a horizontally scaled deployment
must provide a claim/lease-capable executor behind the same interface.

`ASSESSMENT_PROFILE_VERSION` must be numeric `X.Y.Z`. A policy-content change, including a change
to `REQUIRED_TAGS` or `STALE_ACCESS_KEY_DAYS`, must be deployed with a reviewed new version. An
existing `RUNNING` scan is unaffected by later configuration: the executor loads the exact profile
stored for that scan instead of selecting current or latest policy.

The executor also honors the exact `requested_services` persisted for that pending scan. A new 5F
scan uses
`("access-analyzer", "cloudtrail", "cloudtrail-evidence", "ec2", "iam", "kms", "s3")`;
`cloudtrail-evidence` selects the 5F CloudTrail graph path but is not an AWS service or permission.
An accepted 5E scan without that marker resumes without `GetEventSelectors` or a CloudTrail graph.
An accepted 5D scan without `kms` resumes without S3 Control, expanded S3, or KMS work, while a
pre-5D scan without `access-analyzer` or `kms` retains its older collector set. Unknown tuples fail
before AWS collection. Historical manifests remain readable without synthesizing later-slice
evidence. The 5F path and bounded 5G closure are accepted on `main`
without changing this API contract.

## Error behavior

The API does not currently use one universal error envelope:

| Status | Behavior |
| --- | --- |
| `401` | Missing/invalid bearer token: `detail.code=authentication_required`; token-validation detail is not exposed |
| `403` | Valid principal without capability: `detail.code=insufficient_capability` |
| `404` | Missing service entity: `detail.code=entity_not_found` with entity and identifier |
| `409` | Configured assessment-profile version exists with different content: `detail.code=assessment_profile_version_conflict` |
| `409` | Technical-posture provenance is inconsistent: `detail.code=technical_posture_provenance_conflict`; no partial/safe summary is returned |
| `422` | FastAPI request/path/query validation response |
| `503` | Scan executor unavailable/capacity/submission failure, or database readiness failure |
| `500` | Unexpected domain, catalog, database, or server failure; no stable application envelope is promised |

If submission fails after the scan row is committed, the 503 response uses
`detail.code=scan_submission_failed` and returns the durable `scan_id`. The service makes a
best-effort transition to `FAILED`. If the executor is absent from application state, the code is
`scan_executor_unavailable`.

A 409 profile-version conflict occurs before a scan is created. Its fixed message instructs the
operator to increase `ASSESSMENT_PROFILE_VERSION`; it does not expose either checksum, stored
policy fields, SQL, or internal exception details. Correct the deployment configuration by using
a new reviewed version for the changed content, then retry the request.

The technical-posture conflict uses the fixed message
`The retained scan reporting provenance is inconsistent.` It reveals no stored policy,
checksum comparison, SQL or internal failure detail, and sets `Cache-Control: no-store`.
Missing scans still use the existing 404 entity error; malformed scan UUIDs use 422.

Failure messages are sanitized; raw AWS responses and stack traces stay server-side. OIDC/JWKS
lookup or verification failure fails closed as 401.

## Health and readiness

`GET /health` reports process liveness without database or AWS calls. `GET /ready` executes a
database `SELECT 1` and returns 503 when connectivity fails. Readiness does not verify Alembic
revision, executor capacity, OIDC/JWKS availability, AWS credentials, or collector health.

## Opt-in 7B browser interface — accepted

This separate same-origin interface is excluded from OpenAPI and disabled by default. It does
not change `/api/v1`, health, readiness or their accepted schemas. See
[dashboard operations](operations/dashboard.md) for the trusted configuration and session policy.

| Method/path | Contract |
| --- | --- |
| GET /dashboard/ and /dashboard/assets/* | Built static shell/assets, never credentials or embedded evidence |
| GET /dashboard/session | authenticated=false plus login CSRF token, or true plus subject/recognized roles/session deadlines/CSRF/public session_context; never provider tokens |
| POST /dashboard/auth/login | Exact Origin and browser-bound X-CSRF-Token required; returns trusted authorization URL with state/challenge, not verifier/token |
| GET /dashboard/auth/callback | One-time browser-bound code/state exchange; fixed 303 /dashboard/ or /dashboard/?login=failed; no arbitrary redirect |
| POST /dashboard/auth/logout | Exact Origin and session CSRF required; destroys server session and clears cookies, 204; not global IdP logout |
| GET /dashboard/api/scans | Opaque session plus matching X-Dashboard-Context and real bearer/READ; limit 1..100, offset >= 0; only these parameters, no duplicates |
| GET /dashboard/api/scans/{scan_id} | Same session/context/READ checks; valid UUID, no query parameters; unchanged exact-scan detail projection |
| GET /dashboard/api/scans/{scan_id}/technical-posture | Same session/context/READ checks; valid UUID, no query parameters; unchanged 7A report/schema/error semantics |

`session_context` is a random public correlation identifier, not a bearer or CSRF credential.
It must match the current cookie's server session on all three BFF reads; absent/malformed/stale
values return 401 before forwarding and do not revoke the current valid session. This additive
7B-only interface is accepted through PR #43; `/api/v1` headers, fields and authorization are unchanged.

All dashboard responses, including unexpected 500s, carry no-store and scoped browser security headers. Authentication is
401; rejected origin/CSRF is 403; capacity or unavailable login is sanitized 503. Callback errors
do not expose provider detail; callback queries are redacted on error paths as well. The READ adapter retains upstream status and JSON; it rejects a
read if logout/expiry occurs before completion. Unsupported paths/methods are not a generic proxy.
Dashboard cookies never authenticate `/api/v1`. No CORS, roles, capabilities, tenant policy,
database write, scan execution or account isolation is added.

### 7C investigation reads — accepted

`GET /api/v1/resources/{resource_id}/history` adds optional `scan_id` UUID. Count and items
are filtered together; an existing resource without that scan returns an empty page, an unknown
resource still returns 404. Omission preserves existing defaults (50), ordering and schema.
With the filter there is at most one snapshot from the existing unique scan/resource constraint.
Clients still verify the expected snapshot UUID; no latest-snapshot fallback is valid.

New explicit BFF GETs below retain the same opaque session, mandatory matching
`X-Dashboard-Context`, origin checks, bearer/READ enforcement, no-store/security headers and
final logout/expiry guard. They retain upstream JSON/status, default to limit 25, allow 1..100,
offset >= 0 and reject unknown/duplicate queries. Detail paths accept no queries.

| Path after /dashboard/api/ | Allowed query parameters beyond limit/offset |
| --- | --- |
| assessments | required scan_id; resource_id, control_id, result |
| assessments/{assessment_id} | none; no pagination |
| resources/{resource_id} | none; no pagination |
| resources/{resource_id}/history | required scan_id |
| controls/{control_id} | none; no pagination |
| findings | account_id, resource_id, control_id, status, region |
| findings/{finding_id} | none; no pagination |
| exceptions | finding_id, resource_id, control_id, status |
| source-outcomes | required scan_id; collection_account_id, contract_key, collector, phase, subject_resource_id, evidence_kind, state |
| source-outcomes/{source_outcome_id} | none; no pagination |
| relationships | required scan_id; collection_account_id, relationship_id, source_resource_id, target_resource_id, target_reference_id, relationship_type, resolution |
| relationships/{observation_id} | none; no pagination |

UUID/enums are typed; account filters are 12-digit values, name filters 1..128 characters,
Region 1..64. No generic proxy, writer, exception-detail BFF or browser-selected headers/URL.
Only successful findings list/detail and exceptions list responses add `X-Dashboard-Read-At`,
an explicit UTC ISO timestamp captured when producing the response after the final session guard.
It is metadata, not authority, a transaction timestamp, active-ID computation time or scan-time
state. Error/nonoperational responses do not carry it; `/api/v1` response bodies/headers are unchanged.
The UI displays stored status separately from eligibility at this reference and fails unavailable
for missing/invalid times. Technical four-state results never change with operational handling.

### 7D client-only NIST context — accepted

7D reuses the already fetched `GET /dashboard/api/scans/{scan_id}/technical-posture` response.
There is no new API/BFF endpoint, query parameter, response field, reporting enum, authorization
or persistence change. Existing schema `1.0.0` and exact scan/profile/catalog/framework identities
remain authoritative. A separate browser display guard validates nested hierarchy/count/mapping
consistency; supported investigation remains independent of NIST display failures. Framework
selection and expansion issue zero additional requests. No metadata URL is followed and no
NIST result/score or manual-attestation write is introduced. PR #48 passed local validation,
exact-head independent review, both final-head CI runs, guarded merge and merged-main CI;
see the [acceptance record](sprint-7d-preflight.md). Subsequent whole-Sprint-7 acceptance and
documentary closeout passed through PR #50/#51; the [7E matrix](sprint-7e-acceptance.md)
records the combined signed-API/browser/database evidence and its offline limitations.

## Compatibility rule

Before changing a method, path, capability, enum, request field, response field, pagination
behavior, error contract, or stable identifier, search all clients/tests and evaluate persistence
and backward-compatibility implications. Update code, tests, this document, architecture, and
security sources atomically, then run the complete regression suite.

No permissive CORS middleware is configured. Production clients require deployment-provided TLS,
controlled ingress, and an explicit CORS policy only when a trusted browser origin needs one.
