# Result-sensitive AWS evidence outcomes

Status: accepted
Date: 2026-09-14

Implementation update: the Sprint 5 shared foundation integrates this contract into the optional
inventory evidence graph, Alembic revision `20260915_0003`, transactional persistence, and
authenticated generic reads. The accepted 5A EC2/EBS and 5B network producers emit source
manifests, artifacts, and outcomes; the accepted 5C IAM and 5D Access Analyzer producers do
likewise. The remaining Sprint 0--4 legacy collectors retain their accepted graphless behavior,
and no Sprint 6 rule consumes source outcomes yet.

## Context

The accepted Sprint 0--4 inventory boundary records one operational outcome for an entire
collector. `InventoryService` treats an exception as a collector-level failure and does not
retain a partially built collector result. Existing rules therefore use coarse collector
`SUCCEEDED`, `PARTIAL`, and `FAILED` coverage to prevent unsupported clean assessments.

Planned Sprint 5 evidence is more granular. A discovered resource can have several independent
enrichment sources. For example, a bucket can be discovered successfully while policy, ACL, or
tag evidence is unavailable. A deterministic control may also have a versioned result strategy
under which one coherent source proves a failure even though a separate, non-decisive source is
unknown. Treating every source error as an all-or-nothing collector exception would discard valid
facts; treating the collector rollup as proof that every source is complete could instead create
false `PASS` results.

This preflight needs an approved normalized contract and integration rule before new collectors
exist. It must not retrofit that contract into the protected Sprint 0--4 runtime.

## Decision

Adopt the strict immutable `SourceEvidenceOutcome` contract in
`app/assessment/source_outcomes.py` for future Sprint 5 evidence sources. This object records the
state and provenance of one declared AWS API evidence kind. It is not a technical assessment and
does not contain severity, framework mapping, finding, or remediation policy.

### Discovery and enrichment are separate

Every source has an explicit phase and exactly one matching subject:

- `DISCOVERY` is account-scoped, with an explicit global or Regional execution scope. Its subject
  must equal the outcome's verified 12-digit collection account. It proves whether a complete
  enumeration response was obtained for that scope.
- `ENRICHMENT` is resource-scoped. Its subject contains the complete stable resource identity and
  the deterministic `ResourceSnapshot` ID for the same scan. The subject's resource owner may be
  different from the collection account for legitimate cross-account evidence.

A future collector must retain independently validated discovery facts and successful enrichment
facts even when another source fails. A pagination failure may retain resources already observed,
but the discovery outcome is not complete and no absence or enumeration-completeness claim may be
derived from it. Failure to enrich one discovered resource must not erase that resource or other
valid source observations.

The resource snapshot is the subject to which enrichment facts attach. An enrichment error does
not rewrite that snapshot as if the resource had never been observed. Conversely, an enrichment
response cannot create a resource identity that discovery or another identity-authoritative
source did not establish.

### Source states

The controlled version 1 states are:

| State | Meaning |
| --- | --- |
| `PRESENT` | A complete, structurally valid response supplied the declared fact. |
| `EXPECTED_ABSENCE` | A complete response and documented AWS semantics conclusively establish that the declared configuration or enumeration member is absent. |
| `UNAVAILABLE` | The source could not be obtained because of a controlled availability category such as access denial, authentication failure, throttling, timeout, service error, or an unsupported operation. |
| `MALFORMED` | A response was returned but failed the declared structural contract. |
| `CONFLICT` | Multiple observations for the same declared source cannot be reconciled without choosing or discarding evidence. |
| `RESOURCE_DISAPPEARED` | An enrichment call conclusively reports that a previously discovered resource no longer exists. This state is invalid for account discovery. |

`EXPECTED_ABSENCE` is a positive completeness statement, not a synonym for a missing field,
`AccessDenied`, an unsupported API, or an empty value in a malformed response. Whether proven
absence leads to `PASS`, `FAIL`, or `NOT_APPLICABLE` belongs to the versioned control contract.

Non-success states use a controlled `EvidenceFailureCategory`. They do not store raw AWS
exceptions. The state/category combinations are closed and validated: successful states have no
failure category; `MALFORMED`, `CONFLICT`, and `RESOURCE_DISAPPEARED` each have one corresponding
category; `UNAVAILABLE` accepts only the enumerated availability categories.

### Identity and provenance

Each outcome includes:

- a scan ID, verified 12-digit collection account ID, and deterministic source-outcome ID;
- the discovery or enrichment subject, including execution account or resource owner, scope, and
  Region;
- a stable evidence-kind name;
- state and controlled failure category;
- collector name and version;
- canonical AWS service and operation;
- timezone-aware collection time;
- a bounded, single-line internal evidence reference and SHA-256 digest; and
- the source-outcome schema version.

The source-outcome ID is UUIDv5 over the scan, collection account, phase, complete subject
identity, evidence kind, collector and version, and AWS API. It deliberately excludes result
state, failure category, reference, and digest. A retry that yields a different result therefore
addresses the same declared source and must be reconciled explicitly; it cannot create parallel
identities that hide a conflict. Changing the scan, collection account, or source contract creates
a different ID.

The collection account and resource owner have separate meanings. Collection accounts always use
the exact 12-digit AWS account identifier verified for the scan. Customer-owned resources also
use their 12-digit owner, which may differ from the collection account. AWS-managed IAM policies
and their versions use the controlled `aws` owner sentinel; no other resource type may use that
sentinel. Known resource types also enforce their canonical global or Regional scope rather than
accepting a caller-selected scope.

Resource identity strings reject the U+001F unit separator before invoking the accepted
delimiter-based stable-resource and snapshot-ID helpers. This prevents two different field tuples
from producing the same ID without changing established Sprint 0--4 identifiers.

The evidence reference addresses a normalized, sanitized evidence or diagnostic artifact. It
must never contain credentials, raw exception text, signed URLs, request authorization material,
or secrets. The digest binds the referenced normalized artifact but is not a substitute for
retaining it under the repository's evidence-integrity rules.

### Operational rollup remains separate

Per-source states feed, but do not replace, the existing collector-level operational rollup.
Future integration will calculate the rollup only after retaining validated source outcomes:

- `SUCCEEDED` requires every declared source needed for the collector's promised coverage to be
  conclusively complete (`PRESENT` or `EXPECTED_ABSENCE`);
- `PARTIAL` means trustworthy resources or facts were retained while one or more promised sources
  were unavailable, malformed, conflicting, or disappeared during collection, or when a
  validated digest-bound admission gap proves that a safely retained projection excludes an
  observed resource; and
- `FAILED` means the collector could not retain the minimum trustworthy discovery facts required
  for its promised inventory boundary.

The rollup describes collection coverage, not security posture. It cannot itself create a
`PASS`, `FAIL`, finding, exception, or remediation proposal. A future collector's declared source
manifest and version determine which sources are promised; callers may not silently omit a source
to turn `PARTIAL` into `SUCCEEDED`. An admission gap is a separate operational rollup input: it
does not rewrite a structurally valid, complete AWS discovery response from `PRESENT` to a source
failure. The complete artifact retains the AWS-observed identities and records canonical
`unadmitted_resources`; future consumers must consider that metadata and may not treat the source
state alone as proof that every observation was admitted to the top-level projection.

For each integrated graph-aware operational collector/version, reconstruction requires its exact
fixed discovery-source set, not merely whichever subset remains in the graph. Every operational
collector represented by source outcomes must also have exactly one matching requested collector
and collector outcome in the scope manifest. Missing or unknown discovery sources, omitted
collector coverage, malformed admission metadata, and a mismatch between reconstructed and stored
rollup fail closed. Accepted pre-5B history may retain the legacy `security_groups` outcome without
5B source records; the new `vpc_network_evidence` collector has no such compatibility exception.

### Deterministic assessment semantics

Rules consume normalized facts plus the source outcomes required by their versioned technical
contracts. The following invariants apply:

- `PASS` requires complete, coherent evidence for every source that the control declares
  decision-required for that passing result.
- Missing, unavailable, malformed, conflicting, or disappeared decision-required evidence yields
  `INSUFFICIENT_EVIDENCE`, never `PASS`.
- A known coherent fact may produce `FAIL` while another source is unknown only when that exact
  result-sensitive behavior is explicitly declared by the versioned control contract. This is
  not a generic collector-completeness bypass.
- Source failure states alone do not prove a technical `FAIL`; the failure must come from retained
  normalized security facts.
- `EXPECTED_ABSENCE` is evaluated according to the control contract. For example, proven absence
  of required encryption can be a technical failure, while proven absence of public access can
  support a pass.
- An incomplete relationship source emits no positive resource relationship. The independent
  endpoint snapshots remain retained, and a control requiring that edge receives
  `INSUFFICIENT_EVIDENCE`.

Existing coarse guards remain unchanged until an atomic Sprint 5 integration supplies source
outcomes to rules. No current rule may set required collectors to an empty set, reinterpret
`PARTIAL` as complete, or bypass the accepted missing-evidence behavior in anticipation of this
contract.

### Future transactional persistence

Sprint 5 integration will add an Alembic-backed, append-only representation for source outcomes
and their normalized referenced artifacts. The persistence slice must atomically retain the scan,
stable resources, immutable snapshots, source outcomes, relationships, assessments, evidence,
and resulting findings that belong to one completed execution. A failed graph write must roll
back rather than leave assessments detached from their source coverage.

At minimum, persistence must enforce one outcome identity per declared source in a scan, preserve
the full validated subject and provenance, reject conflicting duplicates, and reconstruct this
domain model on read. Updates never overwrite an earlier scan's outcome. API projections must
preserve state and controlled categories without exposing raw provider errors.

The exact migration, table layout, transaction integration, and public projection are deferred
to the corresponding Sprint 5 slice. This decision does not authorize a schema-only table or a
writer without its reviewed reader, constraints, tests, and rollback behavior.

## Alternatives considered

- **Continue throwing away a collector result on any source error.** Rejected for expanded
  collectors because it loses valid discovery and enrichment facts and prevents result-sensitive
  control contracts from distinguishing known facts from unknown sources.
- **Treat `PARTIAL` as sufficient for every rule.** Rejected because it can convert missing
  decision-required evidence into false `PASS` results.
- **Infer source state from absent JSON fields.** Rejected because expected absence, access
  denial, malformed responses, unsupported operations, and resource deletion have different
  meanings.
- **Let each collector invent status strings.** Rejected because rules and persistence could not
  validate a stable cross-service contract.
- **Integrate the new contract during this preflight.** Rejected because doing so would change
  accepted runtime and persistence behavior before Sprint 5 implementation and end-to-end
  validation.

## Security and data-integrity consequences

Explicit uncertainty prevents unsupported clean assessments. Strict subjects reject forged
stable or snapshot IDs, ambiguous Regions, and cross-scan attachment. Deterministic IDs expose
conflicting retries rather than allowing both to appear authoritative. Controlled failure
categories and opaque evidence references reduce the risk of persisting or returning credentials,
provider payloads, resource policy contents, or sensitive exception details.

Retaining partial valid facts increases the amount of security metadata that future persistence
must protect. Source outcomes, referenced artifacts, digests, and collection coverage are
sensitive security data and inherit the repository's access-control, logging, backup, and
retention requirements.

## Compatibility and migration

The shared foundation now integrates this contract into optional `InventorySnapshot` graphs,
transactional persistence, and API/service projections. Graphless Sprint 0--4 serialization,
collector rollups, AWS calls, and rules remain unchanged. Revision `20260915_0003` adds the new
append-only schema without rewriting an accepted migration or historical row.

Collector integration remains slice-specific work in 5A--5F. It must construct the complete
declared-source manifest atomically. The accepted 5A through 5D producers construct their complete
manifests; feature-branch 5E adds the direct S3/KMS manifest pending acceptance. The 5F collector
and every deterministic Sprint 6 rule remain unimplemented merely because the storage and read
boundary exists.

## Validation

Contract tests cover all controlled states and failure-category combinations, discovery and
enrichment subjects, collection-account/resource-owner separation (including cross-account and
AWS-managed IAM identities), exact stable and per-scan resource identity, controlled global and
Regional scope, deterministic IDs, scan separation, timezone-aware provenance, strict digests and
references, schema-version rejection, JSON round trips, immutability, extra-field rejection, and
forged ID rejection. They also verify that source-outcome identity is independent of result state
so a conflicting retry cannot evade reconciliation with a second identity.
