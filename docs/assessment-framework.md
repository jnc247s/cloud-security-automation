# Assessment framework

Sprint 2.1 established the versioned assessment contracts used by the Sprint 3 persistence layer
and Sprint 4 service API. It separates technical AWS evaluation from organization policy and
external cybersecurity-framework metadata. See [Persistence and history](persistence.md) for the
durable data model and [Service API](api.md) for authorized access; technical
evaluation remains side-effect-free.

## Architectural boundary

The assessment path is intentionally one-way:

```text
AWS collectors -> normalized InventorySnapshot -> technical rules + AssessmentProfile
                                               -> AssessmentCandidate + EvidenceArtifact

versioned NIST catalog -> ControlFrameworkMapping (metadata only)
```

Collectors produce facts only. Rules decide technical results using normalized facts and the
selected profile. NIST mappings describe outcomes to which a technical check can contribute; they
are never evaluation inputs and cannot alter `PASS` or `FAIL`. Removing all NIST metadata leaves
the technical control contracts valid.

## Assessment results

`RuleEngine.assess(snapshot, profile)` returns explicit, deterministic results:

| Result | Meaning |
| --- | --- |
| `PASS` | Required evidence is available and satisfies the technical contract. |
| `FAIL` | Required evidence is available and violates the technical contract. |
| `INSUFFICIENT_EVIDENCE` | Required evidence is absent or malformed. This is never a pass. |
| `NOT_APPLICABLE` | A resource-scoped control has no target resources in the snapshot. |

`AssessmentCandidate` binds the result to a stable control ID, account/resource identity,
authoritative scan UUID, normalized-inventory digest, complete control-catalog digest, and exact
profile ID, version, and content checksum. Result states are technical assessment states, not
claims of framework compliance.

## Evidence provenance

Each `PASS` or `FAIL` result contains a structured `EvidenceArtifact`. Its provenance includes:

- an authoritative preallocated scan UUID and deterministic evidence/resource-snapshot identifiers;
- control, account, service, resource type, AWS resource ID, ARN, scope, and region;
- collector, normalized source, source AWS API, and collection timestamp;
- evidence schema name and version;
- a structured, deeply immutable JSON payload; and
- a verified SHA-256 payload digest.

Evidence retains collector-defined structure instead of being flattened into a generic
entity-attribute-value table. Its identifier is bound to the canonical payload digest and complete
provenance, so payload or provenance changes produce a different identifier. Sprint 3 allocates
the scan UUID before collection, carries it through evaluation, and persists that same identity.
Resource-snapshot IDs are derived from the scan UUID and stable target identity, not from mutable
configuration or collection coverage. A new scan receives a new UUID even when its facts match an
earlier scan.

`InventorySnapshot` records every requested collector as `SUCCEEDED`, `FAILED`, or `PARTIAL`.
The inventory service continues independent collectors after sanitized AWS or incomplete-response
failures. If a control's required collector was unrequested, failed, or partial, assessment yields
`INSUFFICIENT_EVIDENCE`; it never infers `PASS`, `FAIL`, or `NOT_APPLICABLE` from unknown coverage.
Sprint 3 persists the exact scan scope and collection outcomes separately from technical results;
incomplete coverage cannot silently resolve a finding.

## Assessment profiles

`AssessmentProfile` is immutable, versioned, and protected by a SHA-256 checksum of its canonical
policy content. It carries:

- `enabled_controls`;
- `required_tags`;
- `stale_key_days`;
- `approved_management_cidrs`;
- `public_ec2_exceptions`; and
- `restricted_data_requires_kms`.

Profiles reject duplicate entries and invalid or non-canonical CIDRs. A caller-supplied checksum
must match the policy content, preventing a version from being silently reused with different
settings.

For API-created scans, `ASSESSMENT_PROFILE_VERSION` explicitly selects the `default` profile
version and must use numeric `X.Y.Z` form. The pair `(profile_id, version)` is permanent identity
for exactly one policy definition. Reusing it with identical content is idempotent; changing
policy content under the same identity is rejected. Operators must choose a reviewed new version
whenever `REQUIRED_TAGS`, `STALE_ACCESS_KEY_DAYS`, or another policy-affecting field changes.
There is no automatic version generation, wall-clock versioning, or implicit "latest" selection.

Scan creation stores the complete profile before committing the pending scan reference. Execution
and startup recovery load and checksum-verify that exact stored definition. Consequently, an old
pending scan continues to use its original policy after the process is redeployed with a newer
configured version, and historical assessments continue resolving to their original definition.
This behavior uses the existing versioned persistence schema and requires no migration.

These thresholds and exceptions are organization or project policy. NIST CSF 2.0 does not
universally mandate the default tag names, a 90-day stale-key threshold, particular management
CIDRs, project-specific EC2 exceptions, or this project's KMS rule. Current controls use only the
`enabled_controls` profile field; the other fields establish versioned inputs for roadmap controls
that will explicitly depend on them.

## Control contracts

The control catalog is `aws-cloud-security-controls` version `0.2.1`. Each automated control has a
framework-independent `TechnicalControlContract` covering:

1. what the control measures;
2. which normalized evidence it requires;
3. exact pass and fail logic;
4. behavior when evidence is unavailable;
5. non-applicability behavior;
6. severity, impact, and remediation guidance;
7. the profile parameters that affect it; and
8. documented limitations.

`ControlContract` composes that technical definition with separately validated framework
mappings. Catalog validation rejects duplicate control IDs, duplicate mappings, orphan mappings,
unknown references, wrong framework versions, and mapping gaps between control and framework
catalogs.

The Sprint 2 encryption prototype was deliberately moved from `S3-002` to non-core `S3-900`
before persistence. Its behavior is preserved, while canonical `S3-002` remains reserved for the
roadmap's future unapproved public/external bucket-exposure control. See the
[control catalog](controls/catalog.md) for all permanent S3 identifier meanings.

## Framework catalog

The bundled catalog, current control mappings, authoritative source provenance, integrity checks,
and update protocol are documented in
[NIST CSF 2.0 framework mapping](frameworks/nist-csf-2.0.md). Framework metadata remains a scoped
reporting relationship: it never sets technical severity, changes a control result, or proves an
entire CSF outcome.

## Compatibility and scope

`RuleEngine.evaluate(snapshot)` remains available for Sprint 2 callers. It emits only failed
`FindingCandidate` values and raises `RuleEvaluationError` for missing or malformed evidence or
incomplete required collection.
`RuleEngine.assess(snapshot, profile)` is the canonical interface for new work because it retains
all four result states and evidence provenance.

Sprint 2.1 added no persistence schema or AWS/control expansion. Sprint 3 records these contracts,
assessments, evidence, findings, and governance history through an explicit caller-owned
transaction. Sprint 4 exposes that history through authorized service/API interfaces and can run
the existing collectors and controls asynchronously. It adds no AWS evidence scope, Terraform,
remediation, additional control library, dashboard, or AI functionality.
