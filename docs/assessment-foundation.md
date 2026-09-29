# Sprint 6A assessment foundation

6D.2 adds opt-in catalog `0.7.0`, NET-006 and bounded execution schema `1.4.0`.
Its VPC/Flow Log join proves exact source-bound population and zero-or-more edge membership.
The shared engine/persistence validator recomputes the result using the retained explicit
environment/traffic policy, including artifact-free N/A. Missing edges cannot fabricate absence.
Earlier strategy meanings and default catalog remain unchanged; see
[approved metadata](controls/sprint-6d2-metadata.md).

Scope/status is owned by [ROADMAP.md](../ROADMAP.md) and the
[active Sprint 6 plan](exec-plans/active/sprint-6.md). This foundation enables no new control.
The default release remains `aws-cloud-security-controls/0.2.1` and its five accepted rules.
Approved 6B.1 adds explicit opt-in `0.3.0` containing those five plus IAM-002/003/005/006.
Synthetic test catalogs are not production releases.

## Explicit configuration

6D.1 adds opt-in catalog `0.6.0` for NET-003/004/005. NET-004 requires extended profile schema
`2.0.0` and explicit `high_risk_public_tcp_ports`; approved values are 3306, 5432, 6379, 9200,
27017. No implicit default is supplied. An explicit empty tuple is N/A after evidence validation;
missing policy fails before collection and during recovery. No profile schema or migration changes.

Execution schema `1.3.0` is restricted to security-group targets and `security_group_v1` proof.
It binds complete discovery membership, resource admission/configuration, exact same-owner/Region
VPC identity, a resolved `in_vpc` edge and its source provenance. Empty group discovery proves N/A
without a fabricated VPC edge. Unavailable evidence cannot prove absence. Both engine and storage
reuse the pure rule result with the exact selected profile; prior execution schemas retain their
semantics. No generic partial-evidence bypass is added. Legacy NET-001/002 and complete-scan
finding resolution are unchanged. See [approved metadata](controls/sprint-6d1-metadata.md).

Run focused local coverage with `python -m pytest tests/unit/rules/test_security_group_controls.py
tests/unit/database/test_network_controls.py tests/unit/database/test_network_http_acceptance.py`.
Run `python -m pytest tests/integration/test_network_controls_postgres.py` with an explicitly
disposable `TEST_DATABASE_URL` for authoritative PostgreSQL history/recovery/HTTP validation.

6C adds opt-in catalog `0.5.0` with EC2-001/002/003/004. Its new controls use execution schema
`1.0.0` and shared EC2 fact/applicability validation; the prior catalog releases are unchanged.
When EC2-002 is enabled, every `public_ec2_exceptions` entry must be a canonical lowercase,
hyphenated stable resource UUID (the existing UUIDv5 `resource_id`), not a snapshot UUID, ARN,
wildcard or bare instance ID. Empty means no approvals. Validation runs before collection and
on exact-policy recovery. Profiles without EC2-002 retain the established string-list contract.
No old policy version is rewritten; create a new version when enabling controls or changing approvals.

Run the bounded local acceptance with `python -m pytest tests/unit/rules/test_ec2.py
tests/unit/database/test_ec2_controls.py tests/unit/database/test_ec2_http_acceptance.py`.
With an explicitly disposable `TEST_DATABASE_URL`, run
`python -m pytest tests/integration/test_ec2_controls_postgres.py`. CI is authoritative for
PostgreSQL and retains real auth, executor, collectors, rules and persistence with fake AWS only.

With `ASSESSMENT_PROFILE_FILE` unset, the existing environment-based legacy factory is unchanged.
Set it only to a protected local UTF-8 JSON file, outside Git, with this envelope:

```json
{
  "catalog_id": "aws-cloud-security-controls",
  "catalog_version": "0.2.1",
  "profile": { "...": "complete serialized profile including content_checksum" }
}
```

The abbreviated `profile` above is illustrative, not a runnable policy. Serialize a validated
`AssessmentProfile` or `ExtendedAssessmentProfile` using `model_dump(mode="json")` to obtain its
complete document and checksum; never manufacture a checksum or hand-copy only some policy fields.
The profile's policy `version` must equal explicit `ASSESSMENT_PROFILE_VERSION`. A legacy profile
has no `schema_version`; an extended profile requires `schema_version: "2.0.0"`. Organization
version numbers do not select schemas. Unregistered enabled controls are rejected.

The file wholly owns policy inputs; `REQUIRED_TAGS` and `STALE_ACCESS_KEY_DAYS` do not merge into
file policy. It is validated once per Settings/application lifecycle and is not hot-reloaded.
URLs/UNC network paths, duplicate JSON keys, malformed content, unsupported versions, files over
1 MiB, and mismatched checksums fail closed with sanitized diagnostics. Protect it using filesystem
permissions and a read-only container mount; it must contain no credentials. API clients cannot
provide a file path. Run Alembic upgrades before starting the upgraded application.

## Profiles and immutable versions

Legacy serialization/checksums and arbitrary historical organization versions are preserved.
The extended schema adds only unused-key age, explicitly chosen high-risk TCP ports, Flow Log
environments/traffic types, governed resource types, S3 exposure approvals, and the sensitive-bucket
classifier. No deployment policy defaults are invented. Enabled future controls require their named
inputs, but cannot run until a later approved release registers them. Exact policy tag whitespace
and case are retained in the extended schema.

Migration `20260924_0004` follows `20260915_0003`. Both new profile columns (`schema_version`,
`policy_extensions`) are SQL NULL for legacy rows. Extended rows retain every extension value,
including full nested artifacts. The closed-kind `assessment_policy_artifacts` registry makes
`(artifact_kind, artifact_id, version)` unique and append-only. A conflicting artifact cannot reuse
its version through another profile. Loads verify both profile checksum and exact registry content.
Control versions gain nullable `execution_contract`; absence is omitted from legacy serialization,
preserving technical/catalog digests. Existing immutable table guards protect new columns too.

New scans persist their selected profile/catalog. Recovery resolves the exact supported catalog,
verifies stored membership, technical definitions and framework mappings, and loads the exact stored
profile before AWS work. Missing/unsupported releases fail; there is no latest-version substitution
or repair of historical rows during verification.

## Explicit targets and source proofs

`ExecutionContract` schema `1.0.0` supports global account, requested-Region EC2 account setting,
or exact service/type resource families, using only `all_observed_v1` selection. The engine and
persistence share the same pure enumerator. Regional settings use `ec2/aws_account`, verified
collection account ID, `regional` scope and requested Region. Their historical snapshots are
assessment-only targets, never inserted into the collector graph. Resource-family assessments
retain actual resource identity/type/owner. Empty populations require an explicit N/A or
insufficient account fallback; incomplete evidence cannot justify N/A.

The original source-aware strategy is `all_required_sources_complete_v1`. Requirements bind collector,
source API, evidence kind, subject scope, declaration version, and completeness strategy. Account
enumeration/settings require explicit normalized completeness flags. Exact resource enrichment may
use `admitted_resource_v1` only with authoritative same-scan resource admission and required account
coverage. Missing sources, discarded identities, incomplete admission, or unresolved required edges
cannot support decisive results. Required edge provenance must resolve to a proved required source.

The per-invocation reader revalidates the graph and indexes declarations/artifacts/provenance.
Assessment payload `source_proof` binds source outcome IDs, artifact IDs/digests, same-scan relationship
observation IDs, scan ID, and schema version. Both boundaries verify it against the retained graph.
`NOT_APPLICABLE` retains the accepted artifact-free representation: the reader verifies complete
required coverage against the retained graph and exact catalog before accepting that result.
This reader validates evidence, not control policy; it has no S3 aggregation or dependency engine.
The five legacy rules keep their whole-collector guards. Source sufficiency does not
relax the existing complete-scan finding-resolution gate.

### 6B.1 IAM evidence joins

Execution schema `1.1.0` adds only `iam_active_key_age_v1` and `iam_active_key_usage_v1`, restricted
to global IAM user targets and their `has_access_key` edges. Schema `1.0.0` retains its exact
semantics and cannot select the new strategies. Complete user discovery and per-user key
enumeration must match retained identities and resolved edges; edge provenance must identify the
exact admitted key source. Zero active keys is N/A only after complete enumeration is proved.
Usage evidence is required only for active keys in IAM-003; missing lookup evidence is not
`no_recorded_use`. Decision facts bind to retained source artifacts and observation time.
Unrelated source failure does not erase complete required evidence, but the existing whole-scan
finding-resolution guard still applies. The reader and persistence enforce the same proof.
The shared candidate validator rejects N/A with a nonempty proved active-key set, and rejects
N/A for the never-inapplicable IAM-005/006 root controls. Genuine complete-empty key N/A is retained.

The opt-in catalog requires a new explicit policy-file profile. IAM-003 requires extended schema
`2.0.0` and `max_unused_access_key_days` (approved deployment value 90); no default is supplied.
Missing declared profile inputs fail before AWS collection, including pending-scan recovery.
See [approved metadata](controls/sprint-6b1-metadata.md). No schema migration is added.

### 6B.2 IAM policy-document joins

Catalog `0.4.0` adds IAM-004 using execution schema `1.2.0`, selection
`iam_policy_documents_v1`, and validation `iam_policy_document_v1`. Old schemas cannot select
this strategy. Customer-managed and referenced AWS-managed default-version documents are targets;
inline documents use their existing owner/name identity without a synthetic AWS version.
One document is evaluated once even when multiple identities attach it or use it as a boundary.
Trust policies are outside this target set. No changes to collectors or the API are required.

The reader verifies complete user/group/role/local-policy enumeration; per-identity attachment,
boundary and inline enumeration; group membership; same-scan resolved edges and exact source
provenance. The target's decoded document and digest must match the retained snapshot. Managed
versions must agree with GetPolicy and the selected-version relationship. Inline owner/name must
agree with enumeration and the canonical identity. Missing metadata/default versions retain a
parent insufficient-evidence target rather than silently disappearing. Complete empty populations
use artifact-free account N/A, but in-scope documents cannot be N/A. Incomplete usage/population
proof makes results insufficient; a document-only failure does not erase complete sibling documents.

Proofs retain canonical sorted source/relationship IDs and usage contexts; evaluation evidence
records version `1.0.0` and matching statement indexes. This detects only literal Allow/Action */
Resource * syntax, not effective permissions. Conditions do not erase the match.
Their operator/key/scalar-or-scalar-list structure must be valid;
malformed nested conditions are insufficient, not PASS or FAIL. Operator semantics are not
evaluated. Structural references follow the
[AWS policy grammar](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_grammar.html).
No thresholds or profile schema change are introduced. Exact catalog/profile recovery and whole-scan finding
resolution remain unchanged. See [approved metadata](controls/sprint-6b2-metadata.md).

## Validation and rollback

Run `python -m pytest tests/unit/rules/test_iam_policy.py tests/unit/database/test_iam_policy.py
tests/unit/database/test_iam_http_acceptance.py` for focused offline validation. Run
`python -m pytest tests/integration/test_iam_policy_postgres.py` with an explicitly disposable
`TEST_DATABASE_URL` for authoritative persistence, recovery, historical versions and authenticated
HTTP acceptance. SQLite HTTP validation is supplemental; CI must execute PostgreSQL.

Focused tests are in `tests/unit/assessment/test_assessment_foundation.py`,
`tests/unit/database/test_assessment_foundation.py`, and
`tests/integration/test_assessment_foundation_postgres.py`. The existing authenticated HTTP
acceptance is parametrized for both profile formats and still replaces only AWS.
PostgreSQL tests require an explicitly disposable `TEST_DATABASE_URL`; CI provides PostgreSQL 16.

See [safe downgrade recovery](operations/known-limitations.md#assessment-foundation-downgrade)
before rollback. Extended history must never be deleted or fabricated to force a downgrade.
