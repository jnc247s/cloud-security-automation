# Sprint 6A assessment foundation

Scope/status is owned by [ROADMAP.md](../ROADMAP.md) and the
[active Sprint 6 plan](exec-plans/active/sprint-6.md). This foundation enables no new control.
The production resolver still supports only `aws-cloud-security-controls` version `0.2.1` and
its five accepted rules. Synthetic test catalogs are not production releases.

## Explicit configuration

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

The only source-aware strategy is `all_required_sources_complete_v1`. Requirements bind collector,
source API, evidence kind, subject scope, declaration version, and completeness strategy. Account
enumeration/settings require explicit normalized completeness flags. Exact resource enrichment may
use `admitted_resource_v1` only with authoritative same-scan resource admission and required account
coverage. Missing sources, discarded identities, incomplete admission, or unresolved required edges
cannot support decisive results. Required edge provenance must resolve to a proved required source.

The per-invocation reader revalidates the graph and indexes declarations/artifacts/provenance.
Assessment payload `source_proof` binds source outcome IDs, artifact IDs/digests, same-scan relationship
observation IDs, scan ID, and schema version. Both boundaries verify it against the retained graph.
This validates evidence, not control policy: no new evaluator, S3 aggregation, or dependency engine
is present. The five legacy rules keep their whole-collector guards. Source sufficiency does not
relax the existing complete-scan finding-resolution gate.

## Validation and rollback

Focused tests are in `tests/unit/assessment/test_assessment_foundation.py`,
`tests/unit/database/test_assessment_foundation.py`, and
`tests/integration/test_assessment_foundation_postgres.py`. The existing authenticated HTTP
acceptance is parametrized for both profile formats and still replaces only AWS.
PostgreSQL tests require an explicitly disposable `TEST_DATABASE_URL`; CI provides PostgreSQL 16.

See [safe downgrade recovery](operations/known-limitations.md#assessment-foundation-downgrade)
before rollback. Extended history must never be deleted or fabricated to force a downgrade.
