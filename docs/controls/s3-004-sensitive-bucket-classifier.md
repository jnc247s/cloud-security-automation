# S3-004 sensitive-bucket classifier contract

Status: approved preflight contract; S3-004 remains reserved and is not implemented

This document is the canonical definition of the classifier that determines whether the future
`S3-004` control applies to an S3 bucket. The executable contract mirror is
`app/assessment/sensitive_buckets.py`. This preflight artifact does not register `S3-004`, call
AWS, alter an assessment profile, persist data, or change current scan behavior.

## Boundary and supported inputs

Classifier `sensitive-bucket` schema `1.0.0` supports only evidence that can be normalized and
replayed from one historical bucket snapshot:

- exact S3 bucket ARNs explicitly classified as sensitive;
- exact S3 bucket ARNs explicitly overridden as non-sensitive;
- restricted, case-sensitive bucket-name patterns; and
- exact, case-sensitive S3 tag key/value rules.

It does not infer sensitivity from account, deployment environment, object contents, IAM policy,
Access Analyzer, severity, a resource group, an LLM, or a future investigation agent. An
organization can deliberately express business, environment, or data-classification labels as
exact tag rules; no tag key or value has built-in meaning.

The classifier consumes the exact bucket ARN and `tags`, where `null` means tag evidence was not
available or complete and an empty list means tag collection completed and found no tags. Bucket
name is derived from the ARN so a caller cannot provide contradictory ARN and name evidence.
Object and access-point ARNs are not bucket identities and are rejected.

## Immutable configuration schema

| Field | Type | Contract |
| --- | --- | --- |
| `classifier_id` | literal string | Always `sensitive-bucket` |
| `schema_version` | semantic version | Always `1.0.0` for this serialization and evaluation contract |
| `version` | semantic version | Organization-selected immutable policy version |
| `sensitive_bucket_arns` | unique tuple of strings | Exact S3 bucket ARNs that are sensitive |
| `non_sensitive_bucket_arns` | unique tuple of strings | Exact, reviewed overrides that are not sensitive |
| `sensitive_name_patterns` | unique tuple of strings | Full bucket-name patterns using only the restricted `*` wildcard |
| `sensitive_tag_rules` | unique tuple of objects | Exact `{key, value}` pairs; any one matching pair is a sensitive signal |
| `content_checksum` | lowercase SHA-256 | Canonical identity of every preceding field, including both versions |

At least one sensitive ARN, name pattern, or tag rule is required. An empty classifier cannot
silently classify every bucket as non-sensitive. An ARN cannot occur in both exact lists, and
duplicates are invalid rather than silently discarded.

Configuration is strict, immutable, and rejects unknown fields and type coercion. Lists and tag
rules are placed in canonical lexical order. The SHA-256 input uses deterministic JSON with
sorted keys and includes `classifier_id`, `schema_version`, policy `version`, and every policy
entry. Equivalent input ordering produces the same serialization and checksum. Changed content
or a changed version produces a different checksum; supplying a checksum for different content
is rejected.

### Restricted name patterns

A name pattern is matched case-sensitively against the complete bucket name, never a substring
or ARN. It is 3–63 characters, uses only lowercase ASCII letters, digits, `.`, `-`, and `*`, must
contain `*`, and may not contain `**` or `..`. The only wildcard is `*`, representing zero or more
valid bucket-name characters. `?`, character classes, regular expressions, path separators, and
implicit case folding are prohibited.

Use an exact bucket ARN for an exact decision. For example, `regulated-*-archive` matches
`regulated-finance-archive`; it does not match `copy-regulated-finance-archive-old`.

### Exact tag rules

Each rule is one exact key/value pair. Rules use OR semantics: any exact pair is a sensitive
signal. Key and value comparisons preserve case and whitespace. Duplicate tag keys in observed
evidence are ambiguous and rejected; the future normalization boundary must represent malformed
or incomplete tag evidence as unavailable, not silently select one value. An empty returned tag
set is complete evidence and differs from unavailable tags.

## Deterministic decision table

The first applicable row determines the typed result. Exact non-sensitive entries are deliberate
overrides of broad patterns and tag rules; matching suppressed signals are retained in the result
for review.

| Priority | Evidence and policy state | Result | Stable reason |
| --- | --- | --- | --- |
| Preflight | Configuration is contradictory, malformed, vacuous, or checksum-inconsistent | Reject the classifier; it is not executable | Validation error |
| 1 | Bucket ARN is in `sensitive_bucket_arns` | `SENSITIVE` | `explicit_sensitive_bucket` |
| 2 | Bucket ARN is in `non_sensitive_bucket_arns` | `NOT_SENSITIVE` | `explicit_non_sensitive_override` |
| 3 | Complete bucket name matches one or more approved full-name patterns | `SENSITIVE` | `sensitive_name_pattern` |
| 4 | Available tag evidence contains one or more exact approved pairs | `SENSITIVE` | `sensitive_tag` |
| 5 | Tag rules are configured, no earlier decisive signal exists, and tag evidence is unavailable or incomplete | `INSUFFICIENT_EVIDENCE` | `required_tags_unavailable` |
| 6 | Every configured input needed for the decision is complete and no sensitive signal matches | `NOT_SENSITIVE` | `no_sensitive_signal` |

The exact sensitive and exact non-sensitive sets cannot overlap, so priorities 1 and 2 cannot
conflict. A reviewed exact non-sensitive override intentionally wins over a matching broad name
or tag signal. This exception is visible through the stable reason and recorded matches and must
be reviewed whenever policy changes. A positive ARN or name signal is conclusive even when tags
are unavailable; missing data cannot reverse a known sensitive classification.

`NOT_SENSITIVE` is therefore not a default for missing configured metadata. It is emitted only
for an explicit override or after the supported configured inputs are complete and no sensitive
signal matches. The classifier does not produce `PASS`, `FAIL`, severity, a finding, or framework
status.

## Historical identity and future S3-004 integration

The classifier object and its typed result carry policy `version` and `content_checksum`.
Serialization followed by strict validation reconstructs the same artifact and classification;
checksum verification detects altered historical content. Policy changes require a new version.
The future profile/persistence integration must enforce one immutable checksum for each
`(classifier_id, version)` pair, retain old artifacts, bind each scan to the exact classifier
identity selected at scan creation, and store that identity with S3-004 assessments.

That integration is intentionally deferred. It must use a new assessment-profile version and an
Alembic-reviewed persistence design; it must not mutate the accepted `1.0.0` default profile or
historical assessment rows. The current artifact proves strict reconstruction in memory but is
not yet registered with `AssessmentProfile` or the database.

When S3-004 is later implemented, classification has only applicability meaning:

- `SENSITIVE` permits the deterministic rule to evaluate the separately collected KMS evidence;
- `NOT_SENSITIVE` maps to the control's documented `NOT_APPLICABLE` path; and
- `INSUFFICIENT_EVIDENCE` forces the control to `INSUFFICIENT_EVIDENCE`.

The existing `restricted_data_requires_kms` profile field defines the consequence after a bucket
is classified. It does not classify a bucket, and this contract does not change that meaning.

## Operational and security notes

Bucket ARNs, tags, classifier configuration, and results are sensitive security metadata. Future
persistence and API exposure must use the repository's existing authorization, immutable-history,
provenance, and sanitized-error boundaries. Operators must review exact non-sensitive overrides
carefully and must never edit a persisted classifier version in place merely to change an
assessment result.
