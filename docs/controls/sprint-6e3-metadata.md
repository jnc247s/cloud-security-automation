# Sprint 6E.3 — S3-004 release metadata

Approved bundle: 2026-09-30, recorded in the [active plan](../exec-plans/active/sprint-6.md).
[ROADMAP.md](../../ROADMAP.md) owns progress. The [classifier schema](s3-004-sensitive-bucket-classifier.md)
is unchanged; this release supplies its approved evaluator using accepted 6A policy storage.

## Release and explicit policy

- S3-004, KMS default encryption for sensitive buckets; HIGH severity, evaluator `1.0.0`.
- Opt-in catalog `aws-cloud-security-controls` / `0.10.0`, extending immutable `0.9.0`.
- Closed execution schema `1.7.0`, strategy `s3_sensitive_kms_v1`.
- Independently checksummed NIST subset `2.0+subset.9`, PR.DS-01, verified 2026-09-30 against
  [NIST CSF 2.0](https://doi.org/10.6028/NIST.CSWP.29), Appendix A, Protect / Data Security.
  Default KMS configuration contributes data-at-rest protection evidence, not full object
  protection or compliance. Mapping and severity do not determine technical status.

The approved initial classifier is schema `1.0.0`, policy version `1.0.0`, one exact
case-sensitive tag pair `DataClassification=Restricted`, with no name patterns, exact sensitive
identities or non-sensitive overrides. Its content checksum is
`4be3ecaffb0a291d3a5005386f29123850afb5f939f7a7f6eb80a4ecf5587f2d`.
Use `SensitiveBucketClassifier.create` for a newly approved artifact, not to re-sign historical
content. Bind it as `sensitive_bucket_classifier` in an explicit new schema-2 profile enabling
`S3-004`, with `restricted_data_requires_kms=true`. Use the existing protected local
[policy envelope](../assessment-foundation.md) to select catalog `0.10.0`; no deployment file,
live policy or implicit fallback is installed. Changed classifier content requires a new policy
version and new profile version.

Both AWS-managed and customer-managed KMS are accepted. The existing boolean does not mean
customer-managed-only. No profile field or migration is needed for this approved policy.

## Evaluation and evidence

After exact same-scan discovery, bucket owner/home Region and immutable classifier binding:

| Condition | Result |
| --- | --- |
| Complete empty discovery | NOT_APPLICABLE |
| Classifier requires unavailable tags, without a decisive identity/name signal | INSUFFICIENT_EVIDENCE, even when KMS is disabled |
| Proven NOT_SENSITIVE | NOT_APPLICABLE; irrelevant encryption/key failure does not block it |
| Proven SENSITIVE and explicit KMS requirement false | NOT_APPLICABLE, never PASS |
| Sensitive, required, one complete SSE-KMS/DSSE-KMS default without an explicit reference | PASS for implicit AWS-managed KMS; no invented key/edge |
| Same, with explicit reference | PASS only with exact DescribeKey/source, resolved ENCRYPTED_WITH, same home Region and AWS/CUSTOMER manager |
| Sensitive, required, complete AES256 or no KMS default | FAIL, not a claim of no encryption |
| Missing, denied, malformed, conflicting or unsupported required evidence | INSUFFICIENT_EVIDENCE |

Any detected bucket disappearance invalidates applicability. Every encryption rule is retained;
multiple default rules are ambiguous rather than first-rule-wins. Blocked-encryption-only rules
and Bucket Keys do not prove a KMS default. An alias/key-ID/ARN lookup must bind to its own
same-scan source and canonical key owner; a sibling observation cannot replace a denied lookup.
Cross-account key ownership is preserved, not overwritten with collection account.

Engine and transactional persistence share this proof and evaluator. Decisive evidence retains
classifier identity/version/checksum, classification reason/matches, exact bucket identity,
profile checksum, normalized inputs, source IDs/digests and resolved key/edge IDs. N/A and
insufficient results preserve the existing no-decisive-artifact convention: exact classifier
history is retained through immutable scan/profile/policy storage and inputs through the
inventory graph; applicability is recomputed during validation and historical replay.
Forged results, matches, source/key/relationship content and substituted historical policy
versions are rejected. A partial scan cannot resolve an existing finding.

## Boundaries and validation

This is default-encryption configuration only, not existing-object encryption, upload enforcement,
key-policy access, key availability/rotation or compliance certification. An authorized operator
must review workload compatibility and key access before any separate encryption change.
The [AWS default-encryption API](https://docs.aws.amazon.com/AmazonS3/latest/API/API_ServerSideEncryptionByDefault.html)
defines the retained algorithm and optional key-reference distinction.

Default `0.2.1`, earlier catalog/framework bytes, collectors, permissions, generic APIs/auth,
classifier schema and migration head `20260924_0004` remain unchanged. No LOG-004, remediation,
infrastructure, AI or later-slice work.

```text
python -m scripts.validate --focused tests/unit/rules/test_s3_sensitive_kms.py tests/unit/database/test_s3_sensitive_kms.py tests/integration/test_s3_sensitive_kms_postgres.py
```

The existing runner uses a disposable PostgreSQL container, not an operator database, then
full regression, Ruff, whitespace, Compose and image checks. HTTP acceptance retains real bearer
authentication/capabilities, services, executor, collectors, rules and transactions; only AWS is
offline. It verifies nonblocking creation and public retrieval by stable IDs, including history,
assessments, proof sources, findings, framework context and audit. No arbitrary scan sleeps or
Principal overrides.
