# Sprint 6E.1 approved policy and control metadata

Approved 2026-09-29. [ROADMAP.md](../../ROADMAP.md) owns progress and the
[active plan](../exec-plans/active/sprint-6.md) owns approved implementation scope.
The user approved the policy directions and subsequently approved severity, guidance, release
identities and reporting mappings. The default catalog remains unchanged.

## Approved policy direction

The user explicitly approved:

- S3-001: effective combined account/bucket Block Public Access, not independent enforcement
  of every flag at both levels.
- S3-003: bounded explicit Deny proof for insecure transport covering the bucket and objects;
  confirmed missing policy is FAIL; unsupported or unavailable evidence is insufficient.

The four BPA flags are evaluated individually: `BlockPublicAcls`, `IgnorePublicAcls`,
`BlockPublicPolicy`, and `RestrictPublicBuckets`. A proved true flag at either applicable level
satisfies that flag. Two proved false flags establish a gap. A false flag plus unavailable
evidence cannot establish a gap or protection. This is a configuration check, not the separate
S3-002 exposure decision, and does not claim to evaluate access-point or organization policies.

## Executable decision contract

This contract is linked from the canonical control catalog. Preserve same-scan source, identity and
bucket-home-Region proof; no settings may be borrowed from another owner/account.

For S3-001, PASS requires all four effective flags proved true. FAIL requires at least one
flag proved false at both levels. Otherwise the result is INSUFFICIENT_EVIDENCE. Expected
absence of a BPA configuration means no flags supplied by that level, not a provider failure.
Retain unavailable-source provenance even when an independent flag establishes a result.

For S3-003, use the following closed positive proof over the already normalized policy:

- Effect exactly `Deny`; principal `*` or an object containing only `AWS` with `*` or `["*"]`.
- Action string/list contains the exact `*` or `s3:*` element.
- Resource string/list contains `*`, or exact bucket ARN and `bucket ARN/*`. Separate otherwise
  qualifying statements may jointly cover these two resource forms. No ARN glob solver is used.
- Condition contains only `Bool`, whose only key is `aws:SecureTransport` with string `false`
  or singleton list `["false"]`. The existing collector's normalized string contract is retained;
  raw JSON Boolean condition values are not newly coerced.
- No NotPrincipal, NotAction, NotResource, additional condition or limiting principal is admitted.

PASS requires this complete denial coverage. A confirmed missing policy or a complete policy
containing only Allow statements is FAIL; HTTPS Allow alone is not enforcement. Other Deny
patterns, incomplete coverage and unsupported syntax yield INSUFFICIENT_EVIDENCE unless separate
supported statements already prove full denial. Malformed/unavailable policy is insufficient.
This is not a general policy solver or effective-permissions computation.

Both controls use N/A only for proven complete empty bucket discovery, never missing or
discarded bucket evidence. Missing identity/location or incomplete discovery cannot fabricate
an empty population. Existing full-scan finding-resolution safeguards remain unchanged.

## Approved metadata

Opt-in catalog `0.8.0` extends `0.7.0`, with evaluator `1.0.0` and a separately
identified/checksummed local NIST subset `2.0+subset.7`. Preserve every earlier release,
framework artifact, profile checksum and default `0.2.1`.

| Control | Severity | Impact and operator guidance | Mapping and limited rationale |
| --- | --- | --- | --- |
| S3-001 | HIGH | Missing required public-access safeguards can permit unintended sharing. An authorized operator must review legitimate public workloads and dependencies before changing settings. | PR.AA-05: preventive public-access configuration contributes access-policy enforcement evidence; it does not prove complete least privilege or separation of duties. |
| S3-003 | MEDIUM | Missing enforced secure transport can permit unencrypted requests. An authorized operator must review clients and AWS-service dependencies before changing the bucket policy. | PR.DS-02: HTTPS-denial configuration contributes data-in-transit protection evidence; it does not prove complete confidentiality, integrity or availability. |

Severities are approved project policy, not NIST assignments. Mappings are reporting metadata
and never determine a technical result. No AWS writes or automated remediation are proposed.

## Sources inspected

- [AWS Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
  supports combining restrictive settings; this slice remains bounded to existing account/bucket evidence.
- [AWS HTTPS bucket-policy example](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies.html)
  supplies the bounded explicit secure-transport Deny pattern.
- [NIST CSF 2.0, Appendix A, printed page 20](https://doi.org/10.6028/NIST.CSWP.29)
  supplies PR.AA-05 and PR.DS-02 context, inspected 2026-09-29. These are project mappings,
  not a claim that NIST assigns controls or severity to this scanner.

## Remaining gates and exclusions

Validate deterministic rule cases, real authenticated HTTP-to-persistence/public reads,
source failures, old/new history, pending-scan recovery, immutable evidence and forged-result
rejection; run full regression, disposable PostgreSQL, Ruff, applicable image/Compose checks,
independent review and final CI. Human merge approval remains mandatory.

S3-002/004, LOG-004 composition, new collectors/permissions, schema redesign, frontend,
remediation and production deployment are excluded. S3-900 remains unchanged. No live AWS
or the user's local demonstration database is needed for validation.
