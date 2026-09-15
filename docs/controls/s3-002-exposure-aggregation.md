# S3-002 public and external exposure aggregation

Status: **canonical planned contract; not implemented or enabled**

This document is the authoritative detailed contract for the immutable control meaning
`S3-002 = Unapproved public/external bucket exposure`. The
[control catalog](catalog.md) owns the identifier and title. The
[Sprint 5 evidence-readiness matrix](sprint-5-evidence-readiness.md) owns collection planning.
This contract defines the later deterministic evaluator's inputs and result, but it does not add
an AWS collector or executable rule.

## Assessment scope and vocabulary

The v1 assessment unit is one general purpose S3 bucket in its home Region. It evaluates exposure
configured through that bucket's policy and bucket ACL. It deliberately distinguishes:

- **public exposure:** a bucket policy Amazon S3 classifies as public, or a bucket ACL permission
  granted to the S3 `AllUsers` or `AuthenticatedUsers` predefined group; and
- **supported external exposure:** a bucket-policy or bucket-ACL grant to a fixed principal
  outside the bucket owner's account that can be represented by an approved principal token.

For this contract, a supported external bucket-policy grant is a configured cross-account grant.
It is not a claim that a request has occurred or that every identity-policy, service-control
policy, resource-control policy, explicit-deny, or condition path was re-evaluated. The complete
policy, including conditions and denies, remains evidence. Unsupported principal or statement
forms are uncertainty, not a silently safe configuration.

Each mechanism normalizes to exactly one of these channel outcomes:

| Channel outcome | Meaning |
| --- | --- |
| `NO_EXPOSURE` | Complete evidence proves no in-scope public or supported external grant. |
| `APPROVED_EXPOSURE` | An in-scope grant exists, is not neutralized, and the exact bucket-scoped policy approves it. |
| `CONFIRMED_UNAPPROVED` | Complete decisive facts prove at least one effective in-scope grant that the bucket-scoped policy does not approve. |
| `UNKNOWN` | Required evidence is absent, denied, malformed, contradictory, stale across a detected mutation, or outside the supported proof subset. |

`PASS` means no **unapproved in-scope** exposure was found. It is not a statement that every S3
access path is private; the explicit v1 exclusions are documented below.

## Versioned bucket-scoped approvals

`s3_exposure_approvals` is planned immutable Assessment Profile content represented by the pure
`S3ExposureApprovalPolicy` schema. Profile registration remains a later implementation boundary;
the approved artifact itself has this exact logical schema:

```text
policy_id: fixed string s3-exposure-approvals
schema_version: fixed string 1.0.0
version: semantic policy version
bucket_approvals: sorted unique tuple of records
  bucket_identity:
    provider: fixed string aws
    aws_account_id: exact 12-digit owner account
    bucket_region: authoritative bucket home Region
    bucket_arn: exact canonical ARN arn:<partition>:s3:::<bucket-name>
    stable_resource_id: canonical UUID derived from account, Region, and bucket name
  allow_public: boolean
  approved_external_principals: sorted unique tuple of canonical principal tokens
content_checksum: required SHA-256 over identity, both versions, and canonical complete content
```

Only these principal-token forms are allowed:

- `account:<12-digit-account-id>`;
- an exact IAM user or role ARN with no wildcard or policy variable; or
- `canonical-user:<canonical-user-id>`.

An AWS account ID and that account's root ARN both canonicalize to `account:<id>`. Same-owner
account principals and recognized AWS service principals are not external approval candidates.
Unknown, wildcard, federated, malformed, or otherwise unsupported principal forms do not acquire
an invented token.

Approvals are deliberately narrow:

- A bucket identity is the validated `S3BucketIdentity` tuple, not an ARN alone. S3 bucket ARNs
  omit owner account and home Region, and a deleted name can later identify a bucket in another
  account. Exact approval therefore binds the owner account, authoritative home Region, exact ARN
  and name, and the repository-derived stable resource ID. The ARN cannot contain a wildcard. At
  most one record can exist for one stable bucket identity.
- A record that sets `allow_public = false` and has no external principals is vacuous and invalid;
  omit it instead.
- No record for a bucket is a complete policy decision equivalent to `allow_public = false` and
  an empty external-principal tuple; it is not missing configuration.
- `allow_public = true` approves public exposure only for that exact bucket. It does not approve a
  separately configured fixed external-principal grant.
- A supported external grant is approved only when every exposed external principal token is in
  that bucket's tuple. One unapproved principal is decisive.
- Archived IAM Access Analyzer findings and operational Finding Exceptions are not approvals.
- Missing, invalid, or checksum-inconsistent Assessment Profile content makes the result
  `INSUFFICIENT_EVIDENCE` before channel aggregation.

The standalone artifact binds its policy ID, schema version, policy version, and every record to
its content checksum. The `create` factory calculates the checksum for new content; every direct,
JSON, or historical reconstruction requires the stored checksum and rejects a missing or
mismatched value rather than silently re-signing content. Changing any bucket identity component,
`allow_public`, or any principal requires a new immutable policy version and checksum.
`S3ExposureApprovalPolicyHistory` rejects
duplicate versions and rejects different content under an existing `(policy_id, version)` while
preserving exact older artifacts for reconstruction. When registered with an Assessment Profile,
that exact artifact identity/version/checksum also participates in the profile's immutable
content. The scan and assessment must retain both identities so old results reconstruct the
policy that produced them.

## Required normalized evidence and provenance

All evidence belongs to one scan, account, stable bucket identity, and bucket-home Region. The
collector must retain the complete normalized value or a typed, sanitized collection outcome for
each call; it must not log raw policy content or AWS errors.

| Source | Required normalized facts | Decision role |
| --- | --- | --- |
| STS identity, `ListBuckets`, `GetBucketLocation` | owner account, bucket name/ARN/stable ID, and authoritative home Region | Mandatory identity and scope |
| `GetBucketPolicy` | explicit `policy_present`; complete decoded statements, principals, effects, actions, resources, conditions, and digest; expected `NoSuchBucketPolicy` as absence | Mandatory policy body or declared absence; needed for supported external grants and consistency |
| `GetBucketPolicyStatus` | explicit `PolicyStatus.IsPublic`; a non-public or expected no-policy outcome when the policy is absent | Amazon S3's authoritative public-policy indicator |
| bucket `GetPublicAccessBlock` | all four bucket booleans or expected `NoSuchPublicAccessBlockConfiguration` normalized as four `false` values | Public-policy and public-ACL neutralizer input; preventive flags are context |
| account `s3control.GetPublicAccessBlock(AccountId=...)` | all four effective account booleans, including inherited organization policy where AWS applies it, or expected absence normalized as four `false` values | Other half of each effective neutralizer |
| `GetBucketAcl` | owner ID plus every grant's grantee type/identifier, group URI, and permission | Mandatory bucket-ACL channel |
| `GetBucketOwnershipControls` | explicit ownership mode or expected absence | Supplementary context for ACL investigation |
| IAM Access Analyzer operations | analyzer identity/type/Region/status and complete finding identity/status/principal/action/condition/`isPublic`/source detail | Supplementary investigation evidence only |

Every retained observation or error record includes `scan_id`, AWS account ID, bucket stable ID,
bucket ARN and name, bucket Region, collector ID and version, AWS service and API, collection time,
normalized-evidence schema version, completeness/outcome, and an evidence-artifact or content-
digest reference. The assessment cites every decisive and unknown record, the two effective BPA
values, the approval profile version/checksum, and the normalization/evaluator versions.

The normalized completeness/outcome record uses the accepted
[result-sensitive source-outcome contract](../design-decisions/0002-result-sensitive-evidence-outcomes.md).
This is why one valid channel can remain assessable when another API fails without pretending the
whole collector succeeded; the current Sprint 0--4 runtime is not changed by this planned
contract.

The minimum evidence is result-sensitive. A `PASS` requires both channels to be complete and safe
or approved. A `FAIL` may be returned when one channel proves `CONFIRMED_UNAPPROVED` even if the
other channel is `UNKNOWN`; unknown evidence cannot erase a known violation. If no channel proves
an unapproved exposure, every unknown channel is decisive and yields `INSUFFICIENT_EVIDENCE`.

## Block Public Access aggregation

For each neutralizing flag independently, the effective value is the logical OR of the effective
account value and bucket value. Amazon S3 applies the most restrictive combination.

| Account flag | Bucket flag | Effective flag |
| --- | --- | --- |
| `true` | `true`, `false`, or `UNKNOWN` | `true` |
| `false` | `true` | `true` |
| `false` | `false` | `false` |
| `false` | `UNKNOWN` | `UNKNOWN` |
| `UNKNOWN` | `true` | `true` |
| `UNKNOWN` | `false` or `UNKNOWN` | `UNKNOWN` |

The four settings do not have interchangeable meanings:

| Setting | S3-002 current-exposure treatment |
| --- | --- |
| `BlockPublicAcls` | Prevents specified future public ACL writes. It does not neutralize an existing ACL and cannot turn current exposure into `PASS`. |
| `IgnorePublicAcls` | Neutralizes bucket-ACL grants to `AllUsers` and `AuthenticatedUsers`; `GetBucketAcl` consequently reports the effective ACL rather than those ignored configured grants. It does not neutralize a grant to a specific external canonical user. |
| `BlockPublicPolicy` | Prevents future public bucket-policy writes. It does not neutralize an existing public policy and cannot turn current exposure into `PASS`. |
| `RestrictPublicBuckets` | When the whole bucket policy is public, neutralizes public and cross-account access derived from that policy except recognized AWS service principals and authorized identities in the owner's account. It has no effect on fixed external delegation in a policy that S3 classifies as non-public. |

Consequently, bucket-level BPA does not generically "override" a public policy. Only effective
`RestrictPublicBuckets = true` neutralizes public-policy-derived exposure. Likewise only effective
`IgnorePublicAcls = true` neutralizes public-group ACL exposure. Missing one side of an OR is not
uncertainty when the other side is already `true`; it is uncertainty when a grant needs the
effective result and the other side is not `true`.

## Policy channel

`GetBucketPolicyStatus.PolicyStatus.IsPublic` is authoritative for Amazon S3's public-policy
classification. The project does not reimplement S3's complete public-policy trust inference.
The decoded policy is still required to preserve evidence, detect limited contradictions, and
identify supported fixed external principals.

The external-principal proof subset accepts complete `Allow` statements targeting the assessed
bucket or its objects with `Principal.AWS` fixed account IDs, root ARNs, or exact IAM user/role
ARNs, and `Principal.CanonicalUser` fixed IDs. Same-owner principals and exact service principals
are not external. Conditions are preserved but do not approve a principal; a configured fixed
cross-account grant remains approval-relevant. `NotPrincipal`, a federated principal, an unknown
principal key, a wildcard/variable in a purported fixed identifier, or an action/resource form
the normalizer cannot safely attribute to this bucket makes that part of the channel `UNKNOWN`.
An unsupported part cannot hide another separately confirmed unapproved grant.

Public and external sub-results are evaluated separately, then combined with
`CONFIRMED_UNAPPROVED` taking precedence over `UNKNOWN`, which takes precedence over safe or
approved:

| Policy fact | Effective `RestrictPublicBuckets` | Approval/evidence fact | Policy channel |
| --- | --- | --- | --- |
| Policy is coherently absent | any | No policy grants exist | `NO_EXPOSURE` |
| Complete coherent policy and `IsPublic = true` | `true` | Any policy-derived public/fixed external grants are neutralized | `NO_EXPOSURE` |
| `IsPublic = true` | `false` | `allow_public = false` | `CONFIRMED_UNAPPROVED` |
| Complete coherent policy and `IsPublic = true` | `false` | Public is approved and all fixed external grants are approved | `APPROVED_EXPOSURE` |
| Complete coherent policy and `IsPublic = true` | `false` | Public is approved but a fixed external grant is unapproved | `CONFIRMED_UNAPPROVED` |
| `IsPublic = true` | `UNKNOWN` | Exposure might be neutralized | `UNKNOWN` |
| `IsPublic = false` | any | No supported external grant and no unresolved potentially external statement | `NO_EXPOSURE` |
| `IsPublic = false` | any | Every supported external principal is approved | `APPROVED_EXPOSURE` |
| `IsPublic = false` | any | At least one supported external principal is unapproved | `CONFIRMED_UNAPPROVED` |
| `IsPublic = false` | any | An otherwise relevant external statement is unsupported or incomplete and no confirmed violation exists | `UNKNOWN` |
| Status/body absent, denied, malformed, or contradictory | any | No independent confirmed policy violation | `UNKNOWN` |

A status of public can independently prove unapproved public exposure when
`RestrictPublicBuckets = false` and `allow_public = false`, even if the policy body lookup failed;
the failed body remains cited. It cannot produce `PASS` without the body because supported
external grants and coherence remain unknown. A body that looks public cannot replace a missing
or malformed authoritative status. A detected impossible pair—such as declared policy absence
with a successful status, or a complete unconditional public wildcard grant with
`IsPublic = false`—is a concurrent-mutation/normalization conflict and is `UNKNOWN`.

## Bucket-ACL channel

S3 defines a public ACL as a grant to the exact `AllUsers` or `AuthenticatedUsers` group URI.
Bucket-owner grants and the recognized S3 Log Delivery group are not external. A canonical-user
grant whose ID differs from `Owner.ID` is a supported external grant and canonicalizes to
`canonical-user:<id>`. Every permission on an in-scope public or external grantee is retained;
the contract does not silently ignore metadata or write permissions.

| ACL fact | Effective `IgnorePublicAcls` | Approval fact | ACL channel |
| --- | --- | --- | --- |
| Complete effective owner-only/service-only ACL | any | No returned public or external grant | `NO_EXPOSURE` |
| Effective public-group grant | `false` or `UNKNOWN` | `allow_public = false` | `CONFIRMED_UNAPPROVED` |
| Effective public-group grant | `false` or `UNKNOWN` | `allow_public = true` and no unapproved external grant | `APPROVED_EXPOSURE` |
| Effective public-group grant | `true` | The effective ACL contradicts the effective flag | `UNKNOWN` |
| External canonical-user grant | any | Principal token is approved | `APPROVED_EXPOSURE` |
| External canonical-user grant | any | Principal token is not approved | `CONFIRMED_UNAPPROVED` |
| Returned public grant plus unapproved external canonical-user grant | `true` | Public grant conflicts with the flag; the separate effective external grant is still decisive | `CONFIRMED_UNAPPROVED` |
| Unknown grantee, legacy email grantee, malformed grant, denied/incomplete call, or ownership mismatch | any | No separate confirmed violation | `UNKNOWN` |

`GetBucketAcl` reports effective permissions when `IgnorePublicAcls` is enabled. The collector
retains exactly those returned effective grants and the effective flag; it does not claim to
reconstruct an ignored configured public ACL or claim that removing BPA would remain safe. Thus
an effective owner-only ACL can be safe even when a configured public grant is hidden, while a
returned public-group grant plus effective `IgnorePublicAcls = true` is contradictory evidence and
is `UNKNOWN`. `RestrictPublicBuckets` does not neutralize ACL grants.

## Final aggregation

The evaluator combines the policy and ACL channel outcomes in this order:

| Policy channel | ACL channel | S3-002 result |
| --- | --- | --- |
| `CONFIRMED_UNAPPROVED` | any, including `UNKNOWN` | `FAIL` |
| any, including `UNKNOWN` | `CONFIRMED_UNAPPROVED` | `FAIL` |
| `UNKNOWN` | no confirmed unapproved exposure | `INSUFFICIENT_EVIDENCE` |
| no confirmed unapproved exposure | `UNKNOWN` | `INSUFFICIENT_EVIDENCE` |
| `NO_EXPOSURE` or `APPROVED_EXPOSURE` | `NO_EXPOSURE` or `APPROVED_EXPOSURE` | `PASS` |

`NOT_APPLICABLE` is valid only for the control-level no-resource case after complete S3 bucket
discovery finds no in-scope general purpose buckets. It is never used for an individual discovered
bucket, an inaccessible bucket, or a bucket that disappeared during follow-up.

## Collection failures and coherence

| Observed condition | Normalized treatment | Result consequence absent another confirmed violation |
| --- | --- | --- |
| `NoSuchBucketPolicy` from policy retrieval, coherently paired with a non-public or no-policy status outcome | Explicit complete absence | Policy `NO_EXPOSURE` |
| `NoSuchPublicAccessBlockConfiguration` | Explicit complete all-false configuration at that level | Continue with effective-OR table |
| `AccessDenied`, throttling, transport failure, unexpected service error | Typed sanitized incomplete source | Affected channel `UNKNOWN` |
| `NoSuchBucket` after discovery, including deletion during the scan | Resource-disappeared conflict; do not fabricate absence | Bucket `INSUFFICIENT_EVIDENCE` |
| Wrong-Region response followed by successful bucket-home-Region retry | Retain redirect and successful home-Region provenance | Evaluate normally |
| Wrong-Region response with no successful authoritative retry | Incomplete source | Affected channel `UNKNOWN` |
| Missing field, wrong type, undecodable policy, invalid principal/grant, or non-progressing collection | Malformed evidence | Affected channel `UNKNOWN` |
| Calls refer to different owner, bucket, Region, scan, or incompatible observed states | Coherence conflict | Bucket `INSUFFICIENT_EVIDENCE` unless a separately coherent channel already proves an unapproved exposure; deletion invalidates the bucket snapshot itself |
| Partial evidence with one separately coherent confirmed unapproved channel | Unknown plus confirmed violation | `FAIL`, with both facts cited |

Arbitrary sleeps are not a coherence strategy. The future collector records all calls within the
scan and rejects detected contradictions; it never rewrites an AWS failure into a negative fact.

## Representative contract cases

This table is the machine-checked acceptance surface for the documented aggregation. `safe` means
the other channel is complete and `NO_EXPOSURE` unless the row says otherwise.

<!-- s3-002-contract-cases:start -->
| Case ID | Decisive normalized facts | Expected result |
| --- | --- | --- |
| `private-policy-and-acl` | Policy coherently absent; ACL owner-only | `PASS` |
| `public-policy-unapproved` | `IsPublic=true`; effective restrict=false; public not approved; ACL safe | `FAIL` |
| `public-acl-unapproved` | Public group ACL; effective ignore=false; public not approved; policy safe | `FAIL` |
| `public-policy-neutralized` | Complete coherent policy; `IsPublic=true`; bucket restrict=true; account restrict missing; ACL safe | `PASS` |
| `public-acl-neutralized` | `GetBucketAcl` returns an effective owner-only ACL under account ignore=true; bucket ignore missing; policy safe | `PASS` |
| `block-public-policy-only` | `IsPublic=true`; only BlockPublicPolicy=true; public not approved; ACL safe | `FAIL` |
| `block-public-acls-only` | Public group ACL; only BlockPublicAcls=true; public not approved; policy safe | `FAIL` |
| `missing-policy-evidence` | Policy body/status incomplete with no confirmed violation; ACL safe | `INSUFFICIENT_EVIDENCE` |
| `missing-bpa-evidence` | Public policy; both effective restrict inputs not known true; public not approved; ACL safe | `INSUFFICIENT_EVIDENCE` |
| `policy-access-denied` | Policy body/status AccessDenied with no confirmed violation; ACL safe | `INSUFFICIENT_EVIDENCE` |
| `status-proves-public-despite-body-denied` | Body AccessDenied; status public; effective restrict=false; public not approved; ACL safe | `FAIL` |
| `bucket-deleted-during-scan` | NoSuchBucket after discovery | `INSUFFICIENT_EVIDENCE` |
| `conflicting-policy-evidence` | Declared absent body but successful public status | `INSUFFICIENT_EVIDENCE` |
| `conflicting-acl-evidence` | Effective public-group ACL grant together with effective ignore=true | `INSUFFICIENT_EVIDENCE` |
| `malformed-acl-evidence` | ACL contains malformed grantee; policy safe | `INSUFFICIENT_EVIDENCE` |
| `approved-public-policy` | Public policy; effective restrict=false; public approved; no external grant; ACL safe | `PASS` |
| `approved-external-policy` | Non-public policy grants account:111122223333; exact token approved; ACL safe | `PASS` |
| `unapproved-external-policy` | Non-public policy grants account:111122223333; token unapproved; ACL safe | `FAIL` |
| `external-acl-not-neutralized` | External canonical-user ACL grant unapproved; effective ignore=true; policy safe | `FAIL` |
| `unknown-plus-known-failure` | Policy incomplete; unapproved external canonical-user ACL grant | `FAIL` |
| `analyzer-only-finding` | Direct policy and ACL channels safe; supplementary active Analyzer finding exists | `PASS` |
<!-- s3-002-contract-cases:end -->

The last row is intentionally scoped: the finding is retained and surfaced for investigation,
but it may represent an access point or a delayed view and is not a v1 S3-002 decision source.

## Access Analyzer and explicit v1 limitations

IAM Access Analyzer is Regional and its zone of trust changes the meaning of "external." Findings
can lag policy or BPA changes, can be archived without removing access, and can include bucket
policy, ACL, access point, or Multi-Region Access Point sources. Therefore Analyzer facts are
supplementary in v1: an active, archived, resolved, absent, incomplete, or error finding never
overrides the coherent direct policy/ACL result and never acts as an approval. All findings and
errors are still retained with analyzer identity, type, Region, status, timestamps, and source for
future investigation and possible separately versioned contract evolution.

The following are outside the v1 decision surface:

- access point and Multi-Region Access Point policies and access-point BPA;
- object ACL enumeration and object-by-object ownership;
- S3 Access Grants, presigned URLs, CloudFront origin access, and application-layer sharing;
- effective evaluation of identity policies, SCPs, RCPs, VPC endpoint policies, KMS policies,
  explicit denies, and every IAM condition operator; and
- directory buckets and resource types not discovered as general purpose buckets.

In particular, a bucket-level `PASS` does not prove that every object ACL or access-point path is
private. Sprint 5 must not fabricate those facts. Expanding the decision surface later requires a
new reviewed contract/evaluator version and any necessary evidence additions; it cannot silently
change historical results.

## Authoritative AWS references

- [Blocking public access to S3 storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [GetBucketPolicyStatus](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicyStatus.html)
- [GetBucketPolicy](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketPolicy.html)
- [GetBucketAcl](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetBucketAcl.html)
- [GetPublicAccessBlock](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetPublicAccessBlock.html)
- [Configuring account Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-block-public-access-account.html)
- [IAM Access Analyzer for S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-analyzer.html)
- [How Access Analyzer findings work](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-concepts.html)
