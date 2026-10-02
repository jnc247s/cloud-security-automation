# Sprint 6E.2 — S3-002 release metadata

Approved implementation bundle: 2026-09-29; authorization and acceptance gates are recorded in
the [completed plan](../exec-plans/completed/sprint-6.md). [ROADMAP.md](../../ROADMAP.md) alone owns
progress. The [canonical channel contract](s3-002-exposure-aggregation.md) is unchanged.

## Release and policy

- Control: S3-002, Unapproved public/external bucket exposure; severity HIGH.
- Explicit catalog: `aws-cloud-security-controls` version `0.9.0`, extending immutable `0.8.0`.
- Evaluator: `1.0.0`; closed execution schema `1.6.0`, strategy `s3_exposure_v1`.
- Reporting: independently checksummed NIST `2.0+subset.8`, PR.AA-05. It reuses the sourced
  reference recorded in [6E.1 metadata](sprint-6e1-metadata.md), not a new compliance claim.
  Direct exposure configuration contributes access-policy enforcement evidence only; it does
  not prove complete least privilege, actual access or compliance. Framework metadata does not
  determine technical results. Earlier framework/catalog bytes remain unchanged.
- Impact: unapproved public or cross-account grants can expose bucket data or permissions.
  An authorized operator must review dependencies and legitimate sharing before changing grants
  or safeguards. This code performs no AWS writes.

The approved initial policy has no exemptions. The following is an explicit artifact, not a
fallback when configuration is absent:

```json
{
  "policy_id": "s3-exposure-approvals",
  "schema_version": "1.0.0",
  "version": "1.0.0",
  "bucket_approvals": [],
  "content_checksum": "7a2794e921afef3e2b98f0674ff916fa4c2b22fa34cbaf7f8f0b7c1210c45cce"
}
```

Use the existing protected local policy-file envelope described in the
[assessment foundation](../assessment-foundation.md), explicitly selecting catalog `0.9.0`
and a new schema-2 profile version enabling `S3-002`, with this artifact in
`s3_exposure_approvals`. No live configuration is created or modified by this implementation.
Missing policy is rejected; legitimate exemptions require an authorized, newly versioned exact
bucket/account/Region/principal artifact and new profile. Keep real policy data outside Git.

## Proof and compatibility

The shared engine/persistence proof binds complete bucket discovery, authoritative home Region,
account and bucket BPA, policy/status, ACL and ownership context to exact same-scan source IDs
and digests. Unavailable observations remain cited; retained ACL conflicts cannot conceal an
independent external grant. Any detected bucket disappearance invalidates that bucket assessment.
The proof retains effective neutralizers, both channel outcomes and exact profile/policy
checksums. It does not duplicate approvals for unrelated buckets into an assessment artifact.

PASS requires both channels safe or explicitly approved. Confirmed unapproved exposure yields
FAIL even when another channel is unknown. Otherwise uncertainty is INSUFFICIENT_EVIDENCE.
Only complete empty discovery is N/A. Access Analyzer is supplementary, and exceptions cannot
approve exposure or rewrite technical results. A partial scan cannot resolve an existing finding.
Stored policy/profile recovery is exact even after deployment configuration changes.

Default `0.2.1`, all earlier controls/catalogs, auth, API schemas, collectors, AWS permissions and
migration head `20260924_0004` are unchanged. No S3-004, LOG-004, scheduler or later-sprint work.

## Validation entry point

```text
python -m scripts.validate --focused tests/unit/rules/test_s3_exposure.py tests/unit/database/test_s3_exposure.py tests/integration/test_s3_exposure_postgres.py
```

The runner creates and removes an isolated PostgreSQL container, runs focused and complete
regression, Ruff, whitespace and container gates. It never reuses a user database. Tests cover
all 21 canonical cases, exact approvals, history, atomic forgery rejection, pending recovery,
finding lifecycle and real authenticated HTTP/executor/public retrieval; only AWS is offline.
No arbitrary collection sleeps, Principal overrides or mocked rule/persistence boundaries.
