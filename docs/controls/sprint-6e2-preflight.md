# Sprint 6E.2 — S3 exposure implementation preparation

Prepared: 2026-09-29. Analysis only; this document does not enable S3-002 or approve policy.
[ROADMAP.md](../../ROADMAP.md) owns status; the [completed plan](../exec-plans/completed/sprint-6.md)
owns task scope. The [canonical S3-002 contract](s3-002-exposure-aggregation.md) remains the
authority for every channel/result decision. Do not redefine it here.

## Starting gate and Git workflow

6E.1 implementation is committed at `f2b57d514a9eb20d4b7d7a21dc35626bc4f6ca5a`, following
the migration-comparison repair `ce49f3b` and local validation automation `8b12191`.
It is pushed on `codex/sprint-6e1-s3-bpa-transport-controls`; local regression passed all
1,790 tests, including 88 PostgreSQL cases, and the single independent review has zero findings.
Final branch CI and approved merge remain required. GitHub's connector refused PR creation
with HTTP 403; use the manual comparison link in the active plan, without changing credentials
or access policy. This preparation is carried with the publication handoff, not a stacked
6E.2 implementation branch.

After 6E.1 is merged, verify green merged-main CI and a clean synchronized main, then create
`codex/sprint-6e2-s3-exposure-control`. Recheck the actual merged SHA and migration head
(`20260924_0004` currently). Do not mark 6E.1 complete or start 6E.2 from an unaccepted stack.

## Bounded implementation

Implement S3-002 only, over the existing general-purpose bucket policy/ACL evidence. Keep
S3-001/003, S3-900, all older catalogs and default `0.2.1` unchanged. No collector/API/authentication
redesign, new AWS calls/permissions, schema migration, S3-004 or LOG-004 implementation is planned.
No live AWS, remediation, dashboard or deployment work is authorized.

1. Add a pure policy-channel and ACL-channel evaluator using the canonical tables and supported
   principal/action/resource subset. Same-owner and recognized service principals are not external.
   Preserve conditions/denies as evidence without claiming effective-permissions computation.
2. Bind exact same-scan bucket identity/home Region, complete discovery, declared source outcomes,
   artifact digests and the immutable approval artifact. Retain unknown observations alongside
   decisive evidence. Reuse existing identity/provenance helpers without modifying older strategies.
3. Add a separately versioned, closed exposure-proof strategy shared by engine and persistence.
   Recompute expected result and proof at the persistence boundary, including exact historical
   approval identity/version/checksum. Do not add exposure semantics to execution schema `1.5.0`.
4. Register S3-002 only in a new explicitly selected catalog/profile after metadata approval.
   Preserve existing version bytes, pending-scan recovery, atomic persistence, exceptions and
   whole-scan finding-resolution rules. Leave a canonical persisted assessment for later LOG-004
   composition; do not implement a dependency scheduler in this slice.

## Inspected integration contracts

| Existing component | Reuse or bounded extension |
| --- | --- |
| `app/collectors/s3.py` and the [evidence matrix](sprint-5-evidence-readiness.md) | Already retain discovery/location, policy, policy status, ACL, account/bucket BPA and sanitized source outcomes. Ownership controls and Analyzer remain context. No evidence expansion required. |
| `app/assessment/s3_exposure.py`, `s3_identity.py` | Strict immutable approval content, exact account/Region/ARN/stable identity, canonical principal tokens and checksum validation already exist. |
| `extended_profiles.py`, `app/database/catalogs.py` | Explicit S3 approval input, complete profile checksums, immutable artifact registry and exact historical loading already exist. Missing artifact differs from an explicitly empty one. |
| `s3_configuration_evidence.py`, `execution.py`, `evidence_reader.py` | Reuse source binding/target conventions; add a closed exposure-specific strategy. The generic all-required-source proof cannot express known violation plus unknown channel. |
| `app/rules/registry.py`, scan executor and services | Explicit catalog resolution and historical recovery already exist. Generic authenticated API projections need no control-specific route. |
| Existing S3 contract/unit and SQLite/PostgreSQL/HTTP fixtures | Extend runtime acceptance, not merely Markdown assertions. Only AWS is replaced in end-to-end tests. |

## Mandatory result boundaries

- A coherent confirmed unapproved channel yields FAIL even when another channel is UNKNOWN.
  Otherwise UNKNOWN yields INSUFFICIENT_EVIDENCE; PASS requires both channels safe or approved.
- Account/bucket BPA combines by the canonical per-flag OR. Preventive BlockPublicPolicy and
  BlockPublicAcls do not neutralize existing exposure. RestrictPublicBuckets and IgnorePublicAcls
  have distinct channel-specific effects; no generic "BPA enabled means private" shortcut.
- Missing/malformed approval policy cannot become an empty policy. Exact empty `bucket_approvals`
  means no approved exposure, only when an explicit complete versioned artifact was provided.
- Detected policy/status or ACL/BPA contradictions retain uncertainty. Resource disappearance
  invalidates the bucket snapshot; no FAIL/PASS from a deleted bucket's stale facts.
- No discovered bucket is N/A. Control-level N/A requires complete empty discovery.
- Analyzer findings and operational exceptions cannot approve exposure or override direct facts.

## Proposed decisions for one implementation approval

These are recommendations, not selected deployment defaults or approved control metadata:

- **Approval artifact:** start with explicit `s3-exposure-approvals` schema `1.0.0`, policy version
  `1.0.0`, empty `bucket_approvals` (no public/external exemptions). Generate and verify its actual
  canonical checksum using the existing factory during implementation. If legitimate exposure
  must be approved, the operator must instead provide exact scoped records through the protected
  policy file; never place real account/bucket/principal policy data in this preparation document.
- **Metadata:** HIGH severity, evaluator `1.0.0`, opt-in catalog `0.9.0` extending `0.8.0`, and
  separately checksummed NIST subset `2.0+subset.8`, subject to version availability at start.
- **Mapping:** PR.AA-05, for configuration evidence of access-policy enforcement only, reusing
  the sourced NIST reference documented in [6E.1 metadata](sprint-6e1-metadata.md). This neither
  determines technical results nor claims complete least privilege, actual access or compliance.
- **Impact/guidance:** unapproved public or cross-account configuration can expose bucket data or
  permissions. An authorized operator must review workload dependencies and legitimate sharing
  before removing grants or changing safeguards. No AWS writes or automated remediation.

Approve these inputs together (or supply replacements) when requesting implementation. The
already accepted channel truth tables do not require another design approval or specialty review.

## Acceptance and stopping point

Implement every existing representative canonical case as a runtime test, including safe/private,
approved/unapproved exposure, same-owner/service exclusions, channel-specific neutralizers,
coherence conflicts, unavailable evidence and known failure plus unknown. Verify exact identity,
historical approval versions, policy substitution/forgery rejection, empty discovery, pending-scan
recovery and finding lifecycle. Prove real bearer/capability HTTP -> executor -> fake AWS -> rules
-> PostgreSQL -> the same public scan/resource/history/assessment/evidence/finding IDs.

Use `python -m scripts.validate --focused <slice-test-paths>` at the stable slice gate, followed by
one consolidated independent review, final-HEAD CI and human merge approval. Keep targeted tests
fast during edits and rerun full validation only when required or invalidated by later changes.
This task stops at preparation: no executable S3-002, new profile, policy artifact or catalog is
created by this document. 6E.3, 6F and later work remain unstarted.
