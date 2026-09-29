# Sprint 6E S3 implementation preflight

Prepared: 2026-09-28. Analysis only; no S3 control is enabled by this document.
[ROADMAP.md](../../ROADMAP.md) owns state and the
[active Sprint 6 plan](../exec-plans/active/sprint-6.md) owns scope.

## Starting checkpoint and gate

Superseding checkpoint, 2026-09-29: PR #32 merged both reviewed 6D slices into main at
`9ad7feab10d8f87f91d878920c6cf40a5d6fe51b`; merged-main CI passed. The proposed two-PR
sequence below was not needed. Clean local main was synchronized and branch
`codex/sprint-6e1-s3-bpa-transport-controls` created from that accepted checkpoint.
The user approved combined BPA and bounded HTTPS-denial policy direction; the
[6E.1 approved metadata](sprint-6e1-metadata.md) records those choices and the subsequent
explicit metadata approval. 6E.1 is now authorized and underway; the original preflight below is historical
where it refers to pending 6D acceptance or undecided 6E.1 policy direction.

Accepted main is `c7d85e2a36a8e8aa0bc044a9fc22b7ea8cdbf01c` (6C). The reviewed local 6D
stack adds catalog `0.6.0` for security groups and `0.7.0` for VPC Flow Logs, with migration head
`20260924_0004` unchanged. Combined independent review passed with zero findings. Local full
regression passed 1,654 tests; 76 disposable PostgreSQL cases skipped. PostgreSQL/image CI and
human acceptance remain outstanding; this is not a declaration that 6D is COMPLETE.

Finish the two bounded 6D PRs first. Target 6D.1 at main and 6D.2 at 6D.1 for review; after the
base merges, retarget the second PR to main and verify its final diff/CI. Do not automatically
merge, rewrite published history, or resolve stack conflicts without inspecting them. Once both
are accepted, start `codex/sprint-6e1-s3-bpa-transport-controls` from clean, synchronized main.
Reverify its actual merged SHA, migration head and CI; this document does not pin a future SHA.
Do not start 6E implementation or another stacked branch merely because this preflight exists.

## Authoritative contracts

- [Control catalog](catalog.md): S3-001/002/003/004 meanings are reserved; S3-900 is preserved.
- [S3-002 aggregation](s3-002-exposure-aggregation.md): fixed policy/ACL channels, effective BPA
  neutralizers, exact bucket-scoped approvals, same-owner exclusions, uncertainty and final table.
- [S3-004 classifier](s3-004-sensitive-bucket-classifier.md): immutable classifier schema 1.0.0,
  exact identities, restricted patterns, tag rules, overrides and historical reconstruction.
- [Evidence matrix](sprint-5-evidence-readiness.md): existing 5E source APIs, scope and fields.
- [Assessment foundation](../assessment-foundation.md) and [persistence](../persistence.md):
  accepted 6A exact catalog/profile recovery, durable policy artifacts and immutable history.
- [Result-sensitive evidence](../design-decisions/0002-result-sensitive-evidence-outcomes.md):
  incomplete sources do not erase an independently proved violation or fabricate a clean result.

The original pre-Sprint-5 contract narratives describe profile/database integration as future
work. Accepted 6A already supplies that integration through `ExtendedAssessmentProfile` and
the immutable artifact registry. Reuse it; do not add another registry or rewrite old schemas.

## Bounded sequence

| Slice | Implementation scope after approval | Evidence and integration focus |
| --- | --- | --- |
| 6E.1 | S3-001 BPA configuration and S3-003 secure transport | Global bucket discovery and account BPA; authoritative bucket-home Region and identity; bucket BPA and decoded policy/expected absence. Approve the missing truth tables before registration. |
| 6E.2 | S3-002 public/external exposure | Existing direct policy/status/ACL/account+bucket BPA facts; exact approval artifact; canonical result-sensitive aggregation. Analyzer remains supplementary. |
| 6E.3 | S3-004 sensitive-data KMS requirement | Reuse the exact classifier; tags versus unavailable tags; encryption rules and referenced KMS facts; exact resolved bucket-to-key relationships where required by the approved decision. |

Keep these as separate reviewed opt-in catalog releases, preserving every earlier catalog,
framework artifact, profile checksum and default `0.2.1`. Allocate release/evaluator identifiers
with approved metadata before each implementation. The slices consume already collected facts;
no additional AWS API or permission is currently identified as necessary.

## Integration seams inspected

| Existing boundary | Required bounded work |
| --- | --- |
| `app/collectors/s3.py`, evidence-graph/source schemas | Reuse discovery, authoritative bucket location, typed per-source values and sanitized states. S3 global discovery and bucket-home Region differ from the network requested-Region population proof; do not copy its regional assumptions. Preserve discovery gaps and disappeared buckets as insufficient, never complete empty N/A. |
| `app/assessment/evidence_reader.py`, `execution.py` | Add a closed, version-bound S3 proof only when implementing the affected slice. Preserve old strategy meanings and source completeness guards. Shared proof/result validation must work identically at engine and persistence boundaries. |
| `app/assessment/extended_profiles.py`, `s3_exposure.py`, `sensitive_buckets.py` | Reuse complete strict approval/classifier artifacts and exact policy checksums. Empty approval records differ from a missing artifact; a vacuous classifier remains invalid. Recompute classification from historical evidence rather than trusting supplied classifications. |
| `app/database/catalogs.py`, `persistence.py` | Existing artifact storage and immutable version checks already apply. Bind new assessments to exact source IDs/digests, profile/evaluator/catalog versions and required edges; reject forged results atomically. Do not add a migration unless an approved new persisted policy actually requires one. |
| `app/rules/registry.py`, `engine.py`, scan services/executor | Explicit opt-in releases only; retained pending scans resolve their exact old catalog/profile. S3-002 needs result-sensitive proof, not a global relaxation of all-required-sources completeness. No cross-control scheduler is needed for 6E. |
| Generic API/auth and future LOG-004 | Reuse scan/resource/history/assessment/evidence/finding/framework interfaces with real capabilities. Retain exact S3-002 bucket snapshot/result for later LOG-004 composition; do not implement LOG-004 or its scheduler in 6E. |

S3-002 must support a coherent confirmed violation with another unknown channel, citing both;
PASS requires complete safe/approved channels. The existing generic evidence reader rejects
incomplete required sources, so merely registering a rule against that strategy would violate
the accepted S3-002 table. This is planned 6E.2 integration, not a defect in accepted 6D behavior.
Whole-scan completeness requirements for finding resolution remain unchanged.

## Decisions still requiring approval

These are the active plan's existing gates, not new requirements or approved policy defaults.

1. **S3-001 direction approved 2026-09-29:** require the effective account/bucket OR for each
   flag, not independently enabled flags at both levels. Record
   PASS/FAIL/insufficient/empty-population behavior, including partial evidence, before implementation.
2. **S3-003 direction approved 2026-09-29:** bounded explicit secure-transport Deny proof.
   The implementation decision table must fix supported principals,
   action coverage, bucket/object resource coverage, Boolean condition forms, additional
   conditions and unsupported syntax. Do not create a general IAM policy solver or mistake
   absence of an explicit Allow for enforced TLS. Missing policy and unavailable policy differ.
3. **S3-002:** supply/approve the immutable deployment approval artifact. An explicitly empty
   `bucket_approvals` tuple can mean no approvals; absence of the artifact cannot. Keep the
   already-approved channel tables and exact owner/account/Region/stable-ID principal matching.
4. **S3-004:** approve AWS-managed versus customer-managed KMS acceptance; treatment of SSE-KMS,
   DSSE-KMS, explicit key references and missing references; and the result when
   `restricted_data_requires_kms` is false. Approve the actual nonempty classifier artifact.
   Do not infer sensitive tag keys or silently add a customer-managed-key requirement.
5. **Each slice:** approve severity, impact/operator guidance, evaluation/catalog identities and
   independently sourced NIST mappings. NIST mappings never decide technical outcomes.

No policy choice in this section has been selected automatically. Only the two 6E.1 directions
above and the 6E.1 metadata have subsequently been approved; later-slice gates remain. Stage approvals per slice;
6E.1 need not wait for organization-specific 6E.3 classifier content once its own gates and the
accepted starting baseline are satisfied.

## Validation and acceptance plan

- Extend existing offline S3 collector fixtures; keep production collection facts-only. Cover
  home-Region routing, exact owner/identity, expected absence, denied/malformed/disappeared
  evidence, empty versus incomplete discovery, and relevant resolved/unresolved relationships.
- Use the canonical S3-002 representative cases as evaluator tests, including known violation
  plus unknown, same-owner/service exclusions, effective versus preventive BPA flags, detected
  contradictions and supplementary Analyzer data. Existing contract-text tests alone do not
  validate a future runtime evaluator.
- Test S3-004 exact classifier/version reconstruction and re-evaluation, positive signals with
  unavailable tags, overrides, complete nonmatches, malformed/missing configured facts and the
  approved encryption table. Do not change classifier schema 1.0.0 semantics.
- Prove old/new populated history, exact pending-scan recovery, transactional forged-result
  rejection and finding lifecycle. Add isolated PostgreSQL cases using existing fixtures.
- Real bearer/capability HTTP acceptance must retain routing, executor, collectors, rules,
  persistence and public read APIs. Replace only AWS; use bounded polling and no arbitrary sleeps.
- For each implementation: targeted checks, full regression, Ruff lint/format, links/whitespace,
  PostgreSQL acceptance, applicable Compose/image checks, independent review, final-HEAD CI and
  explicit human merge approval. Preserve S3-900 and all accepted 0–6D behavior.

No new dependency, collector, API endpoint, authentication model, remediation, dashboard,
production deployment or AI work is proposed. This preflight ends at the decision gates.
