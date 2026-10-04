# Cloud Security Control Plane roadmap

`ROADMAP.md` is the canonical source of project progress. The status recorded here overrides old
prompts, conversations, branch names, and historical planning text.

Last verified: 2026-10-04
Accepted implementation baseline: `main` at `9ace4e65f15be678d3f05c4b5ef3a9896d4ea187` (PR #43;
Sprints 0--6 and Sprint 7A/7B accepted, including exact-scan READ reporting and the opt-in
authenticated shell, catalog `0.13.0` and migration `20261001_0006`; merged-main CI passed)

## Current state

| Sprint | Outcome | Status |
| --- | --- | --- |
| Sprint 0 | Application Foundation | **COMPLETE** |
| Sprint 1 | AWS Resource Inventory | **COMPLETE** |
| Sprint 2 | Security Rules Engine | **COMPLETE** |
| Sprint 2.1 | Assessment Framework / NIST / Control Contracts | **COMPLETE** |
| Sprint 3 | Persistence / History / Evidence / Findings / Exceptions / Audit | **COMPLETE** |
| Sprint 4 | Service Layer / Authentication / Authorization / REST API / Scan Execution | **COMPLETE** |
| Sprint 5 | AWS Evidence Expansion | **COMPLETE** |
| Sprint 6 | Production Security Controls | **COMPLETE** |
| Sprint 7 | Dashboard / NIST Technical Posture | **IN PROGRESS** |
| Sprint 8 | Human-Approved Remediation | **PLANNED** |
| Sprint 9 | Hardening / Scanner Validation | **PLANNED** |
| Sprint 10 | AWS Deployment / v1.0 | **PLANNED** |
| Optional post-v1 | AI Security Investigation Agent | **DEFERRED** |

Sprint 5 is `COMPLETE`. Its shared 5G relationship/source-outcome evidence
foundation and 5A EC2/EBS, 5B VPC/network, 5C IAM, and 5D IAM Access Analyzer evidence slices are
accepted on `main`, as are the bounded fact-only 5E S3 and referenced-KMS and 5F CloudTrail
evidence slices. The bounded 5G closure passed acceptance and was merged in pull request 25.
Sprint 6 is `COMPLETE`. Slices 6A through 6H are accepted and merged; the historical slice
checkpoints below retain their exact validation and approvals. Both 6D slices were
accepted through PR #32 at `9ad7feab10d8f87f91d878920c6cf40a5d6fe51b`; merged-main CI passed.
The user requested 6E implementation and approved combined account/bucket Block Public Access
protection and bounded explicit HTTPS-denial evaluation for 6E.1. The subsequent metadata
approval authorized opt-in catalog `0.8.0`; 6E.1 is COMPLETE, merged through PR #33 at
`4b3d7355dafe6eceab50214ee2281b0b4f96fa81` with green merged-main CI and zero review findings.
The user directed implementation of the prepared 6E.2 bundle after its policy approval prompt;
6E.2 is COMPLETE, accepted through PR #34 at `3eddcaf74fd26e08428464780a2c1a6dd7f6c1bf`,
with green merged-main CI. It uses explicit no-exemption initial policy and opt-in catalog `0.9.0`.
Its [implementation metadata](docs/controls/sprint-6e2-metadata.md) and completed-plan checkpoint
record 1,873 passing tests including 102 PostgreSQL cases, successful quality/container gates,
and independent REVIEW_PASS with zero findings. The human-created PR and merge supersede the
earlier publication-permission blocker; no automatic merge was performed.
The default catalog remains unchanged; all added controls require explicit catalog/profile
selection. [6E.2 preparation](docs/controls/sprint-6e2-preflight.md) records its bounded scope;
the completed plan records authorization. The user approved the 6E.3 policy bundle on 2026-09-30
and requested implementation after 6E.2 acceptance. 6E.3 is COMPLETE: PR #35 merged the reviewed
S3-004 implementation through `447eeb1` into `main` at
`c861713a665669da09d5bc7b5b282b04c16cac1d`. The
[merged-main CI run](https://github.com/jnc247s/cloud-security-automation/actions/runs/36825207102)
succeeded on attempt 2 after attempt 1's only failure was a transient package-download timeout
during the API image build. Local acceptance passed 1,957 regression tests including 122
PostgreSQL cases and quality/container gates. Independent review passed with zero unresolved
findings after two LOW documentation inconsistencies were corrected and verified. The
[completed-plan checkpoint](docs/exec-plans/completed/sprint-6.md#6e3-acceptance-checkpoint--2026-10-01)
records the merge and final gate.
The [6E.3 preparation](docs/exec-plans/completed/sprint-6.md#6e3-implementation-preparation--2026-09-30)
records its bounded S3-004 design and classifier/KMS bundle; the completed plan's authorization,
implementation, and acceptance checkpoints record its approval and completion. PR #36 merged
the separate README/documentation repair at `49500c95c78870d72e6179882bae4e6379cdd6d0`; its
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36900929958)
passed. The user requested 6F preparation on 2026-10-01. The
[analysis-only preflight](docs/controls/sprint-6f-preflight.md) proposes LOG-002/003 first, then
LOG-004 exact same-scan S3-002 composition. Metadata, the bounded composition seam and the
empty-population LOG-004 clarification were initially pending. The user's subsequent
`implement 6f1` request approves the prepared LOG-002/003 bundle and authorizes 6F.1 only.
6F.1 is COMPLETE in opt-in catalog `0.11.0`; independent review passed with zero unresolved
findings. [Pull request #37](https://github.com/jnc247s/cloud-security-automation/pull/37) merged
at `3a053ff396a2c112aa254842cb25730fe3879ecc`, with green final-head and merged-main CI. The user subsequently
approved the remaining Sprint 6 policy bundle and persistent Goal, scoped publication, one
read-only independent reviewer per slice and conditional merges after all mandatory gates.
LOG-004/6F.2, GOV-001/6G and whole-sprint 6H acceptance are COMPLETE. The
[completed-plan authorization](docs/exec-plans/completed/sprint-6.md#remaining-sprint-6-authorization-and-6f1-acceptance--2026-10-01)
records the exact policies, boundaries and merge conditions. No later-sprint implementation is
authorized.
Accepted GOV-001 is registered in opt-in `0.13.0`, with closed proof `1.10.0`, exact initial
Owner/Environment policy across all 11 families, separate NIST subset `.12` and the approved
additive `governance` category / `20261001_0006` migration. It merged through
[PR #39](https://github.com/jnc247s/cloud-security-automation/pull/39) at
`5043f61b384c8c4499710d2033f7636676705deb`.
After the review corrections, fresh validation passed 410 focused and 2,491 regression tests,
including 238 disposable PostgreSQL cases, with no skips and all quality/container gates green.
The same reviewer verified all original findings resolved with zero new findings after 274
independent checks and returned REVIEW_PASS for exact head
`d2874a38f7be468ddc3f307a8fb2251dac8c7d70`. Both exact final-head CI runs and
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36949198125)
passed; main ran 2,491 tests with 20 existing warnings, no skips, Ruff, 335-file formatting and
image build. The [acceptance checkpoint](docs/exec-plans/completed/sprint-6.md#6g-acceptance-and-6h-start--2026-10-01)
records exact heads, review and gates.
See [6G metadata](docs/controls/sprint-6g-metadata.md). No deployed policy,
collector, AWS permission or authentication change. 6H subsequently verified whole-sprint
acceptance through PR #40 from that clean main; later-sprint implementation remains unstarted.
The reviewed LOG-002/003 implementation, tests and approved persistence repair are committed
on the scoped feature branch; unrelated parent-checkout skill files remain excluded and preserved.
Initial acceptance was blocked by a pre-existing domain/database mismatch for unresolved
regional CloudTrail destination references; see [6F.1 metadata](docs/controls/sprint-6f1-metadata.md).
The user subsequently approved the narrowly scoped persistence repair, including an additive
migration if needed, and resumption of 6F.1 validation. The completed plan records its preservation,
upgrade and rollback requirements; no production operation or acceptance is authorized by it.
The local repair adds migration `20261001_0005`, preserving unresolved facts, strict complete
identities, immutable history and downgrade safety. The user authorized one read-only independent
reviewer, who found one MEDIUM boolean/numeric proof-binding defect. Its scoped correction keeps
strict JSON types in the new `1.8.0` projection/proof path without changing historical schemas;
the same reviewer verified it and returned REVIEW_PASS with zero unresolved findings.
Post-review acceptance passes 274 focused checks and 2,125 regression tests, including all 171
PostgreSQL integration cases, with no skips. Ruff, formatting, documentation contracts,
whitespace, Compose and the API image build pass. The disposable database was removed;
no operator database or live AWS account was used. Implementation commit
`f299966f7166a202922341bc5c05f56f962a41ad` and reviewed final documentation head
`2879ea8ae25dd00bd7229976fea5a65f2b48f3c7` are merged through PR #37 under the user's bounded
conditional merge approval. [Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36930583998)
passed 2,125 tests (20 existing warnings, no skips), lint, format and image build. The completed plan
retains historical publication checkpoints and the superseding acceptance record.

Accepted 6F.2 implements LOG-004 in opt-in `0.12.0`, with closed same-invocation S3-002 dependency
proofs and no migration/default change. The initial gate passed 339 focused and 2,196 regression
checks, including 196 disposable PostgreSQL cases, plus quality/container gates. Independent
review requested one MEDIUM exact-destination coverage correction and one LOW repeated-hashing
correction. Both are locally implemented; fresh validation passed 355 focused and 2,212 full
tests (201 PostgreSQL, no skips), plus quality/container gates. The same reviewer confirms both
findings resolved after 94 independent diagnostics and returned REVIEW_PASS with zero unresolved
introduced findings. Reviewed implementation commit `28b9bb4af17577993951761e7db73c64430fa765`
merged through reviewed final head `cfd8d0b28f0d2b44012a71c8f31a214710b55803` in
[pull request #38](https://github.com/jnc247s/cloud-security-automation/pull/38).
Both final-head CI runs and [merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36938144756)
passed; main ran all 2,212 tests with 20 existing warnings and no skips, plus quality/image gates.
The [acceptance checkpoint](docs/exec-plans/completed/sprint-6.md#6f2-acceptance-and-6g-start--2026-10-01)
records the exact merge and evidence. 6G started from that clean accepted main on
`codex/sprint-6g-required-tags`; it implements only the approved GOV-001 policy and narrow
category migration. Subsequent accepted 6H and the documentary closure below finish Sprint 6;
later-sprint implementation remains unstarted.

Accepted 6H passed 138 focused / 2,533 full tests, including 252 disposable PostgreSQL cases,
no skips and all quality/container gates. The single authorized reviewer returned exact-head
REVIEW_PASS for `7d80c57b21a62672a4404bd2af4d077d3990ec52`, with both LOW documentary findings
corrected and zero unresolved findings at every severity. Both final-head CI runs passed;
[PR #40](https://github.com/jnc247s/cloud-security-automation/pull/40) merged that reviewed head
at `19c4cd10d0e22ca526fb9a6e94af967cc8ff0a97`, with verified accepted-base/reviewed-head parents.
[Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36954205010)
passed all 2,533 tests in 522.00 seconds, 20 existing warnings, no skips, Ruff, formatting and
image build. This subsequent documentation-only closure archives the execution plan, preserves
its predictions/implemented differences, marks Sprint 6 COMPLETE and promotes Sprint 7 NEXT.
No application, migration, policy, permission, deployment or later-sprint implementation change.
See
[6H acceptance](docs/controls/sprint-6h-acceptance.md).

## Completed: Sprint 5 — AWS Evidence Expansion

Sprint 5 collects the normalized evidence needed by the Sprint 6 production control library; it
does not implement those controls. Approved roadmap scope includes EC2 and EBS facts, VPC/network
facts, IAM account and policy evidence, IAM Access Analyzer evidence where available, expanded S3
and CloudTrail facts, explicit global-versus-regional execution scope, and resource relationships.

The approved requirements and closeout evidence are preserved in
[the completed Sprint 5 plan](docs/exec-plans/completed/sprint-5.md). Its analysis-only
preflight and reviewable execution sequence are complete. The shared 5G
relationship/source-outcome evidence foundation passed its acceptance gate as
`FOUNDATION_READY_FOR_5A`; 5A was accepted and merged in pull request 16, 5B in pull request 17,
5C in pull request 18, and 5D in pull request 20. Slice 5E was accepted and merged in pull request
22 with only the approved direct S3 and referenced-KMS facts, source outcomes, provenance, and
resource relationships while preserving accepted pending-scan, Access Analyzer, and `S3-900`
behavior. The merged 5F preflight records the immutable scan intent, CloudTrail
ownership/admission, account-coverage, source, and relationship contracts. The bounded fact-only
implementation passed its acceptance gates and was merged in pull request 24 without adding a
Sprint 6 rule. The 5G closure adds deterministic operation/query-count gates and behavior-preserving
in-memory indexes, accepted and merged in pull request 25. Merged-main CI passed all 1,396 tests,
including the 20 PostgreSQL integration tests and the authoritative HTTP acceptance, plus Ruff
and the API image build. Independent review has no unresolved findings.

Sprint 5 Phase 0 completed on 2026-09-15 against `main` commit
`feb0b5c2b517f51dd6c7b48eb38513cf92306164` with result `SPRINT_5_GO`. The first approved
implementation slice was the 5G relationship/source-outcome persistence foundation documented in
the then-active plan, followed by 5A through 5F and the 5G closure. That gate made Sprint 5 ready
to start; the subsequently approved foundation implementation began and moved the sprint to
`IN PROGRESS`.

The shared foundation gate completed on 2026-09-15 at migration head `20260915_0003`. Domain,
migration, PostgreSQL, authenticated API, full-regression, lint, format, container, and independent
review gates passed with no remaining review findings. The separately authorized 5A slice passed
its acceptance gates and was merged on 2026-09-16. Slice 5B subsequently passed its acceptance
gates and was merged in pull request 17 at `66cadb20cd6a469d5a656628c27ae8cb569d8c69`.
Slice 5C subsequently passed its acceptance gates and was merged in pull request 18 at
`819f9ba3b26490ca23c69a6665b1baf9d7948975`. Slice 5D was merged in pull request 20 at
`1a355107eb7a3ed7845fa3a569dbff80da2778bb`, and the merged-main CI quality job succeeded. The
bounded 5E implementation was accepted and merged in pull request 22 at
`8ea9df86f8c6ae623ef41ebb836e6b3b7d052393`, with green pull-request CI. The bounded 5F preflight
was merged into `main` at `349f57ebe8fb8ad6c4e4e6e01a8d6262394f8805`. Slice 5F subsequently
passed its acceptance gates and was merged in pull request 24 at
`29aeea59b9cceff957adac4fba75cb8ca2c4a592`. The bounded 5G closure was accepted and merged in
pull request 25 at `ef4543d439ed3a33064c6bcf383db201a94d2881`. This post-merge closeout marks
Sprint 5 `COMPLETE`, archives its execution plan, and promotes Sprint 6 to `NEXT`. Migration head
remains `20260915_0003`.

## Completed: Sprint 6 — Production Security Controls

Sprint 6 slice 6A was authorized on 2026-09-24. The 25-control evidence matrix is `CURRENT`;
evidence readiness does not enable new rules or decide deferred Sprint 6 policy. The preceding
Sprint 5 closeout did not implement Sprint 6; the subsequent approved 6A work is tracked below.

The subsequent [Sprint 6 execution plan](docs/exec-plans/completed/sprint-6.md) records the
merged starting checkpoint, proposed implementation slices, compatibility work, and policy
approval gates. Slice 6A is `COMPLETE`, merged in PR #27 at
`1900dd4fd0968de5c130a65265ce2c8670a51a09`; merged-main CI succeeded. This checkpoint was
verified on 2026-09-27 and supersedes the earlier 6A pending-merge notes. Migration head is
`20260924_0004`.

The user requested 6B.1 implementation and approved its 90-day unused-key policy and severities
on 2026-09-27, then approved the remaining [control metadata](docs/controls/sprint-6b1-metadata.md).
6B.1 and 6B.2 are `COMPLETE`: PR #29 merged the policy slice into the credential/root branch,
then PR #28 merged both into main at `42cc65366ed4d6e1fe14aa28e2650a62280cba8b`.
Whole-6B independent review passed; final branch CI and merged-main CI passed. This acceptance
was verified on 2026-09-28. Migration head remains `20260924_0004`.

The user approved 6C implementation and its bounded metadata/UUID allowlist decisions on
2026-09-28. See [6C metadata](docs/controls/sprint-6c-metadata.md) and the completed plan.
6C is COMPLETE: PR #30 merged at `c7d85e2a36a8e8aa0bc044a9fc22b7ea8cdbf01c` and
merged-main CI passed. Its independent review has no unresolved findings.

6D.1 (NET-003/004/005) and 6D.2 (NET-006) are COMPLETE. PR #32 merged both implementation
commits at `9ad7feab10d8f87f91d878920c6cf40a5d6fe51b`, superseding the proposed two-PR merge
sequence. Combined independent review passed with zero findings; final branch CI and
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36532277234)
passed. Acceptance was verified on 2026-09-29.

The user requested 6E implementation on 2026-09-29 and approved the 6E.1 policy direction:
effective combined account/bucket Block Public Access and a bounded explicit secure-transport
Deny evaluator. See the [6E preflight](docs/controls/sprint-6e-preflight.md) and
[6E.1 approved metadata](docs/controls/sprint-6e1-metadata.md). The user subsequently approved
that metadata; S3-001 and S3-003 are accepted in opt-in `0.8.0`. The authorized
migration-comparison repair resolved the baseline failures:
all 1,790 tests pass, including 88 PostgreSQL cases, and independent review has zero findings.
PR #33 subsequently merged 6E.1 and its preparation handoff at
`4b3d7355dafe6eceab50214ee2281b0b4f96fa81`; merged-main CI passed. The user directed 6E.2
implementation with the prepared policy/metadata bundle. This does not complete all of 6E;
The separate 6E.3 classifier/encryption bundle was approved on 2026-09-30 and accepted through
PR #35 at `c861713a665669da09d5bc7b5b282b04c16cac1d`; merged-main CI passed. S3-004 is
available in opt-in catalog `0.10.0`, while default `0.2.1` remains unchanged. Slices 6A through
6E are COMPLETE. 6F preparation is recorded in the
[preflight](docs/controls/sprint-6f-preflight.md) and completed plan. The user's implementation request
initially authorized the prepared 6F.1 bundle only; 6F.1 is now COMPLETE through PR #37 and
green merged-main CI. 6F.2 is subsequently COMPLETE through PR #38 and green merged-main CI.
The remaining-Sprint-6 approval covered accepted 6G and 6H acceptance/closeout. Accepted migration
head is `20261001_0006`; 6H added no migration or application behavior. The completed plan records
whole-sprint acceptance and the post-merge documentary closure. Later-sprint work was unstarted
at that closeout; the subsequent approved 7A start is recorded below.

## In progress: Sprint 7 — Dashboard / NIST Technical Posture

Sprint 7 is IN PROGRESS. The 7A reporting foundation and 7B authenticated shell are COMPLETE. The user
requested its analysis-only preflight on 2026-10-02.
The [preflight](docs/sprint-7-preflight.md) is complete and the
[execution plan](docs/exec-plans/active/sprint-7.md) records 7A approval and later proposed slices.
Analysis started from
clean current main `bafa0783d347ef8b6c5e1182d4c2dd86119b412d` (accepted documentary closeout /
PR #41), whose merged-main CI passed. The user's subsequent "Confirm" approves the proposed
exact-scan READ reporting contract and authorizes 7A implementation, including counts, explicit
coverage and historical provenance without a compliance score. The scoped feature branch is
`codex/sprint-7a-reporting`; the existing preflight documentation is preserved.
Browser authentication/toolchain approval is a separate gate before 7B UI work.
The user's smaller goal is limited to 7A and then 7B, with required slice validation and
acceptance gates. The 7A authorization resolves the earlier implementation-approval blocker;
7C through 7E and later sprints remain outside the goal. No reviewer agent, commit, push, PR,
merge or production operation is authorized by this confirmation. Future dashboard consumers
must use the accepted generic services/API and preserve technical results, immutable evidence,
finding/exception separation and limited NIST reporting claims. No Sprint 7 implementation or
new infrastructure was added during Sprint 6 closeout.

7A is COMPLETE: 182 focused checks and 2,601
full regression tests passed (277 PostgreSQL cases, no skips, 20 existing warnings), plus Ruff,
348-file formatting, documentation links, whitespace, Compose, image build and isolated image
import/OpenAPI smoke checks. Migration remains `20261001_0006`; default catalog/profile and
accepted assessment/authentication behavior are unchanged. The subsequently authorized single
read-only reviewer returned REVIEW_PASS with zero unresolved findings after 157 independent
checks and three additional diagnostics. The same reviewer verified the documentation delta
and exact final head `333aefdd9032057ad49701271030e0047ce99601` with zero unresolved findings.
The user's scoped publication approval produced [PR #42](https://github.com/jnc247s/cloud-security-automation/pull/42);
the repository owner subsequently merged it manually on 2026-10-03 at
`bd639f48095ef63e658abd284ce25c927998c0fb`. Both exact-head CI runs and
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37161516904)
passed; main ran all 2,601 tests with 20 existing warnings and no skips, plus quality/image gates.
No agent merge or auto-merge was performed. The active plan preserves earlier approval limits
and the superseding acceptance record.

The user subsequently requested a 7B completion goal and confirmed continuing the existing
7A/7B goal, starting with 7A documentary closeout and the 7B design prerequisites. This authorizes
local reconciliation and analysis-only [7B preparation](docs/sprint-7b-preflight.md), not a selected
browser architecture or 7B implementation. 7B still requires UI/toolchain/browser-auth decisions
and an implementation request. Reviewer agents, publication, merges and production/IdP changes
for this new work need separate authorization. 7B and all later implementation remain unstarted.

The subsequent user confirmations approve React/TypeScript/Vite, the documented same-origin
BFF/session design and 7B implementation, with Cognito User Pools Essentials as the target IdP
and a controlled local issuer for automated tests. This supersedes the preparation-only gate
above for 7B, not for independent review, publication, merging or live IdP/AWS/production changes.
Implementation reuses the preserved worktree on `codex/sprint-7b-authenticated-shell`, from
accepted main `bd639f48095ef63e658abd284ce25c927998c0fb`. Existing documentary work is retained.
7B is not accepted until its required validation, independent review and merge gates succeed.
No 7C, 7D, 7E or later-sprint implementation is authorized.

Local 7B implementation and validation are now complete, not accepted: 195 focused checks,
2,666 regression tests (277 PostgreSQL cases included, no skips), seven frontend units and
12 Chromium/Firefox journeys passed, plus frontend build/type/lint, Ruff/format, documentation
links, whitespace, Compose, multi-stage image and isolated disabled/enabled runtime smoke.
The [implementation checkpoint](docs/exec-plans/active/sprint-7.md#7b-implementation-checkpoint--2026-10-03)
records exact commands, limits and differences. 7B remains IN PROGRESS; independent review has
not been authorized or launched, and all changes are uncommitted/unpublished. Production Cognito
registration is not validated. Required review, publication and merge gates remain outstanding;
the goal is unfinished and later slices remain unstarted.

On 2026-10-04 the user's "Yes" authorizes one read-only independent reviewer for 7B. The
earlier unapproved-review checkpoint above remains historical; review is now authorized.
The initial review returned REVIEW_CHANGES_REQUIRED (two MEDIUM, one LOW); local focused
repairs address safe malformed-input/error handling, cross-tab session binding/invalidation,
and exact enum/count validation. Fresh complete validation and the same reviewer's follow-up
remain required. This does not authorize additional reviewers, commit, push, PR, merge,
live IdP/AWS/secret or production operations. 7B remains IN PROGRESS and unpublished.

Post-review closeout on 2026-10-04: all three findings are resolved and the same reviewer returned
REVIEW_PASS with zero unresolved findings. Fresh final validation passed 205 focused checks,
2,676 regression tests (277 PostgreSQL cases, no skips), 15 frontend units and 14 Chromium/Firefox
journeys, plus quality/build/Compose/image and isolated disabled/enabled/error-path runtime smoke.
The [post-review checkpoint](docs/exec-plans/active/sprint-7.md#7b-post-review-validation-and-independent-closeout--2026-10-04)
records exact commands, independent checks, immutable input fingerprints and limits.
Final documentary verification and separate commit/push/PR authority, exact-head review/CI,
required human merge and merged-main CI remain gates. 7B is not COMPLETE; live Cognito and
production setup are not validated, all changes remain uncommitted/unpublished, and 7C+ is unstarted.

The final documentary review also passed with zero unresolved findings, 82 fresh independent
contract/link checks and unchanged implementation hashes. The user's subsequent "Yes" authorizes
a scoped 7B commit, branch push and PR creation, not merge/auto-merge or live/later-sprint work.
The [publication authorization](docs/exec-plans/active/sprint-7.md#7b-final-documentary-review-and-publication-authorization--2026-10-04)
records verified exact inputs, GitHub identity/current main and preservation boundaries. Publication,
exact-head review/CI, required human merge and merged-main CI remain pending at that checkpoint;
7B stays IN PROGRESS, and no commit/push/PR or acceptance is claimed yet.

Publication checkpoint on 2026-10-04: the scoped 7B implementation is committed at
`ff2088be98928fdf87ca0bc9216c722e71713ec2`, pushed to
`codex/sprint-7b-authenticated-shell`, and open in
[PR #43](https://github.com/jnc247s/cloud-security-automation/pull/43). The same independent
reviewer returned exact-commit REVIEW_PASS with zero unresolved findings and verified all
56 committed blobs match the reviewed files. Both exact-head GitHub CI runs are in progress
at this checkpoint. [Publication detail](docs/exec-plans/active/sprint-7.md#7b-publication-checkpoint--2026-10-04)
records the unchanged implementation, preservation checks and remaining gates. 7B remains
IN PROGRESS: merge/auto-merge is not authorized or performed, live Cognito is unvalidated,
and required human merge approval and green merged-main CI remain outstanding. 7C+ is unstarted.

The subsequent user confirmation authorizes merging PR #43 after green exact-head CI.
Both final-head runs passed, the independently reviewed inputs remained unchanged, and
[PR #43](https://github.com/jnc247s/cloud-security-automation/pull/43) merged at
`9ace4e65f15be678d3f05c4b5ef3a9896d4ea187`. The
[merge checkpoint](docs/exec-plans/active/sprint-7.md#7b-merge-authorization-and-main-ci--2026-10-04)
records exact review, ancestry and tree identity. Merged-main CI is running; 7B remains
IN PROGRESS pending acceptance. This approval is for PR #43 only, not other publication/merges,
live operations or later slices. No 7C+ work started.

7B is COMPLETE: both final-head CI runs and
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37189473834)
passed after the explicit merge approval. Main ran all 2,676 tests, including 277 PostgreSQL
cases, no skips and 19 existing warnings, plus 15 frontend units, 14 Chromium/Firefox journeys
and all quality/image gates. The same reviewer's exact-head REVIEW_PASS had zero unresolved
findings. The [acceptance checkpoint](docs/exec-plans/active/sprint-7.md#7b-acceptance-and-scoped-goal-boundary--2026-10-04)
records the exact merge, CI and unchanged behavior. The local closeout updates current owners
and their documentation-status guard; its separate publication approval is pending. Sprint 7
remains IN PROGRESS, its plan stays active, and 7C/7D/7E and later implementation remain unstarted.
Live Cognito/MFA/TLS and production setup are not validated or authorized.

The user's subsequent 2026-10-04 request establishes a new ACTIVE goal: preflight, implement,
review, publish and merge 7C; repeat for 7D; then review the whole Sprint 7 for correctness
and complete 7E acceptance/documentary closeout. The
[goal-setup checkpoint](docs/exec-plans/active/sprint-7.md#remaining-sprint-7-goal-setup--2026-10-04)
records sequential exact-head review/CI/merge and merged-main CI gates, preserved 7B closeout
work, and stop conditions for material choices or missing authority. The separate pending 7B
closeout publication and one read-only reviewer agent per new review await explicit confirmation.
Goal creation does not complete the prior closeout or advance slice status: Sprint 7 remains
IN PROGRESS, 7C/7D/7E remain PLANNED, and no new implementation, reviewer or publication started.
No live IdP/AWS/IAM/secret/production operation, parallel implementation or Sprint 8 is authorized.

The subsequent "Yes merge" confirms the pending bundle: publish and conditionally merge the
reviewed 7B documentary closeout, one read-only reviewer agent per 7C/7D/final Sprint 7 review,
and the proposed exact-scan history filter/server UTC exception-reference-time metadata.
The [approval checkpoint](docs/exec-plans/active/sprint-7.md#7b-closeout-publication-approval-and-remaining-scope--2026-10-04)
records fresh GitHub/main verification and exact-input review/CI/merge gates. The 7B closeout
is still local at this checkpoint. 7C has an analysis-only preflight, not code; 7D and 7E
have only the full-sprint scope/dependency proposal and remain unpreflighted separately.
No slice status advances through permission alone. Live operations and later sprints remain excluded.

## Pre-Sprint 5 attention

These accepted-baseline limitations were discovered during the governance audit. This register
records both reviewed repairs and remaining items that must be triaged before or explicitly within
an approved Sprint 5 plan:

- **RESOLVED — populated downgrade safety:** the accepted `20260904_0002` migration remains
  unchanged. Alembic now preflights any downgrade across it, blocks before DDL when retained scans
  cannot satisfy the older `NOT NULL` contract, and excludes concurrent PostgreSQL writers while
  checking and transitioning compatible data.
- **RESOLVED — assessment-profile versioning:** `ASSESSMENT_PROFILE_VERSION` explicitly selects a
  numeric immutable profile version for new scans. Changed content under an existing version is
  rejected with a sanitized conflict; a reviewed new version coexists with historical versions.
  Pending and recovered scans load their exact persisted profile instead of current deployment
  policy. The established schema already supports this roll-forward, so no migration was added.
- **RESOLVED — acceptance coverage:** the PostgreSQL integration suite now drives authenticated
  HTTP scan creation through deterministic fake AWS collection, real execution and persistence,
  and the principal read APIs. At the time of this repair, Sprint 5 remained `NEXT` and had not
  begun.
- **RESOLVED — collector failure contract:** existing Sprint 1 collectors now validate required
  identities, promoted nested evidence, pages, tags, permissions, and duplicate stable resources.
  Operational AWS failures remain `FAILED`, malformed evidence becomes sanitized `PARTIAL`, and
  programming defects remain visible. This repair added no Sprint 5 evidence and was completed
  before Sprint 5 began.
- **MEDIUM — audit principal context:** scan-start audit records retain the authenticated subject,
  but not issuer, roles, or the authorizing capability.
- **MEDIUM — authorization scope:** authenticated readers can query every account in this
  control-plane database. The current deployment model is one trusted security domain, not
  tenant-isolated SaaS.
- **LOW — stable ARN presentation:** stable resource identity retains the first-seen ARN while
  snapshots retain observed ARNs. For resources whose ARN can change, the top-level resource view
  can differ from its latest snapshot.

See `docs/operations/known-limitations.md` and `THREAT_MODEL.md` for operational and security
detail.

## Status vocabulary

- `COMPLETE`: accepted implementation, full regression, required integration/security and
  acceptance validation, independent review, current documentation, and required merge approval
  are complete.
- `IN PROGRESS`: implementation is actively underway on an approved plan.
- `NEXT`: the next approved roadmap outcome; implementation has not begun.
- `PLANNED`: future committed v1 work.
- `DEFERRED`: explicitly outside the committed v1 sequence.

Normally at most one sprint is `IN PROGRESS`, exactly one future sprint is `NEXT`, and all later
work is `PLANNED` or `DEFERRED`.

## Transition protocol

At sprint start:

1. confirm this roadmap and `docs/exec-plans/active/` agree;
2. complete the analysis-only preflight and approve the execution plan;
3. create a feature branch from clean, current `main`; and
4. change the sprint from `NEXT` to `IN PROGRESS`.

Sub-sprint state may be recorded inside an active plan as `COMPLETE`, `IN PROGRESS`, or `PLANNED`,
without prematurely completing the parent sprint.

At sprint completion, require all of:

1. implementation complete;
2. targeted tests pass;
3. the complete regression suite passes;
4. lint and formatting pass;
5. relevant collector, database, migration, and integration tests pass;
6. relevant live/mock AWS validation passes safely;
7. independent correctness, security, and data-integrity review is complete;
8. all `CRITICAL` and `HIGH` findings are resolved;
9. the sprint acceptance test passes;
10. documentation is current; and
11. required merge approval and merge are complete.

Then mark the sprint `COMPLETE`, promote the following sprint from `PLANNED` to `NEXT`, and move
the execution plan from `active/` to `completed/`, retaining implemented differences.

## Protected completed-sprint contracts

- Sprint 0: startup, health/readiness, local Docker, CI, and test foundation.
- Sprint 1: standard AWS credential chain, read-only client/session layer, inventory service, and
  fact-only collectors.
- Sprint 2: deterministic, side-effect-free technical rule evaluation.
- Sprint 2.1: four-state assessments, structured evidence, versioned profiles/control contracts,
  and framework-mapping semantics.
- Sprint 3: stable resources versus immutable snapshots, historical evidence and assessments,
  finding/exception/audit integrity, and Alembic migration history.
- Sprint 4: services, OIDC/development authentication, capability authorization, versioned API
  schemas, durable scan identities, and replaceable non-blocking execution.

Changing these contracts requires the interface-change and full-regression protocol in
`AGENTS.md`.
