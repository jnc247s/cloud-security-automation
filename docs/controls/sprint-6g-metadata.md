# Sprint 6G required-tag control

Sprint state belongs to [ROADMAP.md](../../ROADMAP.md). The
[active plan](../exec-plans/active/sprint-6.md) records the user's 2026-10-01 approval.
6G is IN PROGRESS; GOV-001 is registered locally but not yet accepted or published.

## Approved policy and claim

The initial immutable, opt-in profile requires the exact, case-sensitive keys `Owner` and
`Environment`, each with a string value containing a non-whitespace character. Original case
and whitespace are preserved. AWS-reserved `aws:` keys cannot satisfy a required tag.
The governed selectors are `ec2_instance`, `ebs_volume`, `vpc`, `subnet`, `security_group`,
`vpc_flow_log`, `s3_bucket`, `iam_user`, `iam_role`, `iam_customer_managed_policy`, and
`cloudtrail_trail`. Existing schema-2 profile fields are reused; no deployed profile or operator
policy is overwritten and default catalog `0.2.1` remains unchanged.
The [initial opt-in profile example](examples/sprint-6g-initial-profile.json) retains these
approved inputs under separate identity `sprint-6g-initial/1.0.0`, checksum
`90a65ea73748f02742bc7cde8684264b8999d8a562ce87729478138db6caf9a5`. It enables only GOV-001;
it is not installed or selected by default. Operator changes require new immutable versions.

| Evidence and applicability | Result |
| --- | --- |
| Governed target, complete usable required tags | PASS |
| Governed target, complete tags but a required key/value is missing or unusable | FAIL |
| Governed target, unavailable, incomplete or malformed required source | INSUFFICIENT_EVIDENCE |
| Observed ungoverned target, or proven complete empty governed population | NOT_APPLICABLE |

The control assesses tag configuration only. It does not establish ownership truth,
authorization, CMDB accuracy, effective governance or compliance. Guidance is for an authorized
operator; collection and assessment remain read-only. Local execution uses exact same-scan
discovery, identity and tag sources, with shared engine/persistence recomputation and atomic
rejection of forged evidence, results and policy bindings.

Local metadata is MEDIUM severity, additive `governance` category, evaluator `1.0.0`, opt-in
catalog `0.13.0`, closed execution proof `1.10.0`, and NIST subset `2.0+subset.12`.
ID.AM-02 is limited reporting context: owner/environment
tags contribute context to maintained inventories, not proof of the whole outcome. The source
is [NIST CSWP 29](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf), Appendix A, printed
page 18 (PDF page index 22), inspected 2026-10-01. The separately checksummed subset artifact
has SHA-256 `fd3cd6448531d44c73b86781dfd84736fa20726e88360463ac8767ef588c1d2e`;
every earlier artifact's bytes are preserved. Framework mapping never determines a result.

## Closed proof and compatibility

The full profile-governed population is proved from every governed family's complete exact
discovery source before an observed governed target can pass or fail. A failed family's
enumeration cannot disappear behind successful targets of another family. Identity/tag enrichment
is conditional on the exact target family. Ungoverned observed targets are N/A without requiring
unrelated sources. The initial vocabulary excludes IAM groups, AWS-managed policies, keys and
setting observations; those do not acquire invented tags or resource assessments.

New closed target selector `governance_tags_v1` preserves all observed canonical targets and,
when none is profile-governed, additionally requires the existing global `iam/aws_account`
assessment-only target. Its exact discovery proof distinguishes complete empty N/A from missing
or unavailable governed coverage INSUFFICIENT_EVIDENCE, even alongside ungoverned N/A targets.
Engine and persistence enforce the same profile-bound matrix. Historical target selectors and
serialized execution definitions remain unchanged.

An empty population uses the existing global `iam/aws_account` assessment-only target namespace,
not a new collected resource, service or graph endpoint. This reuses accepted scope validation
without adding a synthetic service or exempting it from scope checks. GOV-001 remains a
cross-service control through its exact 11-family contract, not an IAM-only assessment.

Each operation-local reader seals only its private revalidated resource JSON and indexes families
once. Complete governed-population validation, source serialization and sanitized failures are
cached per exact closed contract and freshly checked profile checksum; target admission/tag
sources are still checked independently. Indexed membership avoids repeated family scans.
Caller-owned resources and old proof readers are unchanged; copied citations cannot alter cached
proofs. Deterministic engine/SQLite/PostgreSQL operation-count tests cover 1/2/4/8/16 instances.

The accepted assessment evidence envelope trims nested strings. Rather than changing historical
evidence semantics, new proof `governance.tags` stores lossless canonical UTF-8 hex pairs:
`key_utf8_hex` and `value_utf8_hex`. Original strings remain unchanged in cited normalized source
artifacts and resource snapshots. The shared pure result computation decodes those exact strings;
strict proof recomputation rejects altered tags, numeric/boolean substitutions, IDs, digests,
policy bindings and applicability. This is an encoding, not encryption or redaction; tag evidence
remains sensitive. No established API fields, constructors, collector or permission changes.

## Local additive category migration checkpoint

The implementation adds only public category value `governance` and migration
`20261001_0006`, following accepted `20261001_0005`. Only the named control-version category
CHECK changes. Existing category values, generic APIs, historical rows, schema-2 profiles,
earlier catalogs and old migrations are unchanged.

PostgreSQL replaces the CHECK transactionally. Online pre-DDL downgrade guards serialize with
control-version writers and reject any governance category that the predecessor cannot retain.
Offline downgrades crossing this boundary are rejected.

SQLite retains foreign-key enforcement, reserves the writer, uses a savepoint for the parent
table swap, preserves exact triggers, and checks all foreign keys before clearing the temporary
deferred-violation counter. It restores the caller's defer flag and never commits a caller-owned
transaction. Unsafe incoming delete actions and existing broken foreign keys are rejected before
DDL. A failed swap rolls itself back even if the caller catches the error and commits afterward.
The design follows SQLite's [foreign-key](https://www.sqlite.org/foreignkeys.html) and
[deferred-check](https://www.sqlite.org/pragma.html#pragma_defer_foreign_keys) documentation and
was checked with an isolated in-memory reproduction; it does not disable foreign keys.

The initial pre-review validation passed **362 focused / 2,443 full tests**, including **226 disposable PostgreSQL
cases**, no skips and 20 existing full-suite warnings. Ruff, 335-file formatting, documentation
links, whitespace, Compose and image build passed. Real bearer-authenticated HTTP ran on SQLite
and PostgreSQL with only AWS offline. See the exact command scope/fingerprint in the
[validation checkpoint](../exec-plans/active/sprint-6.md#6g-validation-checkpoint--2026-10-01).
Independent review requested one MEDIUM subset-population correction and two LOW performance /
documentation corrections. The same reviewer verified all resolved, zero new findings, after
274 independent checks plus combined all-26-control and constant-work diagnostics. Fresh
post-correction validation passed **410 focused / 2,491 full tests**, including **238 disposable
PostgreSQL cases**, no skips and 20 existing warnings; all quality/container gates passed.
See the [post-review gate checkpoint](../exec-plans/active/sprint-6.md#6g-post-review-validation-checkpoint--2026-10-01).
Final committed-head reviewer approval and publication remain pending. The
[commit checkpoint](../exec-plans/active/sprint-6.md#6g-commit-checkpoint--2026-10-01) records the
scoped implementation commit; 6G is not accepted. Earlier initial gate outcomes remain recorded
in the active plan.
