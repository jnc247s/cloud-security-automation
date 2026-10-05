# Sprint 7C investigation preflight

Current authority: the user's subsequent "Yes merge" confirms the proposed exact-scan resource
history filter and server UTC exception-reference-time metadata, 7B closeout publication/guarded
merge and one read-only independent reviewer agent per 7C, 7D and final Sprint 7 review.
The [active plan](exec-plans/active/sprint-7.md) records the superseding approval and PR #44's
documentary closeout merge. The original analysis and its then-pending gates below remain
historical. The subsequent "Complete 7c" request completed the approved implementation/review/
publication/merge/main-CI sequence through PR #45/46. 7C is COMPLETE. The subsequent
[7D preflight and acceptance](sprint-7d-preflight.md) records completion of the approved
client-only slice through PR #48 and green merged-main CI. 7D is COMPLETE; 7E remains PLANNED and still
needs its separate preflight. The historical analysis body below is unchanged.
That prerequisite CI has now passed for exact main `f14d861`; the
[handoff checkpoint](exec-plans/active/sprint-7.md#7b-closeout-main-ci-and-remaining-sprint-7-handoff--2026-10-04)
records prerequisite acceptance. The acceptance note below supersedes earlier planned/pending states.

Prepared: 2026-10-04. Analysis only for the requested sequential remaining-Sprint-7 goal.
The accepted APIs provide assessment, evidence and operational facts, but two proposed additive
read contracts need confirmation before implementation: an exact-scan resource-history filter
and a server reference time for operational exception display. No 7C application change,
reviewer launch or publication has occurred.

[ROADMAP.md](../ROADMAP.md) owns progress; the [active plan](exec-plans/active/sprint-7.md)
records authority. 7A/7B are COMPLETE, Sprint 7 is IN PROGRESS, and 7C/7D/7E remain PLANNED.
The separate uncommitted 7B acceptance record still awaits publication/merge approval, as does
one read-only independent reviewer agent for each new slice and final Sprint 7 review.
This preflight is separate from that existing closeout and must not be silently included in a
7B-only commit. Preserve all existing changes and unrelated parent skills.

## Inspected baseline and contracts

Local branch is `codex/sprint-7b-authenticated-shell`, HEAD
`f7e842c2c2075b280c3046ee65a3ee5463130d81`, with the preserved 12-file acceptance/goal delta.
The owners record accepted main at `9ace4e65f15be678d3f05c4b5ef3a9896d4ea187` through PR #43.
No new fetch or remote acceptance is claimed by this analysis. Defaults stay catalog `0.2.1`,
profile `default/1.0.0`, latest opt-in `0.13.0` and migration `20261001_0006`.

Inspected sources include [AGENTS.md](../AGENTS.md), [product requirements](../PRODUCT_REQUIREMENTS.md),
[architecture](../ARCHITECTURE.md), [security](../SECURITY.md), browser/history threats in
[THREAT_MODEL.md](../THREAT_MODEL.md), the active plan, [Sprint 7 preflight](sprint-7-preflight.md),
[API](api.md), [assessment semantics](assessment-framework.md), framework claim boundaries in
[NIST context](frameworks/nist-csf-2.0.md), the READ routes, projections, services and resource model.

| Investigation need | Inspected accepted contract | Required behavior |
| --- | --- | --- |
| Assessment table and detail | AssessmentService and assessment routes support scan/resource/control/result filters, four states and exact evidence/version/finding IDs | Always filter technical rows by selected scan; load detail on demand and validate returned IDs |
| Exact configuration | ResourceService history returns paged immutable snapshots; resource detail returns latest_snapshot | Match scan_id, resource_id and resource_snapshot_id; never substitute latest or first-seen ARN |
| Current findings | FindingService list supports account/resource/control/status/Region; detail includes occurrences and exceptions | Label current handling separately; finding occurrence IDs associate a historical failure, not current status at scan time |
| Time-aware exceptions | ExceptionService list has stored status, creation/expiry/revocation times; finding projections compute active IDs using server wall time | Stored ACTIVE alone is insufficient; reference time and freshness must be explicit, never change technical FAIL |
| Source proofs and artifacts | EvidenceGraphService and source-outcome list/detail expose exact scan, subject, provenance and digest-bound normalized payload | Only typed citations become links; verify fetched scan/subject/artifact identity and show unsupported proofs without guessing |
| Directional relationships | Relationship list/detail exposes observation ID, source-outcome ID, direction, resolution and complete or incomplete endpoints | Keep unresolved references as references; do not invent resources, reverse edges or arbitrary traversal |
| Browser boundary | Dashboard.read re-enters the bearer API with per-user token, origin/session-context checks and final expiry/logout guard | Extend an explicit GET allowlist, not a generic proxy; no direct service/database read or writer |

Relevant implementation is in [API views](../app/schemas/api_views.py),
[projections](../app/services/projections.py), [resource service](../app/services/resource_service.py),
[resource model](../app/models/resource.py), [dashboard routes](../app/dashboard/routes.py),
[ScanShell](../frontend/src/ScanShell.tsx) and [client validators](../frontend/src/api.ts).
No nested AGENTS.md was found in the inspected repository source paths.

## Proposed read contract decisions

Resource history currently accepts only limit/offset. Locating an old assessment's snapshot may
require fetching unrelated newer history; a first-page/latest fallback would be incorrect.
Recommend an optional UUID `scan_id` filter on the existing
`GET /api/v1/resources/{resource_id}/history` route and matching generic service method.
Omitting it must preserve existing ordering, pagination, response schema and not-found behavior.
With it, use the existing unique `(scan_id, resource_id)` constraint to select at most one
snapshot, then validate its snapshot UUID against the assessment or resolved relationship.
No migration is presently justified. Test callers with and without the optional filter on
SQLite and disposable PostgreSQL; prove bounded query counts and representative index use.
This is a proposed additive interface change, not an already accepted filter.

Recommend a server UTC reference-time header on the new operational dashboard reads, captured
when producing the successful response. Preserve the upstream API body/status and existing API
fields. A proposed name is `X-Dashboard-Read-At`; it is metadata, never authentication.
The UI can display stored status and eligibility at that reference time using explicit creation,
expiry and revocation fields, while labeling the data as a retrieved current view, not a
historical exception snapshot or a transactionally frozen mixed report. At the expiry boundary,
`expires_at <= reference_time` is expired; invalid/missing times must not yield an active badge.
Client wall-clock time must not establish eligibility. If the reference time is absent or
unsupported, display raw stored status with eligibility unavailable. Refresh re-reads mutable
facts; this proposal does not add an expiry scheduler, mutate records or rewrite assessment states.
Existing finding active_exception_ids are server-computed, but do not include their computation
time; they are not sufficient to claim perpetual or scan-time exception coverage.

Both proposals require explicit confirmation because they extend accepted interfaces. Their
implementation must update the API/security/architecture owners, all affected callers and tests
atomically. BFF expansion for assessments, exact resource history, findings/exceptions, outcomes
and relationships must retain typed UUID/enum/bounded-page inputs, reject duplicate/unknown
parameters and prohibit client-selected upstream URLs/headers/methods.

## Proposed investigation flow

Extend the accepted shell under an explicit selected scan. Add bounded assessment pages and
filters for the four technical states, plus on-demand assessment detail with reason, missing
evidence, control/profile IDs, evidence schema/digests and payloads. A running or unavailable
report never becomes an empty passing table; partial retained facts remain visible with gaps.
Keep missing assessments distinct from NOT_APPLICABLE and INSUFFICIENT_EVIDENCE.

Open the exact assessed snapshot through the proposed filtered history read. Show stable identity
separately from that scan's ARN, tags, configuration, scope, owner and observed time. Resolve
control metadata only by the assessment's control_version_id and selected catalog, never the
first/current version. Account and regional-setting assessment targets must remain distinct from
collector-observed graph resources; missing graph records do not authorize invented endpoints.

Show current findings/exception pages separately, retaining finding/resource/control IDs and
the retrieval reference time. Use direct association from assessment detail when present and
accepted resource/control filters where needed; do not infer finding identity from reason prose
or treat the lack of an occurrence on PASS/N/A as proof no current finding exists.
Operational status and accepted risk never modify historical four-state results.

Provide on-demand source-outcome/artifact and relationship detail alongside bounded scan-filtered
lists. Validate explicit known proof structures before linking source_outcome_id or observation_id.
Legacy evidence may be readable without graph citations. Unknown proof schemas are displayed
as unsupported structured evidence, not interpreted as a current schema or silently hidden.
Fetched artifacts and endpoints must remain bound to the selected scan and exact identity.
Do not add NIST hierarchy views here; retain mapping IDs as existing provenance and leave 7D
implementation until 7C review, merge and merged-main CI have succeeded.

## Security and efficiency constraints

Reuse server-only credentials, real bearer/READ enforcement, opaque cookies, exact origin,
session-context checks, no-store/CSP protections and cross-tab invalidation. Logout, expiry,
identity replacement, scan/assessment changes, back navigation and component unmount must abort
or ignore outstanding reads and clear all previous sensitive detail. Missing/error/provenance
conflict states must not retain a prior record under a new selection.

Render tags, policy text, evidence, reasons and names as text only. Do not execute HTML or follow
URLs embedded in metadata. Do not add Web Storage, service workers, exports, analytics or external
assets. Use accessible disclosure controls and clearly labeled display truncation for large
payloads, with exact IDs/digests retained; truncation is not full evidence review.
No credentials or cloud fixtures belong in logs, screenshots, traces or committed artifacts.

Use on-demand detail rather than per-row detail requests or downloading all history to aggregate.
Existing resource detail hydrates all snapshots, and finding detail returns all occurrences and
exceptions without pagination. Bounded list limits do not bound those detail payloads; do not
claim otherwise. Prefer the filtered snapshot and paged exception reads for this slice. Measure
representative retained histories and fixed page/detail request counts; any necessary new
persistence/index/pagination contract requires separate justified review, not speculative work.
Existing API offset pagination remains mutable, and READ remains one organization-wide trust
domain rather than account/tenant isolation.

## Validation and review gates

Inspected tests include [read service contracts](../tests/unit/services/test_read_services.py),
[read HTTP contracts](../tests/api/test_read_api.py),
[graph service tests](../tests/unit/services/test_evidence_graph_service.py),
[graph API tests](../tests/api/test_evidence_graph_api.py),
[real BFF authentication](../tests/api/test_dashboard_api.py),
[browser journeys](../frontend/e2e/shell.spec.ts), and the controlled-issuer/PostgreSQL browser
fixture. The existing [validation harness](../scripts/validate.py) owns a fresh disposable
loopback PostgreSQL instance and provides frontend/backend/browser/Compose/image gates.

Add tests for exact old snapshots despite newer observations and equal times; wrong scan/resource/
snapshot/version/source/edge IDs; global/regional/external-owner/unresolved/graphless targets;
all technical states; current versus historical findings; ACTIVE-but-expired, revoked and
boundary-time exceptions; malformed timestamps/response schemas; all READ roles and denied proxy
mutations/injection; loading/empty/errors; stale reads/logout/expiry/two tabs; malicious metadata,
large payloads, keyboard/labels/mobile layout and bounded queries/requests.
Browser acceptance must cross real controlled OIDC, BFF, API and disposable PostgreSQL with
AWS offline. Unit-only fixtures or API authentication overrides cannot prove that flow.

Every implementation slice runs targeted tests, Ruff, formatting, full pytest, relevant
PostgreSQL/security checks, frontend type/lint/unit/build and Chromium/Firefox journeys,
Compose and image checks. Independent review must resolve findings on exact final inputs;
publish a scoped PR, merge the exact reviewed head only after green CI, then verify main CI.
No production/live IdP/AWS/IAM/secret, remediation or later-sprint operation is in scope.

Fresh diagnostics for the unchanged accepted services/API/BFF: 65 focused tests passed, no skips
(16.74s). The first run passed 25 but had 40 setup errors from the sandbox's inaccessible shared
pytest temp directory. A unique workspace-temp retry encountered the same Windows private-directory
restriction, including cleanup. A scoped approved unsandboxed rerun with a verified fresh
workspace temp path passed all 65; no test/assertion, permission or application fix was made.
This is preflight evidence, not implementation/full/browser/PostgreSQL acceptance for 7C.

## Outcome and next gate

Conditional readiness: the investigation facts and auth boundary are present. Confirm the two
additive read contracts, prerequisite 7B closeout publication and one reviewer agent per new
review. Then finish that prerequisite and implement 7C on a scoped branch from verified clean,
current main. Until those gates are resolved, stop before code changes, publication or new agents.
This document does not advance canonical slice status or authorize 7D/7E early.

## Approved implementation preparation

After PR #44's exact-head review and green final-head CI, the parent merged it normally at
`f14d8610eefa9b3e20c11aab50c4b0a4e16ab15c` and prepared `codex/sprint-7c-investigation` from
that verified current main commit. The preflight was carried as an unchanged untracked input,
not included in the 7B-only commit. This superseding-authority header and preparation note are
the first 7C documentary updates after that preservation check; the original predictions remain.
Merged-main CI is running at this preparation checkpoint. No application, schema, dependency,
default, credential or production change occurred. 7C/7D/7E remain PLANNED.

The subsequent merged-main CI completed SUCCESS at the same exact commit. This closes the
7B documentary prerequisite, not 7C implementation or independent review. At handoff the
preflight and two matching owner updates remain local/uncommitted; no application code changed.
The original analysis and running-state checkpoint above remain historical. The existing goal
tracker still requires user-controlled resumption for automatic continuation, despite the
resolved permission bundle. Start with approved 7C implementation; do not advance to 7D/7E early.

## Implementation note — 2026-10-04

The latest "Complete 7c" request authorizes the approved slice. Current owners record 7C IN PROGRESS,
7D/7E PLANNED. Exact current main `f14d861` and prerequisite CI were reverified; implementation is
on `codex/sprint-7c-investigation`, preserving the carried preflight/owner changes and unrelated skills.
The original analysis and predictions above remain historical, not renewed blockers.

Implemented the optional exact-scan history filter using the existing unique index, explicit typed
GET-only BFF investigation allowlist, and successful operational response UTC metadata.
The client uses 25-row pages and on-demand identity-bound historical detail, text-only bounded
disclosures, known typed proof links, directional endpoints and separate current handling.
Invalid filters, wrong provenance and stale selections fail closed. Definition checksums and
artifact/digest bindings are checked against the selected scan or typed citation.
No schema/dependency/default/control/evaluation/auth policy changes or later-sprint implementation.
Resource/finding detail and mutable-page limitations are documented, not silently expanded.
Fresh full validation, independent review, scoped publication/guarded merge and main CI remain
pending at this note; initial focused checks and frontend units are not complete acceptance.

## Accepted 7C implementation — 2026-10-04

The approved exact-scan history filter, typed BFF GET allowlist and successful operational UTC
response metadata are accepted through [PR #45](https://github.com/jnc247s/cloud-security-automation/pull/45)
and [test-only CI repair PR #46](https://github.com/jnc247s/cloud-security-automation/pull/46)
at `f10c450478cce3ec962d2f45d249f57147443c32`. Exact reviewed head `39e9aef`, both final-head CI runs,
approval 9's guarded ordinary merge and [merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37237604046)
passed. The single reviewer has zero unresolved findings; malformed-type guards and deterministic
real-session-expiry tests repaired the identified issues without weakening runtime security.
Final acceptance passed 2,728 backend tests including 283 PostgreSQL cases, no skips, 54 frontend
units, 32 Chromium/Firefox journeys and quality/image gates; 20 repeated expiry journeys also passed.
The [active-plan checkpoint](exec-plans/active/sprint-7.md#7c-acceptance-and-documentary-closeout--2026-10-04)
records exact evidence, diagnostics and limitations. Original predictions above remain historical.
No schema, default, dependency, collector/control/evaluation, role or authentication-policy change.
Next is analysis-only 7D preflight; NIST hierarchy, 7E review and live operations are not delivered here.
