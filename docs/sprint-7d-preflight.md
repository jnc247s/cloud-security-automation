# Sprint 7D NIST context preflight

Prepared: 2026-10-04 as analysis only, following the user's "Do 7d preflight" request.
Superseding acceptance: the subsequent "Implement 7d" approved this prepared slice; 7D is now
COMPLETE through PR #48 with green merged-main CI. Approval 9's single reviewer and guarded
publication/merge sequence was followed; the acceptance record below supersedes pending checkpoints.
7E remains PLANNED and unstarted. The original analysis findings and checkpoint below are retained.
The accepted exact-scan report already supplies the hierarchy, counts and provenance needed
for a client-only NIST context view. No new API, schema, query, mapping, dependency or policy
decision was necessary. The client-only implementation and all required 7D acceptance gates passed.

[ROADMAP.md](../ROADMAP.md) owns progress. The [active plan](exec-plans/active/sprint-7.md)
preserves the prior sequential workflow approval. The original preflight stopped before
implementation, reviewer launch, commit, publication or merge. Its PLANNED checkpoint below
is historical; the superseding implementation/acceptance records make 7D COMPLETE.
7A--7D are COMPLETE, Sprint 7 IN PROGRESS and 7E PLANNED.

## Verified preflight baseline

At preflight, remote main was `2a4af99fef656afe0772580dc7e8576b9f813737`, the accepted
[7C documentary closeout PR #47](https://github.com/jnc247s/cloud-security-automation/pull/47).
Its [merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37240425614)
is COMPLETED/SUCCESS. Recorded baseline results are 2,728 backend tests including 283 PostgreSQL
cases, no skips, 19 existing warnings; 54 frontend units, 32 Chromium/Firefox journeys and
quality/image gates. These are reused accepted-baseline evidence, not new 7D acceptance.
The accepted implementation remains PR #45/46 at `f10c450`; no technical behavior changed in
PR #47. Defaults remain catalog `0.2.1`, profile `default/1.0.0`, latest opt-in `0.13.0`
and migration `20261001_0006`.

The existing clean worktree was reused on local `codex/sprint-7d-preflight`, created from that
verified main. The older parent skill branch and its untracked `.agents/` files, original 6E.3
checkout and all 7C branches are preserved. No reset, clean, replacement or publication.

Inspected authority: [AGENTS.md](../AGENTS.md), [product requirements](../PRODUCT_REQUIREMENTS.md),
[architecture](../ARCHITECTURE.md), [security](../SECURITY.md), T03/T07/T10/T13/T17--T19 in
[THREAT_MODEL.md](../THREAT_MODEL.md), [assessment semantics](assessment-framework.md),
[framework interpretation](frameworks/nist-csf-2.0.md), [API](api.md),
[dashboard operation](operations/dashboard.md), [limitations](operations/known-limitations.md),
and the original [Sprint 7](sprint-7-preflight.md) and [7C](sprint-7c-preflight.md) preflights.

## Integration contracts and callers

| Need | Existing contract | Proposed 7D use |
| --- | --- | --- |
| Exact report and scope | [TechnicalPosture schema](../app/schemas/technical_posture.py), GET /api/v1/scans/{scan_id}/technical-posture | Selected retained scan/profile/catalog and schema 1.0.0; preserve lifecycle, collection gaps and availability |
| Browser authorization | [BFF route](../app/dashboard/routes.py) forwards the report through the real bearer/READ API | Reuse the fetched response and session context; no new target, token handling or direct database read |
| Hierarchy | frameworks contain exact UUID/key/version, source/checksum/retrieval time and reference UUID/parent/level | Select one exact local release; connect parents by UUID within it, never merge display keys across releases |
| Counts and coverage | Controls contain enablement, coverage, definition checksums and mappings; references contain unique mapped-control-version unions and four-state counts | Render server counts; reject inconsistent data without creating scores or results |
| Mapping explanation | [FrameworkMappingView](../app/schemas/api_views.py) retains exact mapping/control-version/framework/reference identity, rationale, source/version, verification time and checksum | Show each contributing mapping and its own Subcategory, including descendant contributions to parent rows |
| Investigation | [ScanShell](../frontend/src/ScanShell.tsx) mounts accepted [Investigation](../frontend/src/Investigation.tsx) with exact scope | Keep 7C independent; do not infer assessment/resource links or add per-row detail reads |

[TechnicalPostureService](../app/services/technical_posture_service.py) already performs exact
retained joins and unions each parent's contributing control versions before counting.
Its available mapped-report path is guarded at ten SELECTs independent of target count, with
no payload hydration, AWS/evaluator call, autoflush or transaction write. Existing PostgreSQL
tests cover representative 128/512-target aggregate plans. No index or migration is justified.
The generic [FrameworkService](../app/services/framework_service.py) exposes retained catalogs,
not selected-scan posture; fetching its complete list is unnecessary and could add unrelated
releases. Do not widen the BFF with framework list/detail calls for this view.

The existing [frontend api](../frontend/src/api.ts) validates only shell fields;
[isScope](../frontend/src/investigation-api.ts) validates 7C identity bindings, not nested NIST
data. Neither is enough to render a hierarchy safely. Add a separate strict 7D validator and
typed view, composed with accepted guards, without breaking their callers or fixtures.
An unsupported NIST response must clear that panel and explain the limitation; it must not
substitute prior data or disable independently valid 7C investigation.

## Proposed presentation and binding rules

Mount a separate NIST technical-context section under the selected scan, reusing its report.
Show four-state unique-assessment totals and catalog/profile coverage separately from reference
coverage. Require explicit framework-release selection, labeled by key/version and UUID;
do not infer a latest release. Use native accessible disclosures for Function, Category and
Subcategory rows, with contributing-control and mapping-provenance details opened on demand.
Reset release/disclosure selection when scan, report revision or session context changes.

Each view must explain TECHNICAL_CONTEXT_ONLY and MAPPED_TECHNICAL_SUBSET in readable language.
These are local mapped subsets, not the full CSF Core or official new NIST releases. Display
source and mapping metadata as text, not arbitrary links. Checksum display is provenance, not
client cryptographic verification of artifact bytes absent from this report.

Before displaying nested data, the proposed validator must check:

- Actual scalar types, supported interpretations/schema/levels, UUIDs, checksum shapes,
  explicit-offset provenance timestamps and safe nonnegative integers. Never coerce with
  String(...) or treat missing/null counts as zero.
- Exact scan/catalog/profile binding, unique control/version keys, enabled-control membership
  and coverage consistency. Available counts agree with unique control rows; unfinished or
  no-bundle reports retain null counts and assessed/unassessed coverage.
- Unique framework/reference/mapping identities, release-local parent membership and valid
  FUNCTION -> CATEGORY -> SUBCATEGORY depth. Reject orphans, cycles, duplicates and foreign
  parent/reference/control versions instead of dropping them or deriving parents from keys.
- Mapping identity agrees with its enclosing control version and exact framework release,
  reference level/key/title. Reference unions agree with direct/descendant mappings; coverage
  and counts agree with that unique union. Reject overflow or contradictory totals. These are
  display integrity checks, not rule evaluation or authorization.

Render PASS, FAIL, INSUFFICIENT_EVIDENCE and NOT_APPLICABLE counts as technical facts, never
a Function/Category/Subcategory result. A parent is a server-provided unique union, not the
sum of child rows. Overlapping references/releases are not additive headline totals.
Keep registered/enabled/disabled/assessed/unassessed definitions distinct from target assessments.
Empty, unmapped and disabled-only rows are not PASS or NOT_APPLICABLE. Unsupported/manual work
stays unassessed by the scanner; do not invent manual attestations, missing Core outcomes,
a new enum, compliance percentage or overall outcome result.

RUNNING and terminal no-bundle reports may show exact retained definition/source context but
must label technical counts unavailable. PARTIAL/FAILED reports with retained results preserve
four-state facts and collection gaps; AVAILABLE never implies complete collection. Historical
counts exclude mutable findings, ACCEPTED_RISK and exception eligibility. The accepted 7C
current-handling view remains separate and cannot rewrite FAIL.

## Security and efficiency boundaries

Reuse existing server-only tokens, opaque cookies, exact origin, real bearer/READ checks,
expected public session context, final in-flight guard, no-store/CSP and cross-tab invalidation.
Logout/expiry/identity changes unmount the view; superseded or aborted report reads cannot
repopulate it. Render escaped text with labeled bounded disclosures; no HTML, Web Storage,
exports, analytics, external assets, metadata-URL navigation or credential logs.

Framework selection/expansion should cause zero additional network requests: the accepted
report already includes the data. Build release-local indexes once per validated report;
avoid repeated whole-report traversal and render only selected/disclosed content. Measure
deterministic request/traversal counts and representative layouts, not only timing. Display
limits do not bound upstream report size; never silently truncate counts or coverage.
READ remains organization-wide. Process-local sessions, offset drift, existing unpaginated
detail internals and unvalidated live Cognito/MFA/TLS/production setup remain limitations.

## Implementation sequence and validation

1. Add typed nested guards and pure release-local hierarchy indexes, with malformed-type,
   duplicate/orphan/cycle/cross-release/unsupported-schema, inconsistent-count and overflow tests.
   Retain valid zero/null cases and every supported historical release.
2. Add the separate context component, release selection, counts/coverage tables and mapping
   disclosures. Integrate with ScanShell and update its 7C-only limitation wording only when
   7D is implemented. Preserve shell, investigation and session lifecycle tests.
3. Extend only synthetic browser fixtures and add real controlled-issuer -> BFF -> bearer API ->
   disposable PostgreSQL journeys in Chromium/Firefox. Exercise old scans after newer catalogs
   are retained, repeated keys across releases, all four states, unavailable/partial reports,
   disabled/unmapped/unassessed context and exception-versus-technical separation. The current
   fixture already provides default-catalog and 0.13.0 scans; add missing historical or adverse
   scenarios without changing bundled mapping/framework artifacts or bypassing authentication.
4. Test keyboard/labels/responsive disclosures, hostile text, wrong-scan responses, delayed reads,
   refresh/back/selection changes, logout/expiry/two tabs and no extra framework/detail requests.
   Authorization journeys use real enforcement. Controlled malformed-response probes supplement,
   never replace, authenticated database-backed journeys.
5. Run targeted tests, then Ruff, format, full pytest with the harness's disposable PostgreSQL,
   frontend type/lint/unit/build, full browser suite, Compose and image/runtime checks. Rerun
   reporting history/query-count/plan tests and real READ/security tests; do not reduce regression
   merely because application changes are client-only.
6. Reconcile README/roadmap/plan, framework interpretation, API reuse, architecture/security/threat
   and operations owners. Keep implementation and acceptance distinct. Require the one approved
   read-only 7D reviewer on exact final inputs, resolve every finding, then follow scoped exact-head
   CI/guarded ordinary merge/merged-main CI gates before advancing to 7E.

Likely implementation files are new frontend NIST guard/component/unit-test modules, ScanShell/
style integration, a new browser spec and the existing test-only browser fixture. No backend/
service/route/schema/model/migration/lockfile/default change is proposed. Any finding requiring
a new accepted contract or material policy choice must be reported for guidance, not silently
included. 7E whole-dashboard acceptance and Sprint 8 remain separate.

Inspected tests: [reporting service](../tests/unit/services/test_technical_posture_service.py),
[reporting HTTP](../tests/api/test_technical_posture_api.py),
[PostgreSQL reporting](../tests/integration/test_technical_posture_postgres.py),
[BFF authentication](../tests/api/test_dashboard_api.py), [shell units](../frontend/src/ScanShell.test.tsx),
[browser journeys](../frontend/e2e/shell.spec.ts), [test server](../tests/dashboard_browser_server.py)
and [validation harness](../scripts/validate.py). No browser or database service was started by
this analysis.

## Preflight result and next gate

Fresh accepted-contract diagnostics passed 81 tests, no skips (34.76s):
`python -m pytest -p no:cacheprovider tests/unit/services/test_technical_posture_service.py
tests/api/test_technical_posture_api.py tests/api/test_dashboard_api.py -q`.
These use disposable SQLite and controlled OIDC fixtures, not an operator database.
Documentation/link/status, Ruff, format and whitespace checks are recorded in the active plan.
Full/PostgreSQL/frontend/browser/image acceptance is reused for unchanged implementation;
no new run of those suites or independent review is claimed here.

Preflight is ready for a separate implementation request under the preserved scoped workflow.
No new material design/policy decision was identified for this client-only proposal. 7D remains
PLANNED and unimplemented. Stop here; do not implement, publish, merge, start 7E, launch a
reviewer or reset/replace/complete the unfinished larger goal during this preflight.

## Superseding implementation checkpoint

The subsequent "Implement 7d" request approves the prepared slice. Local implementation
is underway on `codex/sprint-7d-nist-context`, based on verified accepted main `2a4af99`;
7D is IN PROGRESS and 7E remains PLANNED. The five uncommitted preflight documents were
preserved with manifest `2F182FB16CF3B8A08648E2E7C3CCE06E43ED5AD79BA947603FAE382067BBB91D`
before branching. No accepted backend, mapping, schema, default, dependency or security contract
change was needed. The unrelated parent `.agents/` files and original 6E.3 checkout are preserved.

The view uses a separate strict graph/count/provenance guard, release-local Maps and native
accessible lazy disclosures, resetting through the shell's existing selection/refresh/session
lifecycle. Technical counts and coverage remain separate and sources are bounded escaped text.
Framework selection and expansion make no requests. Supported investigation remains independent
of malformed NIST data; no previous hierarchy/counts or latest release is substituted.

The first real API run exposed an implementation error: backend level literals are lowercase
`function/category/subcategory`, not uppercase enum member names. The client now preserves those
serialized values and uses uppercase only in display labels. Two backend-to-frontend contract
tests pin levels and the four count fields. The following browser run exposed only test plumbing:
newly duplicated profile provenance needs the exact Profile field locator, findings require opening
assessment detail, and the one-shot expiry hook uses `times: 1`. All original expiry completion,
real 401, sensitive-data clearing and historical-count assertions remain; no auth/runtime repair,
retry, skip or weakened test was added. A fresh complete candidate run is pending.

One read-only independent 7D reviewer was launched under approval 9. Review is pending; no
acceptance, commit, publication or merge is claimed here. Existing query/history/READ checks
are rerun on disposable PostgreSQL even though the implementation is client-only. Unsupported
manual/unassessed/unmapped/empty contexts are covered by isolated display fixtures rather than
inventing terminal bundles that accepted persistence does not admit. Real browser journeys cover
retained catalogs 0.2.1/0.3.0/0.13.0, all four states, disabled context, running/no-bundle/partial
reports, current risk separation, stale/wrong scans, refresh/back, keyboard/mobile, hostile text,
logout/expiry/two tabs and zero expansion requests. Existing service/PostgreSQL tests retain all
historical releases and 128/512-target bounded query/plan checks. No 7E or later work is started.

Superseding local validation: 192 focused checks (87.72s); 86 final contracts (0.27s),
130 frontend units/type/lint/build, all 54 Chromium/Firefox journeys (1.1m), 2,731 full backend
tests including 283 PostgreSQL, no skips, 19 existing warnings (580.95s), Ruff/369-file formatting,
whitespace/Compose/image gates passed. The disposable database was removed. Initial review's
two stale current-state documentation statements are reconciled; final frozen-input review and
GitHub CI/merge/main-CI acceptance remain pending. See the
[local acceptance checkpoint](exec-plans/active/sprint-7.md#7d-implementation-and-local-acceptance--2026-10-04).

## Superseding 7D acceptance — 2026-10-04

7D is COMPLETE. The same single reviewer returned exact-commit REVIEW_PASS with zero unresolved
findings for `b92c08a905b8a43f78c90172887e45630d0ff7b6`. Both exact-head CI runs passed;
[PR #48](https://github.com/jnc247s/cloud-security-automation/pull/48) merged ordinarily at
`8f58b2716a726fcefc5d89567b0dff882f7502ea`, and
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37248734936)
passed 2,731 backend tests (283 PostgreSQL, no skips), 19 existing warnings, 130 frontend units,
54 Chromium/Firefox journeys and quality/image gates. The merge tree exactly matches the
reviewed tree; there was no force/admin bypass, auto-merge or branch deletion.
The [acceptance checkpoint](exec-plans/active/sprint-7.md#7d-acceptance-and-documentary-closeout--2026-10-04)
records exact review/publication/merge bindings and the documentation-only publication gates.
The original preflight predictions and intermediate pending checkpoints above remain historical.
Sprint 7 stays IN PROGRESS; 7E's separate preflight and whole-sprint review are unstarted.
No backend/API/auth/schema/mapping/default/dependency or migration change, live provider/cloud/
production operation, later-sprint implementation or unfinished-goal reset/completion.
