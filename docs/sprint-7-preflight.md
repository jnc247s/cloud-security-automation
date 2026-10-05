# Sprint 7 dashboard preflight

Prepared: 2026-10-02. Analysis-only checkpoint, requested by the user; Sprint 7 was NEXT.
Superseding acceptance: the completed plan records all scoped 7A--7E approvals and passed gates.
Sprint 7 is COMPLETE through PR #50 with exact-head review and green main CI. Sprint 8 is NEXT
only; the original analysis and its then-future decisions below remain historical.
The accepted API, history and mappings can support a read-only dashboard, but reporting semantics
and browser authentication need explicit decisions before implementation. The recommended first
slice is 7A, an exact-scan reporting contract and additive read projection.

[ROADMAP.md](../ROADMAP.md) owns status. The [proposed execution plan](exec-plans/completed/sprint-7.md)
records subsequent approvals. This preflight alone does not authorize implementation, reviewer
agents, publication or merging.
Sprint 6's unattended authorization ended with that sprint; it does not extend to Sprint 7.

## Verified starting point

The reused checkout is
`C:\Users\jncoh\OneDrive\Documents\ChatGPT\ResProject1 2\.tmp\sprint-6e3-readme-closeout`.
Clean local and remote main matched `bafa0783d347ef8b6c5e1182d4c2dd86119b412d`, the
accepted [PR 41 closeout](https://github.com/jnc247s/cloud-security-automation/pull/41).
[Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36957670046)
passed 2,533 tests, including 252 PostgreSQL cases, no skips, 20 existing warnings, Ruff,
341-file formatting and the image build. These are recorded baseline results, not new Sprint 7
validation. The implementation acceptance in PR 40 remains preserved in the
[completed Sprint 6 plan](exec-plans/completed/sprint-6.md).

The five-control default catalog is `0.2.1`; profile identity/version is `default/1.0.0`.
Latest opt-in `0.13.0` contains 25 core controls plus supported legacy S3-900. Migration head
is `20261001_0006`. None of those contracts should change for dashboard work.
The parent checkout remains on its unrelated skill branch with untracked skill files, and the
original 6E.3 checkout remains preserved. Analysis documentation uses `codex/sprint-7-preflight`.

Sources inspected: [operating guide](../AGENTS.md), [product requirements](../PRODUCT_REQUIREMENTS.md),
[architecture](../ARCHITECTURE.md), [security](../SECURITY.md), [threat model](../THREAT_MODEL.md),
[API](api.md), [assessment semantics](assessment-framework.md),
[NIST mappings](frameworks/nist-csf-2.0.md), and [limitations](operations/known-limitations.md).

## Integration contracts and gaps

| Consumer need | Accepted interface | Implication for Sprint 7 |
| --- | --- | --- |
| Select a scan and explain collection coverage | ScanService and scan list/detail API; detail includes exact profile/catalog, scope and enabled controls when persisted | Use an explicit scan ID. Scan list has no account/Region filters, and its offset pages are not frozen. Do not infer a single latest scan per account from one page. |
| Show assessment states and counts | AssessmentService; list accepts scan_id and returns four-state results | No summary service exists. An additive backend projection avoids downloading all evidence or one detail request per assessment just to count results. |
| Resolve the applicable control definition | ControlService returns stable controls with all retained versions | Match exact control_version_id and selected scan catalog; never select versions[0] or lexical latest. |
| Explain NIST context | FrameworkService exposes immutable hierarchy and mappings, not posture | Join the selected control versions to their exact reference IDs, framework releases and mapping checksums. Existing catalogs are subsets, not the full CSF Core. |
| Investigate observed resources | ResourceService provides stable identity, latest snapshot and paged history | A historical assessment must use its exact resource_snapshot_id/scan_id. Latest state is not historical evidence; first-seen ARN and equal-time latest-snapshot limitations remain. |
| Follow proof citations | Assessment detail, EvidenceGraphService source-outcome/detail and relationship/detail APIs | Load artifacts on demand. Preserve exact scan, owner, Region, direction and unresolved-reference identity; no fabricated resources or reverse edges. |
| Explain operational handling | FindingService and ExceptionService | Current finding/exception state is a separate live view, not the historical technical result. Stored ACTIVE alone does not prove an unexpired exception. |
| Authenticate a browser | Existing bearer verifier and READ capability; no browser login, session or CORS middleware | A new client must obtain a valid token safely and preserve API enforcement. A dashboard shell is not a login implementation. |

Inspected callers and tests include [read-service tests](../tests/unit/services/test_read_services.py),
[framework tests](../tests/unit/assessment/test_frameworks.py),
[scan service](../app/services/scan_service.py), [projections](../app/services/projections.py),
[API schemas](../app/schemas/api_views.py), [scan schemas](../app/schemas/scan.py),
[routes](../app/api/router.py), [whole-sprint HTTP acceptance](../tests/sprint6_http.py),
and the SQLite/PostgreSQL Sprint 6 historical-release tests.

There is no frontend package, UI runtime, reporting aggregate or manual-assessment store.
There is no exception-detail, audit-read or governance-mutation API. Their absence must not
be hidden by direct database access from a dashboard or by adding mutations to this sprint.

## Proposed reporting semantics

These are project proposals for approval, not accepted API fields or NIST-prescribed calculations.

1. Anchor every technical report to one explicit scan. Include lifecycle, collection account,
   requested/successful scope, collection outcomes, enabled controls, exact profile/catalog
   identities and retained checksums. Never replace those with current deployment defaults.
2. Count unique assessment IDs in the four existing states. Report target-assessment counts
   separately from control counts. Mapping fan-out must not multiply the headline totals.
3. For each control registered in that scan's catalog, distinguish enabled, disabled and enabled
   without retained assessments. A missing result is not PASS or NOT_APPLICABLE.
   An empty enabled-control set means no controls were enabled, not a safe environment.
4. A RUNNING scan is unfinished. A terminal scan without a persisted result bundle has an
   unavailable report and sanitized failure context, not a zero-failure summary. PARTIAL and
   FAILED scans with retained results may show those facts alongside explicit collection gaps.
   Do not discard independently valid assessments or pretend collection is complete.
5. Keep account-global, regional account-setting and resource targets distinct. Resource ownership
   may differ from collection account; supplemental/home Regions do not imply full Region coverage.
   Filters select data and never create tenant authorization.
6. Show NIST Function/Category/Subcategory context only from version-bound mapped subsets.
   Each row should expose mapped/enabled/assessed control counts, four-state target counts,
   missing coverage and source provenance. Do not label one passing control, or even all scanner
   checks passing, as satisfaction of an entire NIST outcome. No compliance percentage.
7. Do not merge references from different local subset releases just because their display keys
   match. Keep full identities/provenance. If a later grouped display is desired, define its
   compatibility rules and retain the contributing exact identities before implementation.
8. Unsupported outcomes and manual work remain unassessed by this scanner. No manual
   attestation exists in accepted storage; do not invent MANUAL evidence or a new technical result.
9. A finding exception never changes an assessment. Label current operational state separately
   from scan-time technical facts. Consider revocation, expiry and a defined server read time;
   do not claim that a live finding view is a historical exception snapshot.

Recommend counts and explicit coverage notes initially, without an overall framework PASS/FAIL
or score. Existing assessment enums, evaluator decisions and mapping artifacts remain unchanged.
The [repository interpretation rules](frameworks/nist-csf-2.0.md#common-interpretation-rules)
are stricter than a generic chart: this display is technical evidence context, not certification.
NIST describes CSF as a taxonomy of outcomes, not a prescribed control implementation.
[NIST CSWP 29](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)

## Proposed architecture and query boundary

Add a generic reporting service and separate response models, with a thin authenticated READ route.
A candidate route is `GET /api/v1/scans/{scan_id}/technical-posture`; its final path and schema
are subject to 7A approval. It reads retained scan/profile/catalog/assessment/mapping records in
the service layer. It never calls AWS, the rule engine, remediation or persistence writers.
Existing routes and fields retain their accepted meanings.

The report should omit normalized configurations and evidence payloads from aggregate responses.
Return context, counts, exact version references and drill-down identifiers; fetch sensitive
payloads only through existing authorized detail APIs. Do not parse reason prose for IDs.

Use bounded bulk queries and exact joins rather than repeatedly calling detail services in a
loop. The accepted assessment scan/result index, scan account/time index, control-version
uniqueness and mapping/reference indexes are starting evidence, not a promise that every proposed
query is indexed. Prove query/operation counts and representative PostgreSQL plans during 7A;
add an Alembic index migration only if demonstrated and separately reviewed. No schema change
is presently justified by the preflight.

Freeze technical counts to immutable terminal scan records. Operational finding/exception data
is mutable; expose it separately with its read time rather than promise a frozen mixed report.
Do not silently change existing offset pagination. Use bounded pages for drill-down, and define
an additive cursor contract only if a measured need warrants it. A frontend must never fetch
every account's full history to calculate a dashboard total.

## Browser and authentication decision

Recommended topology: a thin same-origin, read-only browser client consuming the generic API.
No new public deployment, wildcard CORS, direct PostgreSQL credentials, shared administrator
token, embedded AWS credential, in-app password system or new capability is proposed.

Choose the UI/toolchain and browser authentication design before 7B. A static typed client
is one option; server-rendered pages are another. No framework or dependency version is selected
or installed by this preflight.

For a direct browser OAuth/OIDC client, review Authorization Code with PKCE, exact redirect/issuer/
audience configuration and the existing API's roles contract. Do not use an implicit grant or
replace API authorization with client-decoded roles. Public OAuth clients must use PKCE under
[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.1.1).
Provider registration, token acquisition/refresh/logout and expiration handling are not currently
implemented and need an approved design; existing JWT verification alone does not supply them.

Do not persist credentials or sensitive evidence in localStorage, sessionStorage or browser
databases, and do not place tokens in URLs, console output, analytics or screenshots.
A direct client's short-lived tokens should be held only in memory under the approved design.
A backend-for-frontend alternative requires its own session, secure cookie, CSRF, logout and
token-storage design; it must not be introduced implicitly.
[OWASP HTML5 security guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#storage-apis)

Cloud tags, names, policy text, evidence and exception reasons are untrusted text. Escape them;
do not evaluate HTML, scripts or arbitrary links. Review CSP, security headers, no-store handling
for sensitive responses, bounded payload display and authentication-error clearing. No external
analytics/CDN widgets or offline evidence caches are proposed.
Any local development-auth option stays explicit, loopback/test-only and fails closed in production.

## Proposed slices and dependencies

| Slice | Deliverable | Required predecessor |
| --- | --- | --- |
| 7A | Approve reporting semantics, implement/test exact-scan service and additive READ projection | Plan and 7A contract approval, then explicit implementation request |
| 7B | Approve browser auth/toolchain; authenticated read-only shell, scan selection and error states | Accepted 7A contract and browser-auth decision |
| 7C | Assessments, findings/exceptions, exact snapshots and evidence/source/relationship drill-down | Accepted 7A and 7B |
| 7D | Version-bound NIST technical-context views with explicit subset and coverage limitations | Accepted 7A and 7B |
| 7E | Whole-dashboard acceptance, accessibility/security/performance checks and documentary closure | Accepted 7C and 7D |

Run 7A and 7B sequentially. 7C and 7D can become parallel implementation candidates only after
shared contracts and UI components are frozen and the user explicitly approves delegation.
Use the repository's independent-review and merge gates for each implementation slice;
no reviewer agent is launched by this preflight.

## Risks and required validation

Acceptance must cover missing/partial/failed/running scans, disabled controls, legitimate N/A,
multiple targets, duplicate mappings, all supported historical releases, exact-version joins,
global/external-owner/supplemental-Region targets and unchanged exceptions/technical results.
Reuse the accepted all-26/39-assessment fixture as one oracle, not the only truth table.

Add deterministic service tests and authenticated HTTP tests on SQLite and disposable PostgreSQL,
with production OIDC verification tested using controlled keys/JWKS rather than bypassed
dependencies. Test missing/expired/wrong-issuer/wrong-audience tokens, every READ role, capability
denials for scan creation, and no AWS calls from reporting. Browser tests must use real API
responses through a test database, not only hard-coded UI fixtures; AWS alone may be offline.

Add browser checks for loading/empty/error/partial states, login expiry/logout data clearing,
back/refresh/scan changes, keyboard navigation, screen-reader labels, responsive layouts,
untrusted metadata rendering, sensitive-cache avoidance and consistency with public API IDs/counts.
Use operation/query-count gates and representative large datasets, not timing assertions alone.
Authentication/session decisions require security and threat-model updates.

Every implemented slice still runs targeted tests, Ruff, formatting, full regression and relevant
PostgreSQL/security/acceptance validation. New frontend tooling needs its own reproducible
dependency/build/test gates. Runtime/container changes require Compose and image validation.
Independent review and required publication/merge approval remain separate gates.
No tests, production operation or API behavior are implemented by this document.

## Documentation reconciliation and scope boundary

The limitations register contained one stale sentence saying LOG-002 through LOG-004 remained
planned. Accepted 6F metadata, code, tests and roadmap establish their completion; this preflight
reconciles only that sentence without changing the remaining collector-granularity limitation.
The completed Sprint 6 plan's earlier pending/no-Sprint-7-preflight checkpoints remain historical,
not rewritten to describe this new request.

Leave tenant isolation, scanner orchestration, rate limiting, audit-context expansion,
equal-time latest-snapshot behavior, exception-expiry scheduling, arbitrary graph traversal,
new AWS controls/mappings, manual governance workflows, remediation, production deployment and
AI runtime outside this proposal. Do not silently fix baseline limitations as dashboard work.

## Preflight outcome and next decision

Analysis is complete. Conditional readiness: the accepted backend provides the necessary retained
facts, but the plan and proposed 7A reporting contract require approval before implementation.
Browser auth/toolchain approval is a separate gate before 7B; it need not block an approved 7A.
No implementation, new migration, policy/default change, agent review or publication has occurred.

Next: review and approve the proposed plan and 7A contract, then explicitly request 7A implementation.
Fresh diagnostic results and final local Git state are recorded in the proposed plan.
