# Sprint 7E acceptance and closeout preflight

Prepared: 2026-10-04, analysis only following "Do 7e preflight".
Superseding acceptance: the subsequent "Implement 7e" approved this acceptance-only slice.
7E and Sprint 7 are now COMPLETE through PR #50 at `7998e12786b817aa6de3abd63b37d22b5c4a99b6`,
with whole-sprint exact-head independent REVIEW_PASS, both green final-head CI runs, guarded
ordinary merge and green merged-main CI. The [matrix](sprint-7e-acceptance.md) records exact
accepted evidence, the bounded Firefox test-launch repair, failed attempts and explicit limits.
The separate documentary closeout subsequently passed exact-head review, both final-head CI
runs, guarded ordinary merge through PR #51 and final main CI at
`b90bf08eeb79ba56d5308f19a942c6c10bf41b28`. The plan is archived and all 7A--7E states are COMPLETE.
Sprint 8 is NEXT only; separate preflight and implementation authority are required.
The original analysis and its then-PLANNED checkpoint below remain historical.
7A--7D are COMPLETE, Sprint 7 is IN PROGRESS, and 7E remains PLANNED.
The existing implementation is ready for a bounded acceptance-only slice: combine the accepted
browser journeys, strengthen accessibility and cross-panel safety evidence, then review the
whole sprint and close its documents after all gates pass. No new product interface, dependency,
schema, control, mapping or authentication decision is presently justified.

[ROADMAP.md](../ROADMAP.md) alone owns progress; the
[completed plan](exec-plans/completed/sprint-7.md) owns approved detail and the historical sequential
workflow authority. This request stops before implementation, reviewer launch or publication.
Approval 9's one final read-only reviewer and guarded publication/merge sequence remains recorded,
but is not exercised by this preflight. The unfinished broader goal is not reset or replaced.

## Verified baseline

Fresh GitHub and local Git readback agree on main
`9927b768f8d3cbc1ffa958c50262eef18271da13`, accepted
[7D documentary closeout PR #49](https://github.com/jnc247s/cloud-security-automation/pull/49).
Its parents are accepted implementation `8f58b2716a726fcefc5d89567b0dff882f7502ea`
and reviewed documentary head `47bf7125937c78a8339f01d74388571864661100`;
main retains tree `24f098b08655aaf529038c187080ec421403e21f`.
PR #49 merged at 2026-10-05 01:22:43 UTC, which is October 4 locally.
Both exact-head CI runs and
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37251193595)
are successful. Main's logs record 2,731 backend passes, 19 existing warnings,
130 frontend units, 54 Chromium/Firefox journeys and quality/image gates. The accepted
PostgreSQL count is 283, with no skips.

The clean accepted main was fetched and used for scoped local branch
`codex/sprint-7e-preflight` in the existing `.tmp/sprint-6e3-readme-closeout` worktree.
The older 7D branch, parent skill branch/untracked `.agents/`, and original 6E.3 checkout
remain preserved. No accepted implementation was rebuilt or restarted.
Defaults remain catalog `0.2.1`, profile `default/1.0.0`, opt-in catalog `0.13.0`
and migration head `20261001_0006`.

## Inspected integration and existing evidence

The accepted path is browser -> same-origin dashboard READ adapter -> signed bearer/READ API ->
generic services -> retained database records. Browser cookies do not authenticate `/api/v1`.
The adapter checks origin and the current public session context before forwarding, then checks
session lifetime again before returning data. Only successful current findings/exceptions reads
carry a UTC response-time reference. See [API](api.md), [dashboard operations](operations/dashboard.md),
[assessment semantics](assessment-framework.md) and [known limits](operations/known-limitations.md).

`App.tsx` unmounts sensitive state before logout/expiry checks and keys the shell by session
context. `ScanShell.tsx` loads bounded history, exact scan detail and the exact 7A report;
scan/session/revision guards reject stale data. Investigation independently binds assessment,
snapshot, control, source and directional relationship identities to that retained scope.
`NistContext.tsx` reuses the same report, validates/indexes its nested data, mounts hierarchy
on disclosure, and issues no additional requests when selecting or expanding a release.
There is no NIST-row-to-assessment shortcut; acceptance must use the existing investigation
filters, not add navigation features.

Existing shell, investigation and NIST browser suites already cover all four READ roles,
real code/PKCE/JWKS login, exact historical data, four technical states, unavailable/partial
coverage, mapping fan-out, current expired risk handling, hostile text, stale responses,
mobile/keyboard actions and logout/expiry. Some journeys already combine NIST and investigation.
7E should add explicit whole-story and cross-panel assertions, not claim these risks are untested
or duplicate every slice truth table.

The browser fixture seeds real retained bundles through accepted offline collectors/rules and
persistence, including the 26-control catalog, historical releases, malformed/empty evidence,
unresolved references and newer observations. It uses a controlled loopback issuer,
forbids AWS clients and leaves authentication dependencies intact. Existing Sprint 6 HTTP
acceptance separately preserves real scan execution through offline AWS.
Neither test boundary is permission for browser scan execution or live IdP/AWS work.

## Proposed acceptance delta

| Concern | Existing evidence to retain | Bounded 7E addition or audit |
| --- | --- | --- |
| Whole user story | Signed login, real PostgreSQL/BFF/API reads and version-bound slice journeys | A dedicated combined story: select exact scan/release, check unique counts and retained mapping provenance, investigate the corresponding assessment/snapshot/evidence and graph records, inspect separately labeled current handling, then clear all panels on session change |
| Independent oracles | Offline fixture truth tables, exact UUID/checksum persistence and API readback | Use known fixture facts and retained identifiers alongside report/detail consistency; expected technical results must not be derived solely from the response under test |
| Accessibility | Native labels, captions, column headers, disclosures, focus styling, skip link and mobile tests | Test accessible names/landmarks, keyboard-only selection/filter/disclosure/drill-down/logout, meaningful focus, loading/error announcements and small-view overflow with existing Playwright tools; audit contrast and record manual assistive-technology limits |
| Security | Signed tokens, CSRF/origin, cookie-only denial, typed allowlists, no-store, redacted logs and stale-context tests | Verify combined panels cannot survive logout, real 401 expiry or identity replacement; preserve no mutation/executor/AWS calls, no credential storage/URL leakage, and escaped text-only metadata |
| Deterministic scaling | Available report uses ten SELECTs; PostgreSQL plans at 128/512 targets; exact-history query plans; linear client index and lazy hierarchy tests | Preserve query/operation/request-count budgets in whole-story acceptance, including zero NIST expansion requests and bounded on-demand detail/pages; do not substitute elapsed-time assertions |
| Sprint correctness | Accepted 7A--7D tests and protected Sprints 0--6 | A single authorized independent review of the whole Sprint 7 delta, not just new 7E tests, plus final documentation/status/link consistency |

Candidate work is a dedicated `frontend/e2e/sprint7.spec.ts` plus narrowly shared test assertions
where needed. Reuse the existing controlled browser fixture and accepted backend tests.
Add focused SQLite/PostgreSQL signed-HTTP acceptance assertions only where combined
count/provenance/read-only checks are missing; avoid a new test service or public fixture endpoint.
No application-code change is planned. If analysis or acceptance exposes a real defect,
report its affected contract and obtain guidance for a material scope/design change; do not
weaken an assertion, add skips/retries or silently redesign an accepted interface.

## Risks and non-goals

Current findings/exceptions are live operational views, not scan-time or atomic snapshots.
Stored ACTIVE is distinct from expiry eligibility at the explicit server reference;
missing/invalid time is unavailable. Exceptions never change historical FAIL or NIST counts.
Unavailable counts are null, not zero; unassessed/disabled/unmapped context is not PASS or N/A.
References with equal keys in different retained releases stay separate. Metadata URLs are
escaped text, not navigation, and client checksums do not certify unseen source bytes.

Accepted limits remain: one organizational READ trust domain, process-local sessions/no global
IdP logout, offset-page drift, unpaginated upstream resource/finding hydration, and display
truncation that does not bound payload size. Accessibility acceptance is scoped evidence,
not a formal WCAG certification or substitute for screen-reader testing. Live Cognito/MFA/TLS,
supply-chain hardening, tenant isolation, remediation and production deployment are not 7E.

Use only an owned disposable PostgreSQL database for integration/browser validation.
`scripts/validate.py --dashboard` creates a uniquely named loopback PostgreSQL container,
keeps its generated password out of argv/logs and removes only that owned container.
The browser seeding is not idempotent: use a fresh database for each fixture-server run.
Keep both Chromium and Firefox and the pinned Node/pnpm/dependencies; do not replace user
browser caches or upgrade dependencies to work around an environment fault.

## Sequential implementation and closeout gates

1. After a separate implementation request, reverify main, scope and the clean/unrelated Git
   boundaries. Retain this proposal and update only the normative 7E IN PROGRESS guard when
   implementation actually begins.
2. Add the acceptance delta and a concise evidence matrix, provisionally
   `docs/sprint-7e-acceptance.md`. Run targeted backend and both-browser acceptance first.
3. Run fresh Ruff lint/format, the complete backend suite with explicitly disposable PostgreSQL,
   frontend typecheck/lint/unit/build, both-browser journeys, documentation links, whitespace,
   Compose configuration and image gates. Check the existing offline non-root container smoke
   acceptance where applicable. Baseline CI is not acceptance of new tests or fixes.
4. Use the one authorized read-only final reviewer to examine the entire Sprint 7 delta from
   accepted pre-sprint base `bafa0783d347ef8b6c5e1182d4c2dd86119b412d` through the exact final
   head, its protected contracts, security and evidence matrix. Resolve findings, rerun affected
   and required regression gates, and get an exact-head/tree follow-up from that same reviewer.
5. Follow the recorded scoped publication and guarded ordinary merge authority only after
   review and green exact-head CI. Require green merged-main CI before accepting the slice.
   No auto/admin merge, force push or branch deletion.
6. Only after acceptance, reconcile README, ROADMAP, changelog and domain owners, record exact
   implemented differences, and move the active plan to `docs/exec-plans/completed/sprint-7.md`.
   Atomically update every inbound plan link and
   `tests/unit/contracts/test_sprint5_preflight_readiness.py`'s strict state/path guard, preserving
   historical predictions and adding explicit accepted-state assertions. Review and validate
   the final documentary delta through its required publication/CI gates as well.
7. Mark Sprint 7 COMPLETE only from actual passed gates, not permission or baseline test totals.
   Stop at closeout; Sprint 8 requires its own preflight and implementation authority.

## Preflight validation and stopping point

Fresh existing checks passed: 226 reporting, exact-history, signed dashboard/API,
session/log security and documentation/contract checks in 44.66s, using disposable in-memory
SQLite with no PostgreSQL URL and no live AWS/IdP. Command:

```text
python -m pytest tests/unit/contracts tests/unit/services/test_technical_posture_service.py tests/unit/services/test_investigation_history.py tests/api/test_dashboard_api.py tests/api/test_dashboard_investigation_api.py tests/unit/security -q
```

This is diagnostic evidence, not implementation or whole-Sprint-7 review. The accepted main CI
remains reusable baseline evidence because this preflight changes Markdown only.
After the Markdown delta, all 87 documentation/contract checks passed in 0.27s.
Ruff lint/format and whitespace passed; Alembic reports unchanged `20261001_0006 (head)`.
Full PostgreSQL/browser/container gates were not repeated for this analysis-only delta.
The [completed-plan checkpoint](exec-plans/completed/sprint-7.md#7d-documentary-publication-and-7e-preflight--2026-10-04)
records exact diagnostic commands and validation reuse.
No blocking design choice was found in the inspected scope; new findings may still require guidance.
The preflight is local and uncommitted. No reviewer, commit, push, PR, merge, server launch,
production mutation or later-sprint implementation occurred. Next is a separate 7E implementation
request; the current Sprint 7/7E status guards remain unchanged.
