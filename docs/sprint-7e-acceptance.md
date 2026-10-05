# Sprint 7E acceptance evidence

Status: IN PROGRESS, not accepted. The user approved the
[7E preflight](sprint-7e-preflight.md) on 2026-10-04.
This slice adds tests, browser-harness configuration and acceptance documentation only; no application
runtime, API/BFF, policy,
dependency, catalog, mapping or migration change is planned.
[ROADMAP.md](../ROADMAP.md) owns progress and the
[active plan](exec-plans/active/sprint-7.md) records review/publication/merge gates.

## Whole dashboard story

A reader signs in through the controlled issuer, chooses an exact retained scan and mapped
framework release, inspects four-state counts and mapping provenance, investigates the exact
assessment/snapshot/evidence and typed source/relationship records, then inspects current-risk
handling separately. Logout, real server expiry and identity replacement clear every sensitive
panel. The browser consumes the existing same-origin adapter, signed bearer/READ API and
generic retained-data services; it never connects directly to the database or starts a scan.

The full offline fixture has 26 enabled controls and 39 retained assessments: 21 PASS, 17 FAIL,
one NOT_APPLICABLE and zero INSUFFICIENT_EVIDENCE. These are frozen facts from accepted Sprint 6
acceptance, not expected values calculated from a response under test. The old network fixture
retains one FAIL despite a newer PASS and current ACCEPTED_RISK with a stored ACTIVE, expired
exception. Its counts never change. These fixture truths are not production posture claims.

## Acceptance matrix

| Boundary or risk | Evidence |
| --- | --- |
| Signed login and READ for all four roles | [Combined SQLite HTTP tests](../tests/api/test_sprint7_acceptance.py), [same PostgreSQL tests](../tests/integration/test_sprint7_acceptance_postgres.py) and [browser story](../frontend/e2e/sprint7.spec.ts); no authentication dependency override |
| Browser -> adapter -> API -> retained PostgreSQL | Controlled browser fixture plus real signed reads; the [shared HTTP assertions](../tests/sprint7_acceptance.py) compare unchanged BFF/API projections and exact profile/catalog/control provenance |
| Known counts and immutable evidence | Frozen 39-assessment truth table, catalog checksum, profile checksum, unique IDs, structured evidence digest, exact source artifact and directional snapshot readback |
| Historical facts versus mutable handling | An older FAIL is not replaced by a newer PASS; stored ACTIVE is distinguished from expiry at server response time; current accepted risk leaves the old assessment/report unchanged |
| Read-only behavior | AWS is forbidden in fixtures; all captured acceptance SQL is SELECT; no executor submissions; cookie-only API denial and dashboard mutation rejection remain enforced |
| Browser request budgets | One 25-row filter page and four on-demand detail reads; NIST selection/expansion issues zero requests; history and graph reads carry the exact scan; no per-row or all-history client rollup |
| Server and client scaling | Existing [report query/side-effect tests](../tests/unit/services/test_technical_posture_service.py), [128/512 PostgreSQL aggregate plans](../tests/integration/test_technical_posture_postgres.py), [indexed exact history](../tests/integration/test_investigation_postgres.py) and [linear NIST indexing](../frontend/src/nist-api.test.ts) remain acceptance gates; not a latency SLA |
| Combined session clearing | Both browser engines exercise immediate two-tab clearing while logout is held, replacement identity with old-context 401, and real server expiry with completion synchronized to the expiry request |
| Hostile metadata and credentials | Text-only NIST/evidence, no navigated source URL, no Web Storage/readable session cookie or credential-bearing final URL; accepted token/CSRF/origin/allowlist/log redaction tests remain required |
| Accessibility | Both browser engines at 1280px and 390px: names/labels, landmarks, table captions/column semantics, keyboard controls/native disclosures, focus indicator, no page overflow, loading/status/error announcements; rendered representative text contrast >=4.5:1 and focus contrast >=3:1 |
| Baseline compatibility | Complete backend/PostgreSQL/frontend/browser suites and exact-head whole-Sprint-7 independent review; original catalogs/defaults, identifiers, services, auth, persistence and machine-readable API contracts remain unchanged |

The backend acceptance helper compares every mapping field by identity, normalizing the
accepted SQLite timestamp projection to UTC for comparison. PostgreSQL exception timestamps
must carry UTC explicitly. The browser uses PostgreSQL and must display unavailable eligibility
for missing/naive timestamps, as the accepted client contract requires.
Ordinary success paths are real responses; only selected adverse/held-response tests intercept
real fixture responses. There is no mock successful dashboard backend.

## Validation and review

The initial focused run passed 266 backend checks, including the four SQLite and four PostgreSQL
role stories. Initial helper import, ORM linkage, mapping ordering and SQLite timestamp assumptions
were corrected to the accepted contracts, without changing application behavior or weakening
existing tests. The 20 new Chromium/Firefox journeys passed after test-only corrections to a strict
combobox locator and the accepted 404 wording; replacement-identity reads are held deterministically
until old context is cleared. Typecheck, lint, 130 frontend unit tests and production build passed.

The first full harness passed 267 focused checks but stopped after 73 of 74 browser journeys:
an existing Firefox second-tab navigation waited past its load-event timeout despite rendering
the dashboard. That unchanged test then passed ten consecutive repetitions (39.3s). No timeout,
retry, assertion or application behavior was changed. A fresh complete harness passed all 267
focused checks, 130 frontend units, 74 browser journeys (1.7m), type/lint/build and Ruff/374-file
formatting. Complete regression then passed **2,741 tests**, including **287 PostgreSQL** cases,
with no skips and 19 existing SQLite migration deprecation warnings (609.82s). Whitespace,
Compose configuration and image build passed; only the owned disposable database was removed.
Fresh offline image inspection confirmed non-root runtime, built assets, and no Node/tests/issuer
in the final image. The accepted offline lifespan/health/auth smoke evidence is reused for
unchanged runtime behavior; this image inspection is not a new production or live-provider smoke.

Separate synthetic desktop/mobile visual checks verified real controlled login, PostgreSQL-backed
reads, historical investigation, logout, no console/page errors, no horizontal overflow and empty
Web Storage. Bundled axe reported zero violations and zero incomplete checks (42 passing checks
for the combined context; 46 for expanded investigation). Screenshots were inspected locally.
A Windows captured-output/background-browser pipe stalled the diagnostic wrapper; direct native
CLI checks completed, then the exact owned browser, fixture processes and database were closed.
This recovery is not claimed as a successful wrapper run or a production accessibility audit.

The single authorized whole-Sprint-7 reviewer returned REVIEW_PASS with zero unresolved findings
for initial head `31336a0`/tree `24bca246`. Independent checks passed 267 focused backend,
35 PostgreSQL and 130 frontend units/type/lint plus quality/migration gates. Complete full/browser/
image/visual results were inspected, not independently repeated in full.
[PR #50](https://github.com/jnc247s/cloud-security-automation/pull/50) published that exact head.
Both first exact-head CI runs subsequently failed at 73/74 browser journeys, before security
assertions: PR CI's new sibling-tab navigation and push CI's existing shell login waited past the
Firefox load event. No merge occurred. These failures invalidate browser acceptance of that head.

Navigation-wait experiments failed: DOMContentLoaded passed only 39/40 repetitions and commit
plus rendered UI only 38/40. Neither was accepted; every experiment was reverted, leaving the
original navigation and security assertions unchanged. The symptoms match the confirmed
[upstream Playwright 1.63 / Firefox build 1543 channel collision](https://github.com/microsoft/playwright/issues/42731)
when a COOP response replaces a browsing context in the same process. That protocol collision
was not instrumented locally; the diagnosis is supported by repeated rendered-view timeouts,
the exact pinned versions and the upstream report.

The bounded repair in [Playwright configuration](../frontend/playwright.config.ts) restores
Firefox's normal desktop site-isolation strategy (`fission.webContentIsolationStrategy=1`) in
the test launcher, instead of Playwright's override of zero. Chromium, dependencies, application
headers (including COOP), authentication, all assertions, thirty-second timeout and zero retries
are unchanged. Four original multi-tab/login journeys in both engines repeated five times each
passed **40/40 (1.3m)**. Fresh full validation, the same reviewer's exact-new-head follow-up and
both green new-head CI runs are required before merge. No final acceptance is inferred from the
initial review or the repetition alone.

### Repaired-input full validation

The fresh complete harness after the launcher repair passed **267 focused checks (113.77s)**,
frontend typecheck/lint/build and **130 units (2.81s)**, all **74 Chromium/Firefox journeys (1.7m)**,
Ruff/374-file formatting, and **2,741 backend tests (602.95s)** including **287 PostgreSQL** cases,
with no skips and 19 existing SQLite migration warnings. Documentation links, whitespace,
Compose configuration and image build passed. Only the harness-owned disposable database was
removed. Fresh network-disabled image inspection confirmed non-root runtime, built assets and
no Node/tests/controlled issuer. Unchanged offline lifespan/health/auth smoke and synthetic visual
evidence above remain applicable; no new live-provider, production or formal accessibility claim.

The same reviewer preliminarily verified the bounded repair, unchanged original assertions and
accurate failure/diagnosis limits. Independent typecheck/lint, 88 contracts (0.28s; no skips/warnings)
and whitespace passed without starting a competing fixture. The original four-file Git-filtered
core manifest remains `A27970801EC0178254BD8F5D80BE84B0EBDE7E1C12CFFE466397907E30D5E2F8`.
Including the launcher as a fifth technical file gives path/TAB/Git-blob-OID UTF-8/LF manifest
SHA256 `64CD2612DE7194D0FC34B746DBCC7C604D652E3DCB9FC17C2DD066765FF1DC6A`.
Final exact-commit review, both green new-head CI runs, guarded merge and green merged-main CI
remain required. 7E and Sprint 7 are still IN PROGRESS; PR #50 is not yet accepted or merged.

## Limits and safety

This is offline acceptance, not live AWS/Cognito/MFA/TLS or production deployment validation.
Only owned disposable PostgreSQL runtimes are used; generated secrets stay out of argv/logs,
and each browser-fixture server starts against a fresh database. Keys/credentials are generated
in memory; automated traces, screenshots and videos remain disabled. A separate synthetic
visual diagnostic is not a saved authenticated production session.

Accessibility evidence is scoped, not formal WCAG certification. Manual screen-reader testing
and comprehensive zoom/high-contrast/OS/device coverage remain unverified. Display truncation
is not full evidence review or a network-payload bound. Organization-wide READ trust, process-local
sessions/no global IdP logout, mutable operational reads, offset drift and unpaginated upstream
detail hydration remain documented in [known limitations](operations/known-limitations.md).
No tenant policy, rate limiter, distributed session store, supply-chain upgrade, remediation,
production operation or Sprint 8 implementation is added.
