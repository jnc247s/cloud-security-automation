# Sprint 8B3.3 installed worker acceptance preflight

Prepared: 2026-10-12. Analysis complete; test implementation has not started at this checkpoint.

Recommend one complete test-only slice for installed-image, separate-process and security
acceptance, followed by 8B closeout. Start with the signed end-to-end process journey and its
strict transport/database guards, then complete every negative and recovery family below.
No new product architectural or design decision is identified. Standing Sprint 8 workflow
authority applies within the accepted design; it does not authorize a live operation.
[ROADMAP](../ROADMAP.md) owns status and the [active plan](exec-plans/active/sprint-8.md)
owns approved task detail.

## Accepted entry and scope

Clean main was normally fast-forwarded to `489b047562005a766734e9b571f7e307f8506102`,
tree `b6d202329f11dbc76b02db72fb3a00c7083126bb`, only after the complete first-attempt
[exact-main CI 38308762804](https://github.com/jnc247s/cloud-security-automation/actions/runs/38308762804)
audit passed. [PR #65](https://github.com/jnc247s/cloud-security-automation/pull/65) closes the
8B3.2 documentary prerequisite after immutable-head REVIEW_PASS, both candidate CI passes
and an ordinary exact-head guarded merge. Its parents are accepted test baseline `9c3df32`
and reviewed documentary head `a050d70`. These results are baseline evidence, not acceptance
of proposed process tests.

Sprints 0--7, 8A, 8B1, 8B2, 8B3.1 and 8B3.2 are COMPLETE. Sprint 8/8B/8B3 remain IN PROGRESS;
8B3.3 and 8C--8E remain PLANNED; Sprint 9+ is unstarted. Runtime baseline `7a36ddde`, migration
`20261008_0009`, opt-in catalog `0.13.0`, default catalog `0.2.1` and profile `1.0.0` are unchanged.
The new scoped branch is `codex/sprint-8b33-preflight`. All 500 starting tracked hashes matched
the reviewed tree; the existing 73 branches, three worktrees and three unrelated parent skill
files were preserved. Only accepted local main advances and one analysis branch is added.

Scope remains EC2-004, `aws.ec2.enable-ebs-encryption-by-default` / `1.0.0`, false to true only.
Keep three distinct verified PROPOSE/APPROVE/EXECUTE human identities, without ADMIN bypass,
and separate worker service attribution. Scanner credentials remain read-only. No additional
handler, credential source, worker API, production test mode, endpoint override, schema change,
rescan, dashboard mutation, general scan-start UI or operational enablement belongs here.

## Contracts and existing coverage

| Boundary | Existing contract and process-test consequence |
| --- | --- |
| Entrypoint and configuration | `app/remediation/worker.py` is the separate one-job module; `WorkerSettings` is environment-only, independent of `.env` and scanner/application settings. Default-off returns before engine/provider construction. Enabled mode requires explicit account, Region, expected IAM role and PostgreSQL URL. Preserve exact arguments, classifications, exit codes and sanitized output. Existing process tests call `main` in-process, not a fresh enabled installed process. |
| Packaging and startup | The non-root `Dockerfile` installs application/migrations and defaults to the API command; tests/scripts are excluded from production packaging. Compose and API/scanner caller searches contain no worker construction/start path. Keep them unchanged. A narrow read-only mounted test harness may intercept transport before invoking the unchanged installed module entrypoint, as the governing 8B3 preflight already permits. |
| Exclusive writer | `worker_aws.py` uses the real ECS-relative-only temporary provider, built-in SDK models/endpoints, fixed regional STS/EC2, explicit timeouts/proxies and one total SDK write attempt. Host/static/profile/web-identity/full-URI/endpoint/CA/model-path fallback is rejected. Metadata read retries are separately bounded; do not confuse them with write retries. |
| SQL and audit | `RemediationWorkerService` locks admission guard, Resource, Finding, proposal, target and claim; it refreshes time after waits. The driver closes worker sessions before factory, STS, EC2 and shutdown. WRITE_INTENT and paired service audit commit before dispatch. Existing PostgreSQL NOWAIT probes cover the whole lock set; process tests must independently check committed state and lock availability. |
| Signed authority and history | `tests/worker_http.py` supplies real signed production-mode HTTP, migrated evidence, exact history/digest/audit assertions and full protected-table comparisons. Its API/PostgreSQL wrappers cover all seven present/absent/exact legacy-key and changed-precondition cases. The controlled issuer supplies test keys/JWKS, not authentication dependency overrides. Preserve these callers and strict defaults. |
| Faults and recovery | Accepted `worker_fault_http.py` and API/PostgreSQL fault wrappers cover signed authority, actual SDK transport, ownership/lock races, uncertain effects and persisted budgets. Retain their seven-family matrix and repaired strict-newer/governance/capacity guards. Fresh-process recovery complements that evidence; it must not replace it with a smaller passing subset. |
| Findings and scanning | Normal scan persistence owns sufficient, explicit completed-PASS reconciliation. Neither process output, acknowledgment nor readback creates a scan, verifies remediation or changes technical/finding state. Exact-policy linked verification remains 8C; browser workflow and reported navigation/layout issues remain 8D. |

The analysis follows the root architecture/security requirements, relevant API/persistence/threat
sections, remediation/limitation runbooks, approved 8B design and 8B3/8B3.2 preflights. Code and
tests are implemented-behavior evidence, not authority to change those contracts.

## Complete acceptance matrix

| Family | Required evidence before accepting 8B3.3 |
| --- | --- |
| Installed signed journey first | Persist complete EC2-004 FAIL evidence, then create proposal, independent approval and third-human admission through signed bearer HTTP. Run the unchanged installed module in a fresh process with the real worker/closed adapter and intercepted synthetic metadata/STS/EC2. Cover expected absence, ARN and exact legacy non-ARN key contexts; require committed intent/audit before exactly one enable send, then ACKNOWLEDGED_UNVERIFIED and signed READ/replay fidelity. |
| No-write and identity | Cover already-enabled, changed/missing/unexpected key, wrong account/role/Region and incomplete/malformed settings/identity. Require the exact blocker and zero enable invocations/sends, not merely a nonzero exit. Capture the complete operation sequence and reject unused or unexpected responses. Preserve strict boolean and exact key/absence semantics. |
| Sources and configuration | Carry forbidden source/endpoint/CA/model-path families into process-level negatives, including empty values, missing/malformed relative ECS paths and malformed/unavailable metadata. Default-off, help/invalid arguments, missing scope/database, non-PostgreSQL URLs and synthetic `.env`/scanner fallback traps must demonstrate the intended pre-construction cutoff. No host credential file or metadata endpoint is consulted. |
| Process output and leakage | Cross-check fixed worker stdout/exit status, empty worker stderr and suppressed dependency debug/warning/error output against synthetic sensitive argument, configuration, SQL and provider sentinels. Keep credentials, signed headers, tokens, URLs and evidence out of reports. A generic WORKER_UNAVAILABLE is not proof of no AWS effect; use durable history and exact transport counts. |
| Separate-process recovery | Terminate only a deliberately owned synthetic worker at a demonstrated post-intent boundary, and exercise ambiguous transport/receipt recovery through a new process. Require no repeat enable, no post-intent owner reclaim, sticky quarantine/reservation/capacity, immutable grant and durable global observation budget/window. True observation does not clear quarantine. Keep the accepted expiry/race/fencing suite and do not fabricate hard cancellation or AWS CAS. |
| Independence and integrity | Prove installed application paths/source fingerprints, actual Python/SDK versions, non-root/read-only/no-new-privileges runtime and narrow mounts. Probe worker transaction closure/committed paired audit independently of its self-report. Signed history excludes private claims; READ/replay and API/scanner startup cannot construct/dispatch the writer. Complete protected-table comparisons permit only declared remediation coordination/journal/audit deltas. |
| Packaging and full acceptance | Preserve Compose/default-off startup, current migration/history/auth/service/scanner contracts, all backend/PostgreSQL and frontend/browser regression. Reconcile complete 8B evidence and residual limits only after exact-commit independent review, both candidate CI passes, ordinary guarded merge and green exact-main CI. Do not mark 8B/Sprint 8 complete from the first successful process journey. |

## Test isolation and implementation order

Use a focused private process harness/orchestrator and PostgreSQL integration wrapper, for example
`tests/worker_process_harness.py`, `tests/worker_process_http.py` and
`tests/integration/test_remediation_worker_process_postgres.py`, plus small harness guard tests
where needed. Reuse signed headers, retained evidence, migration configuration and protected
history projections. Factor an existing helper only if necessary, preserving all callers atomically.
No application, dependency, migration, frontend, IAM or CI edit is predicted.

The orchestrator owns a fresh UUID-labelled test stack: exact built image, internal Docker
network, tmpfs PostgreSQL 16 and bounded ephemeral worker processes. Verify a local Linux Docker
endpoint before provisioning; inherited remote TCP/SSH contexts are not permitted test targets.
Derive loopback parent and private child database URLs from those owned handles; migrate only the
owned database/schema
through Alembic to 0009. Never derive a worker target by rewriting an arbitrary operator URL,
attach to an unrelated container, use host networking or mount the Docker socket/host credential
store. Keep passwords in child environments, not argv or logs. Mount only the explicitly selected
test harness/scenario files read-only; do not shadow installed application/SDK modules.

Arm strict synthetic transport interception before entering the installed module. Every unexpected
destination/operation, missing interception, wrong sequence or unused response must fail the parent
test even if the worker sanitizes the resulting exception. Keep worker output separate from bounded
test proof counters; independent database and source checks must corroborate the counters.
Do not replace the worker, adapter, authorization, journal or scan persistence with fakes.

Begin with resource ownership/cleanup guards and the signed installed success/no-write journey.
Then add source/configuration/leakage negatives and fresh-process conservative recovery, followed
by the complete acceptance audit and owner documentation. Required configured integration/full-CI
environments must run the process tests; missing Docker or process coverage is a failed gate, not
an unjustified skip. Unconfigured local integration remains unaccepted, as before.
Remove only exact owned containers/networks/temp paths on every outcome; preserve a primary test
failure if cleanup also fails and report cleanup failure without printing sensitive input.

## Risks compatibility and decisions

Principal risks are an unarmed/misrouting interceptor, testing host rather than installed code,
shadowed SDK models, an overbroad mount/environment, connecting a child to the wrong schema,
masked worker/cleanup failures, incomplete process proof and false repair claims. Use strict
queues, immutable image/source identity, explicit resource ownership, bounded subprocess waits,
independent PostgreSQL probes and complete before/after comparisons. Test-container restrictions
do not prove deployed ECS task/host/network/IAM isolation or distinct physical humans.

No established interface change is predicted. Preserve routes/status codes, constructors/enums,
v1/v2 event bytes, private coordination, profile/catalog/control IDs and default behavior. Migration
0009 remains schema-before-code even while disabled; no operator rollout/migration is authorized.
Report fresh actual installed versions; native SDK 1.43.87 and prior image/CI SDK 1.43.112 are
different environments, not interchangeable proof. Backend ranges/base-image tags remain mutable.

The 24-hour proposal, five-minute capped grant, intent cutoff, fenced pre-intent ownership,
three-read budget and three-poll/thirty-second recovery remain unchanged. No post-intent resend,
TTL unlock, automatic rollback, force-clear or new success definition is allowed. AWS has no
accepted CAS/hard-cancellation guarantee; key/workload usability remains human review.
Stop for explicit approval if a reproduced defect requires changed authority, credential source,
runtime topology, public API/schema, retry/release policy, cancellation or verification semantics.
Routine test-only work and bounded accepted-design repairs remain covered by standing authority.

The old artifact-free main Firefox cause remains unconfirmed; the demonstrated application
layout/pointer race remains unfixed and the original scan-picker/back-navigation report untriaged.
The interrupted old native result remains unverified. Preserve these limitations and historical
failed receipts; Linux passes and a process harness are not UI, live-provider or deployment fixes.

## Validation and approval boundary

Run new targeted process/harness checks and affected old signed API/worker/auth/history/migration
checks first, then `python -m ruff check .`, `python -m ruff format --check .` and complete
`python -m pytest` with explicit fresh disposable PostgreSQL. Validate Compose and exact packaged
image, full pinned frontend type/lint/unit/build and all 76 Chromium/Firefox journeys with one
worker, zero retries and no skipped acceptance. Record actual collected counts and complete
primary logs; baseline totals cannot substitute for the expanded suite.

Freeze the exact candidate for the existing authorized reviewer; resolve actionable findings,
require both first-attempt final-head CI runs, ordinary expected-head guarded merge and complete
exact-main CI. Only then reconcile 8B3.3/8B3/8B acceptance and begin 8C's separate preflight.
8C--8E and whole Sprint 8 remain required; Sprint 9+ stays unstarted.

This checkpoint changes analysis/progress Markdown only. No test/runtime implementation, enabled
worker run, database/container provisioning, reviewer launch, commit, publication or next-stage
acceptance is performed by the analysis. Its lightweight validation receipt belongs in the active
plan. Standing accepted-design implementation is already requested by the Sprint 8 goal;
new architectural/design decisions, live AWS/IdP/IAM/secrets, deployment, operator databases and
production operations are not pre-approved.
