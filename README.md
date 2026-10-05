# Cloud Security Control Plane

A Python service that collects read-only AWS configuration, evaluates deterministic technical
security controls, preserves evidence and assessment history in PostgreSQL, and exposes an
authenticated FastAPI interface and an opt-in read-only investigation dashboard.

The project performs **NIST CSF 2.0-aligned AWS technical security assessments**. It does not
provide certification or claim organization-wide NIST compliance.

## Status

Sprints 0 through 7 are COMPLETE and merged; all Sprint 7 slices, 7A--7E, are accepted.
Sprint 8 is NEXT only, not started. The accepted main checkpoint is
`b90bf08eeb79ba56d5308f19a942c6c10bf41b28`, after the reviewed Sprint 7 closeout.
Latest opt-in catalog `0.13.0` contains all 25
core controls plus supported legacy `S3-900`; the five-control default remains unchanged.
Whole-sprint 6H acceptance merged through
[PR #40](https://github.com/jnc247s/cloud-security-automation/pull/40), with exact-head independent
REVIEW_PASS and 2,533 regression tests (252 PostgreSQL, no skips), plus all quality/container gates.
[Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36954205010)
passed all 2,533 tests. The completed plan retains original predictions, implemented differences
and validation history. Sprint 7 is COMPLETE: 7A exact-scan READ reporting is COMPLETE,
merged through [PR #42](https://github.com/jnc247s/cloud-security-automation/pull/42).
7B is COMPLETE through [PR #43](https://github.com/jnc247s/cloud-security-automation/pull/43),
with independent review and green merged-main CI. Its opt-in read-only browser shell uses a
server-side OIDC session boundary, Cognito Essentials as target and a controlled local issuer
for tests. No live IdP resources, remediation or production deployment are implemented.
7C is COMPLETE through [PR #45](https://github.com/jnc247s/cloud-security-automation/pull/45) and
[test-only CI repair PR #46](https://github.com/jnc247s/cloud-security-automation/pull/46),
with zero unresolved independent-review findings and green exact-head and merged-main CI.
It adds bounded exact-scan
assessment/evidence/snapshot inspection, typed source/relationship navigation and separately
labeled current findings with server-time exception eligibility. 7D is COMPLETE through
[PR #48](https://github.com/jnc247s/cloud-security-automation/pull/48), using the existing
exact-scan report for retained NIST mapped-subset hierarchy, counts and provenance. Independent
review passed with zero unresolved findings; both exact-head CI runs and
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37248734936)
passed 2,731 backend tests (283 PostgreSQL, no skips), 130 frontend units, 54 Chromium/Firefox
journeys and quality/container gates. This is accepted code, not production deployment.
7D's documentary closeout is merged through
[PR #49](https://github.com/jnc247s/cloud-security-automation/pull/49), with green
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37251193595).
7E whole-sprint acceptance is COMPLETE through
[PR #50](https://github.com/jnc247s/cloud-security-automation/pull/50), with exact-head independent
REVIEW_PASS and zero unresolved findings, both green final-head CI runs, guarded ordinary merge
and green [merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37264941156)
at `7998e12786b817aa6de3abd63b37d22b5c4a99b6`. Acceptance passed 267 focused checks, 2,741 backend
tests (287 PostgreSQL, no skips), 130 frontend units, all 74 Chromium/Firefox journeys and
quality/container gates. A bounded pinned-Firefox test-launch isolation repair also passed 40
original multi-tab repetitions; application behavior/headers, dependencies, assertions, retries
and timeouts stayed unchanged. Failed runs and diagnostic limits are preserved in the
[acceptance evidence](docs/sprint-7e-acceptance.md). This is accepted offline code, not live-provider,
production deployment or formal accessibility certification. Sprint 8 is NEXT only and requires
its own preflight and separate implementation approval.
[ROADMAP.md](ROADMAP.md) alone owns progress; the
[completed Sprint 6 plan](docs/exec-plans/completed/sprint-6.md) records exact approvals and gates.
The [completed Sprint 7 plan](docs/exec-plans/completed/sprint-7.md) records exact scoped authority,
implementation differences and validation. The separate documentary closeout passed exact-head
independent review, both final-head CI runs and a guarded ordinary merge through
[PR #51](https://github.com/jnc247s/cloud-security-automation/pull/51).
[Final merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37268875724)
passed 2,741 backend tests (287 PostgreSQL, no skips), 130 frontend units, 74 browser journeys
and quality/image gates. The plan is archived, and all 7A--7E states are COMPLETE.
Historical test totals describe their respective accepted checkpoints;
the 7E results above are whole-Sprint-7 acceptance.

The accepted 7A endpoint is `GET /api/v1/scans/{scan_id}/technical-posture`, protected by the
existing READ capability. It returns exact historical four-state counts, control/target coverage
and version-bound mapped NIST context, without payloads, an overall result or a compliance score.
Running/no-bundle scans have unavailable counts; exceptions do not rewrite technical results.
See the [API contract](docs/api.md#exact-scan-technical-posture--7a). 7A introduced the reporting
foundation; the accepted opt-in 7B/7C/7D browser boundary builds on it.
Local 7A validation passed 182 focused checks and 2,601 regression tests (277 PostgreSQL,
no skips), plus quality/container gates. Independent review returned REVIEW_PASS with zero
unresolved findings after 157 independent checks and three additional diagnostics. The completed
plan records the exact-head review and human merge. [Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37161516904)
passed all 2,601 tests and quality/image gates. [7B preparation](docs/sprint-7b-preflight.md)
preserves the approved design and its original analysis. See [dashboard operation](docs/operations/dashboard.md)
for opt-in configuration, token/session handling, Cognito registration requirements and local tests.

Final local 7B checks passed: 205 focused checks, 2,676 regression tests (277 PostgreSQL,
no skips), 15 frontend units, 14 Chromium/Firefox journeys and quality/container/runtime gates.
Independent review passed with zero unresolved findings; explicit human merge approval and
both final-head CI runs passed. [Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37189473834)
passed the same 2,676 backend tests, 15 frontend units and 14 browser journeys plus quality/image
gates at `9ace4e65f15be678d3f05c4b5ef3a9896d4ea187`. This is accepted code, not a production
deployment. The completed plan records exact validation, publication and acceptance checkpoints.

7C acceptance passed 2,728 regression tests (283 PostgreSQL, no skips), 54 frontend units,
32 Chromium/Firefox journeys and quality/container gates. CI expiry-test ordering/completion races were
repaired without changing session behavior or weakening assertions; 20 repeated expiry journeys
also passed. Exact-head review passed for `39e9aef`. [Merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/37237604046)
passed every gate at `f10c450478cce3ec962d2f45d249f57147443c32`. The [acceptance checkpoint](docs/exec-plans/completed/sprint-7.md#7c-acceptance-and-documentary-closeout--2026-10-04)
records exact Git/validation evidence. The [7D preflight and acceptance record](docs/sprint-7d-preflight.md)
preserves the approved client-only scope and implementation differences. 7D is COMPLETE at
`8f58b2716a726fcefc5d89567b0dff882f7502ea`; exact mapped releases and coverage remain separate
from technical results. The [7D acceptance checkpoint](docs/exec-plans/completed/sprint-7.md#7d-acceptance-and-documentary-closeout--2026-10-04)
records review, validation and merge evidence. Subsequent 7E whole-sprint acceptance is COMPLETE;
the archived plan and evidence matrix supersede earlier pending checkpoints.
Production setup is unimplemented.

The current implementation includes:

- FastAPI health/readiness, centralized configuration, PostgreSQL/SQLAlchemy/Alembic, Compose,
  pytest, Ruff, and GitHub Actions;
- standard-chain boto3 authentication, STS identity, and fact-only IAM account, identity, policy,
  Access Analyzer, security-group, VPC, subnet, VPC Flow Log, S3, CloudTrail, EC2-instance,
  EBS-volume, Regional EBS-default, expanded S3, and referenced-KMS collection;
- deterministic four-state assessment with structured evidence, versioned profiles and control
  contracts, and checksum-validated NIST CSF 2.0 mapping metadata;
- immutable resource snapshots, scan scope, assessments, evidence, deduplicated findings and
  occurrences, explicit exceptions, and append-only audit history;
- OIDC/JWT authentication, development-auth safeguards, role/capability authorization, and
  versioned APIs for scans, resources/history, assessments, findings, controls, frameworks, and
  exceptions;
- an opt-in same-origin dashboard with server-side OIDC sessions, exact-scan evidence/history
  investigation, retained NIST mapped-subset context, and separate current finding/exception
  handling; browser reads cross the real bearer/READ API and cannot execute scans or mutations;
- durable HTTP 202 scan creation backed by a bounded, replaceable in-process executor; and
- generic immutable source-outcome/artifact and relationship history, populated by the accepted
  5A EC2/EBS, 5B network-evidence, 5C IAM, 5D Access Analyzer, 5E S3/KMS, and 5F CloudTrail
  producers.

The default catalog remains `aws-cloud-security-controls/0.2.1` with `IAM-001`, `LOG-001`,
`NET-001`, `NET-002`, and legacy non-core `S3-900`. New Sprint 6 controls are available only
through explicit, versioned catalog/profile selection. The opt-in releases are cumulative:

| Catalog | Controls added | State |
| --- | --- | --- |
| `0.3.0` | `IAM-002`, `IAM-003`, `IAM-005`, `IAM-006` | Accepted |
| `0.4.0` | `IAM-004` | Accepted |
| `0.5.0` | `EC2-001` through `EC2-004` | Accepted |
| `0.6.0` | `NET-003`, `NET-004`, `NET-005` | Accepted |
| `0.7.0` | `NET-006` | Accepted |
| `0.8.0` | `S3-001`, `S3-003` | Accepted |
| `0.9.0` | `S3-002` | Accepted |
| `0.10.0` | `S3-004` | Accepted |
| `0.11.0` | `LOG-002`, `LOG-003` | Accepted through PR #37; merged-main CI passed |
| `0.12.0` | `LOG-004` | Accepted through PR #38; merged-main CI passed |
| `0.13.0` | `GOV-001` | Accepted through PR #39; merged-main CI passed |

See the [control catalog](docs/controls/catalog.md) for authoritative meanings, versions, evidence
contracts, and policy boundaries. Access Analyzer findings remain supplementary facts and do not
decide `S3-002`. LOG-002/003 are accepted and require explicit opt-in selection;
see [6F.1 metadata](docs/controls/sprint-6f1-metadata.md). `LOG-004` is accepted;
`GOV-001` is accepted in opt-in catalog `0.13.0`. It checks the exact required
`Owner` and `Environment` tags across 11 explicitly governed resource families, with complete
source proofs; see [6G metadata](docs/controls/sprint-6g-metadata.md) and the
[initial opt-in profile](docs/controls/examples/sprint-6g-initial-profile.json).
LOG-004 composes only a validated same-scan S3-002
assessment for the exact destination bucket; missing/disabled dependencies cannot pass.
See [6F.2 metadata](docs/controls/sprint-6f2-metadata.md). Existing `LOG-001` behavior is unchanged.
The [6H acceptance record](docs/controls/sprint-6h-acceptance.md) records accepted combined-control,
historical-release recovery and authenticated API validation and documentary closure.

Key operating limits include one API process and one Region per request; cross-account assume-role
and full multi-region orchestration are not implemented. The deployment is one trust domain: all
recognized roles can read its security data, and query filters are not object- or account-level
authorization. The opt-in dashboard shell, investigation and NIST context are accepted
7B/7C/7D code,
not a production deployment. Acceptance does not authorize live operations.
No production Terraform, governance mutation API, remediation,
distributed worker, or AI runtime exists yet. AWS resources are never modified. See
[known limitations](docs/operations/known-limitations.md) before production use.

## Documentation

| Source | Responsibility |
| --- | --- |
| [AGENTS.md](AGENTS.md) | Permanent development, validation, Git, and safety rules |
| [ROADMAP.md](ROADMAP.md) | Canonical sprint state and transition protocol |
| [PRODUCT_REQUIREMENTS.md](PRODUCT_REQUIREMENTS.md) | Stable product requirements and non-goals |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Accepted technical architecture and current boundaries |
| [SECURITY.md](SECURITY.md) | Authentication, authorization, secrets, least privilege, and production safety |
| [THREAT_MODEL.md](THREAT_MODEL.md) | Threats, controls, assumptions, and residual risks |
| [CHANGELOG.md](CHANGELOG.md) | Accepted implementation history |
| [docs/api.md](docs/api.md) | Authoritative API behavior, filters, lifecycle, and errors |
| [docs/assessment-framework.md](docs/assessment-framework.md) | Assessment, evidence, profile, and control contracts |
| [docs/frameworks/nist-csf-2.0.md](docs/frameworks/nist-csf-2.0.md) | NIST source and mapping integrity |
| [docs/controls/catalog.md](docs/controls/catalog.md) | Implemented controls and permanent control-ID meanings |
| [docs/persistence.md](docs/persistence.md) | Data model, history, transactions, and migrations |
| [docs/operations/aws-inventory.md](docs/operations/aws-inventory.md) | AWS permissions and inventory operation |
| [docs/operations/dashboard.md](docs/operations/dashboard.md) | Opt-in dashboard configuration, sessions, investigation, and browser validation |
| [docs/operations/known-limitations.md](docs/operations/known-limitations.md) | Accepted limitations requiring follow-up |
| [docs/sprint-7e-acceptance.md](docs/sprint-7e-acceptance.md) | Whole-Sprint-7 acceptance evidence, review/merge receipts, and validation limits |

## Repository structure

```text
.
├── AGENTS.md
├── ROADMAP.md
├── ARCHITECTURE.md
├── PRODUCT_REQUIREMENTS.md
├── SECURITY.md
├── THREAT_MODEL.md
├── CHANGELOG.md
├── app/
│   ├── api/                 # Health and authenticated versioned routes
│   ├── assessment/          # Profiles, evidence, control and framework contracts
│   ├── aws/                 # Lazy sessions, clients, and STS identity
│   ├── collectors/          # Fact-only AWS collectors
│   ├── dashboard/           # Opt-in OIDC sessions and explicit read-only BFF
│   ├── database/            # Validation, transactions, persistence, and governance
│   ├── logging/             # Central logging configuration
│   ├── models/              # SQLAlchemy history and lifecycle records
│   ├── remediation/         # Reserved; no remediation implementation exists
│   ├── rules/               # Deterministic technical controls
│   ├── schemas/             # Inventory, persistence, and HTTP contracts
│   ├── security/            # Authentication and capability policy
│   └── services/            # Inventory, query, and scan-executor boundaries
├── alembic/                 # Linear, reviewed database migrations
├── alembic.ini
├── docs/
│   ├── api.md
│   ├── assessment-framework.md
│   ├── persistence.md
│   ├── controls/
│   ├── design-decisions/
│   ├── exec-plans/active/
│   ├── exec-plans/completed/
│   ├── frameworks/
│   └── operations/
├── scripts/
│   ├── run_inventory.py
│   └── validate.py
├── tests/
├── frontend/                # Pinned React/TypeScript dashboard and browser acceptance
├── terraform/               # Placeholder only; no infrastructure exists
├── .github/workflows/ci.yml
├── docker-compose.yml
├── Dockerfile
└── pyproject.toml
```

## Local Python setup

Python 3.12 or later is required.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

On macOS/Linux, activate with `source .venv/bin/activate` and copy with
`cp .env.example .env`.

Start PostgreSQL, apply migrations, and run the API:

```powershell
docker compose up -d db
alembic upgrade head
uvicorn app.main:app --reload
```

- Liveness: [http://localhost:8000/health](http://localhost:8000/health)
- Readiness: [http://localhost:8000/ready](http://localhost:8000/ready)
- OpenAPI: [http://localhost:8000/docs](http://localhost:8000/docs)

Every `/api/v1` operation needs a bearer token. With the example local-only configuration, select
**Authorize** in OpenAPI and enter `local-development`. Production must use the OIDC settings in
[the API guide](docs/api.md#authentication).

`/ready` checks database connectivity only. Apply migrations before using persistence; startup
does not create tables automatically.

## Docker Compose

```powershell
Copy-Item .env.example .env
docker compose up --build
```

Compose waits for PostgreSQL, runs `alembic upgrade head`, and then starts one API process. API and
database ports bind to loopback by default. Example passwords are local placeholders and must not
be reused in production.

Compose deliberately does not mount host AWS credentials. An API scan requires an explicitly
supplied read-only workload credential chain. The current executor supports one API process; read
[known limitations](docs/operations/known-limitations.md) before changing topology or policy
settings.

Stop with `docker compose down`. The PostgreSQL volume remains. Use
`docker compose down --volumes` only when intentionally deleting local database data.

## Run an inventory or scan

For an independent read-only inventory check with IAM Identity Center:

```powershell
aws sso login --profile security-audit
$env:AWS_PROFILE = "security-audit"
$env:AWS_REGION = "us-east-1"
aws sts get-caller-identity --profile security-audit
python scripts/run_inventory.py
```

The command prints a sanitized aggregate summary; it does not evaluate controls or persist data.
See [AWS inventory operations](docs/operations/aws-inventory.md) for the exact calls and policy.

With the API process configured for AWS and local development authentication, an `ADMIN` can
submit a scan:

```powershell
$headers = @{ Authorization = "Bearer local-development" }
$scan = Invoke-RestMethod -Method Post `
  -Uri http://localhost:8000/api/v1/scans `
  -Headers $headers -ContentType application/json `
  -Body '{"region":"us-east-1"}'
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/$($scan.scan_id)" -Headers $headers
```

The POST returns HTTP 202 after persisting the scan identity. The account always comes from STS.
Poll the scan, then query resources, assessments, and findings through the documented API.

## Read-only dashboard

The dashboard is disabled by default. Accepted functionality includes explicit historical scan
selection, evidence/snapshot/source/relationship investigation, retained NIST technical context,
and separately labeled current finding/exception handling. It does not provide a compliance
score, scan execution or remediation.

Follow [dashboard operation](docs/operations/dashboard.md) for pinned frontend tooling,
asset builds, explicit OIDC/origin/session configuration and controlled local validation.
Enabling the dashboard does not permit development-bearer fallback or validate a live Cognito
pool, MFA, ingress/TLS or production deployment. Live registration and production operations
require separate authorization; do not expose the controlled test issuer publicly.

## Tests and quality

For the complete backend and dashboard acceptance pipeline, use Docker, development dependencies,
the pinned Node/pnpm tooling and installed Chromium/Firefox builds described in
[dashboard validation](docs/operations/dashboard.md#reproducible-validation):

```powershell
.\.venv\Scripts\python.exe -m scripts.validate --dashboard
```

Optionally run the 6E.3 checks first with:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate --focused `
  tests/unit/rules/test_s3_sensitive_kms.py `
  tests/unit/database/test_s3_sensitive_kms.py `
  tests/integration/test_s3_sensitive_kms_postgres.py
```

The runner always performs Ruff, formatting, the full regression (including PostgreSQL and
Markdown/link contracts), whitespace checks, Compose validation and the image build.
`--dashboard` also runs frontend typecheck/lint/unit/build and real controlled-issuer browser
acceptance; omitting it runs the backend/container pipeline only. It creates
its own loopback-only PostgreSQL 16 container with a random password and temporary memory-backed
storage; it never uses your configured database URL. The test container is removed on success or
ordinary failure, and failures return a nonzero exit status. Your application/database containers
are untouched. The local `cloud-security-automation:validation` image/cache is retained.
Force-killing the runner or losing the Docker daemon can prevent cleanup; the uniquely named
`cloudsec-validation-*` container is labeled with its exact name for manual identification.
Do not use broad Docker cleanup commands. This command does not commit, push, merge or deploy.

Default tests use fake AWS clients and migrated SQLite databases. PostgreSQL tests run only when
`TEST_DATABASE_URL` points to a dedicated disposable test database; CI supplies PostgreSQL 16.

```powershell
python -m ruff check .
python -m ruff format --check .
python -m pytest
docker compose config --quiet
```

The PostgreSQL role used by integration tests must be able to create/drop its isolated generated
schema. Never point `TEST_DATABASE_URL` at production. See
[persistence tests](docs/persistence.md#tests).

## Configuration safety

Configuration comes from environment variables and optional local `.env`; the example documents
all fields. Never put AWS keys, bearer tokens, OIDC secrets, database production passwords, or
other credentials in `.env` or Git.

With `ASSESSMENT_PROFILE_FILE` unset, `ASSESSMENT_PROFILE_VERSION` selects the immutable `default`
policy definition built from the environment and must be a numeric `X.Y.Z` value. An existing
deployment with unchanged `REQUIRED_TAGS` and `STALE_ACCESS_KEY_DAYS` can retain version `1.0.0`.
Whenever either policy setting changes, choose and deploy a new reviewed profile version at the
same time—for example, move from `1.0.0` to `1.1.0`. Reusing an existing version with different
policy content is rejected with a sanitized HTTP 409 response; stored profiles and historical
scans are never overwritten.

Pending scans retain the exact profile selected when they were created. A restarted executor
loads that persisted definition instead of rebuilding it from the deployment's current
environment. This roll-forward requires no database migration because the existing schema already
stores complete legacy profile content and scan provenance. The additive 6A schema extension
requires migration `20260924_0004`.
The local 6F.1 release also adds `20261001_0005` for unresolved relationship persistence;
apply current migrations only to an explicitly authorized environment. See
[persistence recovery guidance](docs/operations/known-limitations.md#unresolved-regional-relationship-persistence--repaired).
Accepted 6G adds `20261001_0006` for the governance category. This remains the migration head
after Sprint 7; apply the full reviewed migration chain rather than stopping at an older slice.

When `ASSESSMENT_PROFILE_FILE` is unset, the service retains the legacy-compatible default catalog
`0.2.1`. In file mode, a protected local envelope selects an exact registered catalog and contains
a complete checksum-bearing profile whose embedded version must match
`ASSESSMENT_PROFILE_VERSION`. Legacy and schema-2 profiles are supported, but controls that need
extension policy—including S3-004—require schema 2. Use a new immutable profile version whenever
policy content or enabled-control membership changes. The file wholly owns its policy inputs;
`REQUIRED_TAGS` and `STALE_ACCESS_KEY_DAYS` do not merge into it. See
[versioned assessment configuration](docs/assessment-foundation.md) for the complete contract.
