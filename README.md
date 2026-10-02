# Cloud Security Control Plane

A Python service that collects read-only AWS configuration, evaluates deterministic technical
security controls, preserves evidence and assessment history in PostgreSQL, and exposes an
authenticated FastAPI interface.

The project performs **NIST CSF 2.0-aligned AWS technical security assessments**. It does not
provide certification or claim organization-wide NIST compliance.

## Status

Sprints 0 through 5 are complete and merged. The
[completed Sprint 5 plan](docs/exec-plans/completed/sprint-5.md) records its accepted evidence
expansion and retained limitations. Sprint 6 is `IN PROGRESS`: slices 6A through 6F are complete
and merged. Slice 6E.3 added S3-004 through pull request 35; its independent review and
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36825207102)
passed. Slice 6F.1 (LOG-002/003) has passed local implementation acceptance checks,
including its explicitly approved [persistence repair](docs/controls/sprint-6f1-metadata.md).
All 2,125 regression tests pass, including 171 PostgreSQL cases, with no skips; quality and
container gates pass. Independent review passed with zero unresolved findings. The reviewed
implementation merged in [pull request #37](https://github.com/jnc247s/cloud-security-automation/pull/37);
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36930583998)
passed all 2,125 tests and quality/image gates. LOG-004/6F.2 subsequently merged in
[PR #38](https://github.com/jnc247s/cloud-security-automation/pull/38), with independent REVIEW_PASS,
355 focused checks and 2,212 full tests (201 PostgreSQL, no skips). Both final-head CI runs and
[merged-main CI](https://github.com/jnc247s/cloud-security-automation/actions/runs/36938144756)
passed. GOV-001/6G is authorized and in progress; 6H is authorized but unstarted.
[ROADMAP.md](ROADMAP.md) is the only authoritative
progress source.

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
| `0.13.0` | `GOV-001` | Published in PR #39; final CI/acceptance pending |

See the [control catalog](docs/controls/catalog.md) for authoritative meanings, versions, evidence
contracts, and policy boundaries. Access Analyzer findings remain supplementary facts and do not
decide `S3-002`. LOG-002/003 are accepted and require explicit opt-in selection;
see [6F.1 metadata](docs/controls/sprint-6f1-metadata.md). `LOG-004` is accepted;
`GOV-001` is locally implemented and in progress, not yet accepted. It checks the exact required
`Owner` and `Environment` tags across 11 explicitly governed resource families, with complete
source proofs; see [6G metadata](docs/controls/sprint-6g-metadata.md) and the
[initial opt-in profile](docs/controls/examples/sprint-6g-initial-profile.json).
LOG-004 composes only a validated same-scan S3-002
assessment for the exact destination bucket; missing/disabled dependencies cannot pass.
See [6F.2 metadata](docs/controls/sprint-6f2-metadata.md). Existing `LOG-001` behavior is unchanged.

Key operating limits include one API process and one Region per request; cross-account assume-role
and full multi-region orchestration are not implemented. The deployment is one trust domain: all
recognized roles can read its security data, and query filters are not object- or account-level
authorization. No production Terraform, dashboard, governance mutation API, remediation,
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
| [docs/operations/known-limitations.md](docs/operations/known-limitations.md) | Accepted limitations requiring follow-up |

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

## Tests and quality

For the complete local acceptance pipeline with Docker running and development dependencies
installed, use:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate
```

Optionally run the 6E.3 checks first with:

```powershell
.\.venv\Scripts\python.exe -m scripts.validate --focused `
  tests/unit/rules/test_s3_sensitive_kms.py `
  tests/unit/database/test_s3_sensitive_kms.py `
  tests/integration/test_s3_sensitive_kms_postgres.py
```

The runner always performs Ruff, formatting, the full regression (including PostgreSQL and
Markdown/link contracts), whitespace checks, Compose validation and the image build. It creates
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

When `ASSESSMENT_PROFILE_FILE` is unset, the service retains the legacy-compatible default catalog
`0.2.1`. In file mode, a protected local envelope selects an exact registered catalog and contains
a complete checksum-bearing profile whose embedded version must match
`ASSESSMENT_PROFILE_VERSION`. Legacy and schema-2 profiles are supported, but controls that need
extension policy—including S3-004—require schema 2. Use a new immutable profile version whenever
policy content or enabled-control membership changes. The file wholly owns its policy inputs;
`REQUIRED_TAGS` and `STALE_ACCESS_KEY_DAYS` do not merge into it. See
[versioned assessment configuration](docs/assessment-foundation.md) for the complete contract.
