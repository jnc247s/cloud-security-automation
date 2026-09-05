# Cloud Security Control Plane

A Python service that collects read-only AWS configuration, evaluates deterministic technical
security controls, preserves evidence and assessment history in PostgreSQL, and exposes an
authenticated FastAPI interface.

The project performs **NIST CSF 2.0-aligned AWS technical security assessments**. It does not
provide certification or claim organization-wide NIST compliance.

## Status

Sprints 0 through 4 are complete and merged. **Sprint 5 — AWS Evidence Expansion** is `NEXT` and
has not begun. [ROADMAP.md](ROADMAP.md) is the only authoritative progress source.

The accepted baseline includes:

- FastAPI health/readiness, centralized configuration, PostgreSQL/SQLAlchemy/Alembic, Compose,
  pytest, Ruff, and GitHub Actions;
- standard-chain boto3 authentication, STS identity, and fact-only IAM-user, security-group, S3,
  and CloudTrail collectors;
- deterministic four-state assessment with structured evidence, versioned profiles and control
  contracts, and checksum-validated NIST CSF 2.0 mapping metadata;
- immutable resource snapshots, scan scope, assessments, evidence, deduplicated findings and
  occurrences, explicit exceptions, and append-only audit history;
- OIDC/JWT authentication, development-auth safeguards, role/capability authorization, and
  versioned APIs for scans, resources/history, assessments, findings, controls, frameworks, and
  exceptions; and
- durable HTTP 202 scan creation backed by a bounded, replaceable in-process executor.

Current controls are `IAM-001`, `LOG-001`, `NET-001`, `NET-002`, and legacy non-core `S3-900`.
Canonical `S3-001` through `S3-004` are reserved for later roadmap meanings and are not
implemented.

No Terraform deployment, dashboard, remediation, or AI functionality exists yet. AWS resources
are never modified.

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
├── scripts/run_inventory.py
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

The accepted baseline constructs immutable profile `default` version `1.0.0` from
`REQUIRED_TAGS` and `STALE_ACCESS_KEY_DAYS`. Keep those values stable for an existing database
until an explicit profile roll-forward workflow is implemented.
