# Cloud Security Control Plane

A production-style Python service for discovering AWS resources and evaluating them with
evidence-based security controls, with durable scan and finding lifecycle state in PostgreSQL.

## Project status

**Sprint 3 — Persistence and Scan Lifecycle**

Available now:

- FastAPI liveness (`GET /health`) and PostgreSQL readiness (`GET /ready`) endpoints
- Environment-based application and AWS configuration
- Lazy boto3 sessions and cached clients using the standard AWS credential chain
- A cached STS caller identity with bounded client timeouts and standard retries
- Paginated, fact-only collectors for:
  - EC2 security groups and ingress/egress rules
  - S3 buckets, tags, default encryption, and public-access-block configuration
  - IAM users, MFA devices, and access-key metadata
  - CloudTrail trails, tags, home regions, and logging status
- A normalized, JSON-serializable in-memory inventory model
- An inventory orchestration service and command-line summary
- A side-effect-free rule engine, duplicate-safe rule registry, and validated finding candidates
- Exactly five deterministic controls:
  - `NET-001` — public SSH exposure
  - `NET-002` — public RDP exposure
  - `S3-002` — missing bucket encryption configuration
  - `IAM-001` — IAM user without MFA
  - `LOG-001` — no suitable active CloudTrail
- SQLAlchemy models and Alembic migrations for scans, resources, and findings
- Transactional resource upserts and database-enforced finding deduplication
- Successful-scan verification that resolves missing findings and reopens recurring findings
- Durable `QUEUED`, `RUNNING`, `COMPLETED`, and `FAILED` scan state
- A persisted scan runner that leaves findings unchanged when collection or evaluation fails
- Offline unit tests, Ruff configuration, and GitHub Actions CI

Scan, finding, resource, and control REST endpoints, Terraform, remediation, authentication, a
frontend, and AI functionality are **not implemented**. Scanning remains read-only in AWS. Sprint
3 writes scan results only to the configured application database and never changes AWS resources.

## How it is used

In a real environment, an administrator grants a user or role the documented read-only
permissions. An operator obtains short-lived AWS credentials and selects a region. Application
code then collects a snapshot and evaluates it:

```python
snapshot = InventoryService(provider).collect()
engine = RuleEngine(build_default_registry())
findings = engine.evaluate(snapshot)
```

The default registry contains exactly the five controls listed above. Evaluation is deterministic:
the same normalized snapshot and registry produce the same ordered finding candidates. The
persisted workflow reconciles those candidates against existing findings in one transaction:

```powershell
alembic upgrade head
python scripts/run_scan.py
```

The existing inventory command remains useful for checking collection independently:

```powershell
python scripts/run_inventory.py
```

The application resolves the caller with STS, runs the four collectors, normalizes and sorts
the results, and prints only an aggregate summary. This command does not run the rule engine or
write inventory to PostgreSQL.

See [AWS inventory operations](docs/aws-inventory.md) for the complete setup, least-privilege
policy baseline, call flow, scope, and troubleshooting guidance. See
[Security controls](docs/security-controls.md) for control semantics, evidence, limitations, and
programmatic evaluation. See [Persistence and scan lifecycle](docs/persistence.md) for schema,
transaction, deduplication, and resolution semantics.

## Technology stack

- Python 3.12+
- FastAPI and Uvicorn
- boto3 and botocore
- Pydantic Settings
- SQLAlchemy 2.x, Alembic, and PostgreSQL with psycopg 3
- Docker and Docker Compose
- pytest, httpx, Ruff, and GitHub Actions

## Repository structure

```text
.
├── app/
│   ├── api/                 # API routing and health/readiness endpoints
│   ├── aws/                 # Lazy AWS sessions, clients, and caller identity
│   ├── collectors/          # Fact-only AWS resource collectors
│   ├── database/            # SQLAlchemy engine, sessions, and model base
│   ├── logging/             # Application logging configuration
│   ├── models/              # Scan, resource, finding, and lifecycle models
│   ├── remediation/         # Reserved for future approved remediation
│   ├── rules/               # Rule contracts, engine, registry, and five controls
│   ├── schemas/             # HTTP, inventory, resource, and finding contracts
│   ├── services/            # Inventory, persistence, and scan orchestration
│   ├── config.py
│   └── main.py
├── docs/
│   ├── aws-inventory.md
│   ├── persistence.md
│   └── security-controls.md
├── alembic/                 # Versioned database migrations
├── scripts/                 # Inventory-only and persisted scan commands
├── tests/                   # API, unit, persistence, and migration tests
├── terraform/               # Placeholder only; no infrastructure exists yet
├── .github/workflows/ci.yml
├── docker-compose.yml
├── Dockerfile
└── pyproject.toml
```

## Local Python setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

On macOS or Linux, activate with `source .venv/bin/activate` and copy the example with
`cp .env.example .env`.

Start PostgreSQL, apply migrations, then start the API:

```powershell
docker compose up -d db
alembic upgrade head
uvicorn app.main:app --reload
```

- Liveness: [http://localhost:8000/health](http://localhost:8000/health)
- Readiness: [http://localhost:8000/ready](http://localhost:8000/ready)
- OpenAPI UI: [http://localhost:8000/docs](http://localhost:8000/docs)

`/ready` executes `SELECT 1` against PostgreSQL and returns HTTP 503 when the database is
unavailable. API startup and health checks do not contact AWS.

## Run AWS inventory

With an AWS IAM Identity Center profile:

```powershell
aws sso login --profile security-audit
$env:AWS_PROFILE = "security-audit"
$env:AWS_REGION = "us-east-1"
python scripts/run_inventory.py
```

Omit `AWS_PROFILE` to let boto3 use its standard credential chain, including environment
credentials or a workload role. Never put access keys in `.env` or commit them to Git.

Example output:

```json
{
  "account_id": "123456789012",
  "requested_region": "us-east-1",
  "collected_at": "2026-09-02T18:30:00+00:00",
  "resource_count": 27,
  "resources_by_service": {
    "cloudtrail": 2,
    "ec2": 8,
    "iam": 5,
    "s3": 12
  }
}
```

Raw configurations are intentionally omitted from console output because they can contain
sensitive infrastructure metadata.

## Evaluate security controls

The rule engine consumes an `InventorySnapshot`; it never calls AWS or writes to the database.
After constructing an AWS client provider, use the public evaluation flow:

```python
from app.aws.client import Boto3ClientProvider
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.services.inventory_service import InventoryService

provider = Boto3ClientProvider.from_settings()
snapshot = InventoryService(provider).collect()
findings = RuleEngine(build_default_registry()).evaluate(snapshot)
```

Each `FindingCandidate` identifies its control and target, assigns a severity, and carries
structured evidence, impact, and remediation guidance. The rule engine remains side-effect-free;
`ScanPersistenceService` is the separate transactional boundary that reconciles candidates.

## Run a persisted scan

Apply migrations, configure read-only AWS credentials as above, and run:

```powershell
python scripts/run_scan.py
```

The command records scan state, stores normalized resources, creates or updates findings, and
resolves prior findings only after a successful verification scan. It prints aggregate metadata
only. A collection or rule-evaluation failure marks the scan `FAILED` without persisting a partial
snapshot or resolving existing findings.

## Docker Compose

```powershell
Copy-Item .env.example .env
docker compose up --build
```

For macOS or Linux, use `cp .env.example .env`. The example values are local placeholders and
must not be reused as production credentials.

Compose waits for PostgreSQL, runs `alembic upgrade head` in a one-shot `migrate` service, and then
starts the API.

Compose does not mount host AWS credentials, and the API has no inventory endpoint yet. Run
inventory from the configured host environment. In deployments, prefer a workload role over
mounted credential files.

Stop services with `docker compose down`. The PostgreSQL volume is retained; use
`docker compose down --volumes` only when you intentionally want to delete local database data.

## Tests and code quality

Tests use injected fake AWS clients and an isolated SQLite database. They require neither AWS
credentials, a running PostgreSQL server, nor network access.

```powershell
python -m pytest
ruff check .
ruff format --check .
```

Apply formatting locally with `ruff format .`.

## Configuration

Configuration comes from environment variables and an optional local `.env` file:

- `APP_ENV`
- `DATABASE_URL`
- `LOG_LEVEL`
- `AWS_REGION`
- `AWS_PROFILE` (optional; blank means standard credential chain)
- `STALE_ACCESS_KEY_DAYS`
- `REQUIRED_TAGS` as a comma-separated list

`STALE_ACCESS_KEY_DAYS` and `REQUIRED_TAGS` are retained for future controls and are not used by
the five Sprint 2 controls. Never commit `.env`, credentials, credential exports, or scan output.
