# Cloud Security Control Plane

A production-style Python service for discovering AWS resources and, in later sprints,
evaluating security controls and managing evidence-based findings.

## Project status

**Sprint 1 — AWS Resource Inventory**

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
- Offline unit tests, Ruff configuration, and GitHub Actions CI

Security-rule evaluation, findings, inventory persistence, scan API endpoints, Terraform,
remediation, authentication, a frontend, and AI functionality are **not implemented**.
Running Sprint 1 does not change AWS resources.

## How it is used

In a real environment, an administrator grants a user or role the documented read-only
permissions. An operator obtains short-lived AWS credentials, selects a region, and runs:

```powershell
python scripts/run_inventory.py
```

The application resolves the caller with STS, runs the four collectors, normalizes and sorts
the results, and prints only an aggregate summary. It does not evaluate whether a resource is
secure and does not write inventory to PostgreSQL in this sprint.

See [AWS inventory operations](docs/aws-inventory.md) for the complete setup, least-privilege
policy baseline, call flow, scope, and troubleshooting guidance.

## Technology stack

- Python 3.12+
- FastAPI and Uvicorn
- boto3 and botocore
- Pydantic Settings
- SQLAlchemy 2.x and PostgreSQL with psycopg 3
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
│   ├── models/              # Reserved for future persistence models
│   ├── remediation/         # Reserved for future approved remediation
│   ├── rules/               # Reserved for future security controls
│   ├── schemas/             # HTTP and normalized inventory schemas
│   ├── services/            # Inventory orchestration
│   ├── config.py
│   └── main.py
├── docs/aws-inventory.md
├── scripts/run_inventory.py
├── tests/                   # API and offline unit tests
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

Start PostgreSQL if you want the readiness endpoint to report ready, then start the API:

```powershell
docker compose up -d db
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

## Docker Compose

```powershell
Copy-Item .env.example .env
docker compose up --build
```

For macOS or Linux, use `cp .env.example .env`. The example values are local placeholders and
must not be reused as production credentials.

Compose does not mount host AWS credentials, and the API has no inventory endpoint yet. Run
inventory from the configured host environment. In deployments, prefer a workload role over
mounted credential files.

Stop services with `docker compose down`. The PostgreSQL volume is retained; use
`docker compose down --volumes` only when you intentionally want to delete local database data.

## Tests and code quality

Tests use injected fake AWS clients and require neither AWS credentials nor network access.

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

`STALE_ACCESS_KEY_DAYS` and `REQUIRED_TAGS` are retained for future controls; Sprint 1 only
collects facts. Never commit `.env`, credentials, credential exports, or scan output.
