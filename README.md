# Cloud Security Control Plane

A production-style Python service for discovering AWS resources and evaluating them with
evidence-based, framework-aligned security controls. Later sprints will persist and expose the
resulting assessments and findings.

## Project status

**Sprint 2.1 — Assessment Framework and Control Contracts**

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
- A side-effect-free rule engine with explicit `PASS`, `FAIL`, `INSUFFICIENT_EVIDENCE`, and
  `NOT_APPLICABLE` results
- Deeply immutable `EvidenceArtifact` values with payload digests and content-bound scan,
  snapshot, collector, API, resource, and time provenance
- A versioned, checksummed organization assessment profile
- Versioned technical control contracts and an independently validated NIST CSF 2.0 mapping
  catalog
- Five deterministic controls:
  - `NET-001` — public SSH exposure
  - `NET-002` — public RDP exposure
  - `S3-900` — missing explicit bucket encryption configuration (legacy prototype behavior)
  - `IAM-001` — IAM user without MFA
  - `LOG-001` — no suitable active CloudTrail
- Offline unit tests, Ruff configuration, and GitHub Actions CI

Assessment and finding persistence, finding lifecycle management, scan API endpoints,
authentication, Terraform, remediation, a frontend, and AI functionality are **not implemented**.
Sprint 2.1 does not expand the AWS resource or API-permission scope and does not add security
controls. It only reads AWS configuration and evaluates an in-memory snapshot; it does not
change AWS resources or write assessments to PostgreSQL.

## How it is used

In a real environment, an administrator grants a user or role the documented read-only
permissions. An operator obtains short-lived AWS credentials and selects a region. Application
code then collects a snapshot and evaluates it:

```python
from app.assessment.profiles import create_default_assessment_profile
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.services.inventory_service import InventoryService

snapshot = InventoryService(provider).collect()
engine = RuleEngine(build_default_registry())
profile = create_default_assessment_profile()
assessments = engine.assess(snapshot, profile)
```

The default registry contains the five controls listed above. Evaluation is deterministic: the
same normalized snapshot, registry, and profile produce the same ordered assessment candidates.
The older `engine.evaluate(snapshot)` interface remains available for compatibility; it emits only
failure `FindingCandidate` values and raises `RuleEvaluationError` when required facts are missing
or malformed.

The existing inventory command remains useful for checking collection independently:

```powershell
python scripts/run_inventory.py
```

The application resolves the caller with STS, runs the four collectors, records each collector
as `SUCCEEDED`, `FAILED`, or `PARTIAL`, normalizes and sorts available results, and prints only an
aggregate summary. An incomplete run exits unsuccessfully without hiding results from independent
collectors. This command does not run the rule engine or write inventory to PostgreSQL.

See [AWS inventory operations](docs/aws-inventory.md) for the complete setup, least-privilege
policy baseline, call flow, scope, and troubleshooting guidance. See
[Security controls](docs/security-controls.md) for control semantics and limitations, and
[Assessment framework](docs/assessment-framework.md) for result states, profiles, evidence
provenance, framework mappings, and programmatic evaluation.

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
│   ├── assessment/         # Profiles, evidence, control contracts, and frameworks
│   ├── api/                # API routing and health/readiness endpoints
│   ├── aws/                # Lazy AWS sessions, clients, and caller identity
│   ├── collectors/         # Fact-only AWS resource collectors
│   ├── database/           # SQLAlchemy engine, sessions, and model base
│   ├── logging/            # Application logging configuration
│   ├── models/             # Reserved for future persistence models
│   ├── remediation/        # Reserved for future approved remediation
│   ├── rules/              # Rule contracts, engine, registry, and five controls
│   ├── schemas/            # HTTP, inventory, resource, and finding contracts
│   ├── services/           # Inventory orchestration
│   ├── config.py
│   └── main.py
├── docs/
│   ├── assessment-framework.md
│   ├── aws-inventory.md
│   └── security-controls.md
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
  "collector_outcomes": {
    "cloudtrail_trails": "SUCCEEDED",
    "iam_users": "SUCCEEDED",
    "s3_buckets": "SUCCEEDED",
    "security_groups": "SUCCEEDED"
  },
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
After constructing an AWS client provider, use the canonical assessment flow:

```python
from app.assessment.profiles import create_default_assessment_profile
from app.aws.client import Boto3ClientProvider
from app.rules.engine import RuleEngine
from app.rules.registry import build_default_registry
from app.services.inventory_service import InventoryService

provider = Boto3ClientProvider.from_settings()
snapshot = InventoryService(provider).collect()
profile = create_default_assessment_profile()
assessments = RuleEngine(build_default_registry()).assess(snapshot, profile)
```

Each `AssessmentCandidate` identifies its control, target, exact profile version and checksum,
and one explicit technical result. `PASS` and `FAIL` include a structured `EvidenceArtifact` with
provenance and a verified payload digest. Missing or malformed required facts, or a required
collector that was unrequested, failed, or partial, produce `INSUFFICIENT_EVIDENCE`, never
`PASS`. Resource controls return `NOT_APPLICABLE` only when their collector succeeded and no
target resources exist.

The compatibility method `RuleEngine.evaluate(snapshot)` still returns failure-only
`FindingCandidate` values and raises `RuleEvaluationError` for insufficient evidence or incomplete
required collection. New code should use `assess`. Both result types remain in memory; Sprint 2.1
creates no database records.

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

`STALE_ACCESS_KEY_DAYS` and `REQUIRED_TAGS` remain available as configuration inputs for later
profile-aware orchestration but are not consumed by the current five technical decisions.
Assessment profile thresholds are organization or project policy, not universal NIST CSF
requirements. Never commit `.env`, credentials, credential exports, or scan output.
