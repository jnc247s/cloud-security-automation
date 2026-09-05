# Cloud Security Control Plane

A production-style Python service for discovering AWS resources and evaluating them with
evidence-based, framework-aligned security controls. It preserves assessment history and findings
in PostgreSQL and exposes them through an authenticated, versioned service API.

## Project status

**Sprint 4 — Service Layer, Secure API and Scan Execution**

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
- Preallocated scan UUIDs, exact scope manifests, and explicit complete/partial/failed coverage
- Stable resource identities separated from immutable per-scan resource observations
- PostgreSQL persistence for versioned profiles, catalogs, assessments, structured evidence,
  deduplicated findings, and finding occurrences
- Time-bounded exceptions and audited finding dispositions that never rewrite technical results
- Alembic migrations, database-enforced history guards, and transactional audit records
- OIDC/JWT authentication with JWKS signature, issuer, audience, expiry, and subject validation
- Explicit `VIEWER`, `ANALYST`, `APPROVER`, and `ADMIN` roles mapped to `READ`, `PROPOSE`,
  `APPROVE`, and `EXECUTE` capabilities
- A local-only development identity that is rejected outside explicit development/test modes
- Versioned, authorized APIs for scans, resources and history, assessments and evidence, findings,
  controls and framework mappings, and exceptions
- Separate scan, resource, assessment, finding, control, framework, exception, and audit services
- A bounded, recoverable `ScanExecutor` that persists a scan before asynchronous AWS work begins
- Five deterministic controls:
  - `NET-001` — public SSH exposure
  - `NET-002` — public RDP exposure
  - `S3-900` — missing explicit bucket encryption configuration (legacy prototype behavior)
  - `IAM-001` — IAM user without MFA
  - `LOG-001` — no suitable active CloudTrail
- Offline unit tests, migrated-database tests, optional PostgreSQL integration tests, Ruff,
  and GitHub Actions CI

Sprint 4 adds no AWS resources or API permissions, new collectors, new security controls,
Terraform infrastructure, remediation, frontend, password database, or AI functionality.
`S3-900` remains the unchanged legacy encryption-configuration prototype; it is not a new
production control. AWS resources are never modified.

## How it is used

In a real environment, an administrator grants the API workload the documented read-only AWS
permissions and configures an external OIDC provider. An authorized caller submits a scan and
receives its durable identity immediately:

```powershell
$headers = @{ Authorization = "Bearer local-development" } # local development only
$scan = Invoke-RestMethod -Method Post `
  -Uri http://localhost:8000/api/v1/scans `
  -Headers $headers -ContentType application/json `
  -Body '{"region":"us-east-1"}'
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans/$($scan.scan_id)" -Headers $headers
```

The POST returns HTTP 202 while the bounded executor collects and evaluates in the background.
The account identity is resolved from STS, never accepted from the request. A CLI, dashboard,
integration, or future agent can then query the stable machine-readable IDs, results, evidence,
and framework mappings. See [Secure service API](docs/secure-api.md) for the complete contract.

Application code can also compose the underlying deterministic services directly:

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

Each collection receives a scan UUID before AWS identity or evidence collection begins. A caller
can supply its own UUID with `collect(scan_id=scan_id)`. Evaluation stays in memory; a separate
`persist_scan_result(...)` call records the validated result bundle in a caller-owned database
transaction. See [Persistence and history](docs/persistence.md) for the scope contract and example.

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
provenance, framework mappings, and programmatic evaluation. The Sprint 3
[persistence guide](docs/persistence.md) covers durable history and finding lifecycle safety.
The [secure API guide](docs/secure-api.md) covers authentication, authorization, endpoints, scan
execution, and deployment limitations.

## Technology stack

- Python 3.12+
- FastAPI and Uvicorn
- PyJWT and cryptography-backed OIDC signature verification
- boto3 and botocore
- Pydantic Settings
- SQLAlchemy 2.x, Alembic, and PostgreSQL with psycopg 3
- Docker and Docker Compose
- pytest, httpx, Ruff, and GitHub Actions

## Repository structure

```text
.
├── app/
│   ├── assessment/         # Profiles, evidence, control contracts, and frameworks
│   ├── api/                # Versioned secure routes and health/readiness endpoints
│   ├── aws/                # Lazy AWS sessions, clients, and caller identity
│   ├── collectors/         # Fact-only AWS resource collectors
│   ├── database/           # Sessions, catalog/result persistence, and governance
│   ├── logging/            # Application logging configuration
│   ├── models/             # Historical records, findings, exceptions, and audit
│   ├── remediation/        # Reserved for future approved remediation
│   ├── rules/              # Rule contracts, engine, registry, and five controls
│   ├── schemas/            # HTTP views, inventory, evidence, finding, and scan contracts
│   ├── security/           # OIDC/development authentication and capability policy
│   ├── services/           # Query services, inventory orchestration, and scan executor
│   ├── config.py
│   └── main.py
├── docs/
│   ├── assessment-framework.md
│   ├── aws-inventory.md
│   ├── persistence.md
│   ├── secure-api.md
│   └── security-controls.md
├── alembic/                 # Reviewed, versioned schema migrations
├── alembic.ini
├── scripts/run_inventory.py
├── tests/                   # API, offline unit, and PostgreSQL integration tests
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

Start PostgreSQL, apply the schema migrations, then start the API:

```powershell
docker compose up -d db
alembic upgrade head
uvicorn app.main:app --reload
```

- Liveness: [http://localhost:8000/health](http://localhost:8000/health)
- Readiness: [http://localhost:8000/ready](http://localhost:8000/ready)
- OpenAPI UI: [http://localhost:8000/docs](http://localhost:8000/docs)

Every `/api/v1` request needs a bearer token. With the example local configuration, choose
**Authorize** in OpenAPI and enter `local-development`. Production must set `AUTH_MODE=oidc` and
the OIDC variables described below.

`/ready` executes `SELECT 1` against PostgreSQL and returns HTTP 503 when the database is
unavailable. It is a connectivity check, not a migration-version check. Health requests do not
contact AWS. Application startup resubmits durable `RUNNING` scans, so it contacts AWS only when
unfinished work exists. Apply migrations before using persistence; application startup does not
create tables automatically.

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
  "scan_id": "77f0d7c3-d67e-4e65-9bbf-783414355fdb",
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
the normalized-inventory and control-catalog digests used during evaluation, and one explicit
technical result. `PASS` and `FAIL` include a structured `EvidenceArtifact` with provenance and a
verified payload digest. Missing or malformed required facts, or a required collector that was
unrequested, failed, or partial, produce `INSUFFICIENT_EVIDENCE`, never `PASS`. Resource controls
return `NOT_APPLICABLE` only when their collector succeeded and no target resources exist.

The compatibility method `RuleEngine.evaluate(snapshot)` still returns failure-only
`FindingCandidate` values and raises `RuleEvaluationError` for insufficient evidence or incomplete
required collection. New code should use `assess`. Neither evaluation method writes to the
database; persistence is a separate explicit operation.

## Persistence and finding history

`persist_scan_result` stores an already-collected, already-assessed result bundle atomically in
the caller's transaction. It does not execute a scan. Each scan retains its scope, exact
profile/catalog versions, resource snapshots, four-state assessments, and evidence.

Repeated failures reuse one stable finding and append occurrence history. Only an explicit
`PASS` from a complete scan can resolve it, according to observation-time ordering. Missing
resources, partial scans, `NOT_APPLICABLE`, and `INSUFFICIENT_EVIDENCE` never resolve a finding.
Exceptions and accepted-risk decisions change
operational handling, never `FAIL` into `PASS`.

See [Persistence and history](docs/persistence.md) for the data model, transaction example,
governance operations, migration commands, and PostgreSQL test setup.

## Docker Compose

```powershell
Copy-Item .env.example .env
docker compose up --build
```

For macOS or Linux, use `cp .env.example .env`. The example values are local placeholders and
must not be reused as production credentials.

Compose waits for PostgreSQL to become healthy, runs the one-shot `migrate` service with
`alembic upgrade head`, and starts the API only after migration succeeds. If migration fails,
inspect `docker compose logs migrate`; do not bypass it or delete the database to hide the error.

Compose does not mount host AWS credentials. A scan request therefore needs credentials supplied
to the API through an appropriate workload environment; for simple host-side inventory checks,
continue to use the inventory command. In deployments, prefer a workload role over mounted
credential files. Compose binds the API to `127.0.0.1` by default because its development bearer
marker is intentionally not a secret.

Stop services with `docker compose down`. The PostgreSQL volume is retained; use
`docker compose down --volumes` only when you intentionally want to delete local database data.

## Tests and code quality

The default tests use injected fake AWS clients and migrated SQLite databases; they require
neither AWS credentials nor a running PostgreSQL server. PostgreSQL integration tests are skipped
unless `TEST_DATABASE_URL` is set. CI supplies a PostgreSQL test service and runs them as well.

```powershell
python -m pytest
ruff check .
ruff format --check .
```

Apply formatting locally with `ruff format .`.

To run the PostgreSQL integration tests against a dedicated local test database:

```powershell
$env:TEST_DATABASE_URL = "postgresql+psycopg://cloudsec:change-me@localhost:5432/cloudsec_test"
python -m pytest tests/integration
```

The test role must be able to create and drop schemas. The tests use an isolated generated schema;
never point this setting at a production database. See the
[test details](docs/persistence.md#tests) before running them.

## Configuration

Configuration comes from environment variables and an optional local `.env` file:

- `APP_ENV`
- `DATABASE_URL`
- `LOG_LEVEL`
- `AWS_REGION`
- `AWS_PROFILE` (optional; blank means standard credential chain)
- `STALE_ACCESS_KEY_DAYS`
- `REQUIRED_TAGS` as a comma-separated list
- `AUTH_MODE` (`development` locally or `oidc` for production)
- `DEV_IDENTITY_SUBJECT` and `DEV_IDENTITY_ROLES` (local development only)
- `OIDC_ISSUER`, `OIDC_AUDIENCE`, and `OIDC_JWKS_URL`
- `OIDC_ALGORITHMS` (asymmetric allowlist; defaults to `RS256`)
- `OIDC_ROLES_CLAIM` (defaults to `roles`)
- `OIDC_ALLOW_INSECURE_HTTP` (localhost development providers only; defaults to `false`)

`STALE_ACCESS_KEY_DAYS` and `REQUIRED_TAGS` populate the versioned default assessment profile used
by asynchronous scans. These thresholds are organization or project policy, not universal NIST
CSF requirements. Never commit `.env`, credentials, credential exports, or scan output.
