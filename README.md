# Cloud Security Control Plane

A production-style foundation for a service that will discover AWS resources, evaluate
security controls, and manage evidence-based findings. Sprint 0 establishes the application,
database, container, testing, and CI foundations only.

## Project status

**Sprint 0 — Foundation**

Available now:

- FastAPI application factory
- `GET /health` liveness endpoint
- `GET /ready` readiness endpoint with a PostgreSQL connectivity check
- Environment-based configuration
- SQLAlchemy engine, session factory, and declarative base
- Docker Compose services for the API and PostgreSQL
- API tests, Ruff configuration, and baseline GitHub Actions CI

AWS resource collection, security controls, Terraform infrastructure, remediation, and a
dashboard have **not** been implemented.

## Technology stack

- Python 3.12+
- FastAPI and Uvicorn
- Pydantic Settings
- SQLAlchemy 2.x
- PostgreSQL with psycopg 3
- Docker and Docker Compose
- pytest, httpx, and Ruff
- GitHub Actions

## Repository structure

```text
.
├── app/
│   ├── api/                 # API routing and HTTP endpoints
│   ├── database/            # SQLAlchemy engine, sessions, and model base
│   ├── schemas/             # Request and response schemas
│   ├── collectors/          # Reserved for future AWS resource collection
│   ├── logging/             # Application logging configuration
│   ├── models/              # Reserved for persistence models
│   ├── remediation/         # Reserved for future approved remediation
│   ├── rules/               # Reserved for future security controls
│   ├── services/            # Reserved for application services
│   ├── config.py
│   └── main.py
├── tests/
│   ├── api/
│   ├── integration/
│   └── unit/
├── docs/
├── scripts/
├── terraform/               # Placeholder only; no infrastructure exists yet
├── .github/workflows/ci.yml
├── docker-compose.yml
├── Dockerfile
└── pyproject.toml
```

## Local Python setup

Create and activate a virtual environment:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
```

On macOS or Linux, activate the environment with
`source .venv/bin/activate` and copy the example with
`cp .env.example .env`.

Start PostgreSQL if you want the readiness endpoint to report ready:

```powershell
docker compose up -d db
```

Then start the API:

```powershell
uvicorn app.main:app --reload
```

The service is available at:

- Liveness: [http://localhost:8000/health](http://localhost:8000/health)
- Readiness: [http://localhost:8000/ready](http://localhost:8000/ready)
- OpenAPI UI: [http://localhost:8000/docs](http://localhost:8000/docs)

`/health` reports whether the API process is running. `/ready` also executes
`SELECT 1` against PostgreSQL and returns HTTP 503 when the database is unavailable.

## Docker Compose

Copy the example environment file, then build and start both services:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

For macOS or Linux, use `cp .env.example .env`. The values in
`.env.example` are local-development placeholders and must not be reused as production
credentials.

Stop the containers with:

```powershell
docker compose down
```

The named PostgreSQL volume is retained. Use `docker compose down --volumes` only
when you intentionally want to delete local database data.

## Tests

Tests do not require AWS or a live PostgreSQL server. Database readiness outcomes are
substituted at the endpoint boundary.

```powershell
python -m pytest
```

## Linting and formatting

```powershell
ruff check .
ruff format --check .
```

To apply Ruff formatting locally:

```powershell
ruff format .
```

## Configuration

Configuration is read from environment variables and, for local development, an optional
`.env` file. Supported Sprint 0 settings include:

- `APP_ENV`
- `DATABASE_URL`
- `LOG_LEVEL`
- `AWS_REGION`
- `AWS_PROFILE`
- `STALE_ACCESS_KEY_DAYS`
- `REQUIRED_TAGS` as a comma-separated list

AWS-related values are reserved for later sprints. Sprint 0 does not call AWS APIs or load
AWS credentials.

Never commit `.env` or real credentials.
