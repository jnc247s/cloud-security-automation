# Persistence and scan lifecycle

Sprint 3 adds durable PostgreSQL storage for scans, normalized AWS resources, and security
findings. Alembic owns schema changes; application startup never calls `Base.metadata.create_all`.

## Data model

- `scans` records public scan UUIDs, account and region scope, lifecycle timestamps, status, and
  aggregate evaluation counts.
- `resources` stores the latest normalized facts for one stable AWS identity. `first_seen` is
  preserved and `last_seen` advances on later observations.
- `scan_resources` records which real inventory resources were observed by each scan without
  duplicating the resource itself.
- `findings` stores one lifecycle record per `control_id + resource_id`. A database unique
  constraint is the final guard against duplicates.

PostgreSQL uses `JSONB` for tags, normalized configuration, raw collector configuration, and
finding evidence. The model uses SQLAlchemy's portable JSON variant so the same behavior can be
tested offline with SQLite.

Resource identity is derived from:

```text
account + service + resource type + scope + region/global + AWS resource ID
```

The canonical identity is hashed for a compact unique database key while all identity fields
remain queryable. `LOG-001` is an absence-based, account-level control, so its finding points to a
stable synthetic `aws_account` resource. Synthetic resources are not counted as collected AWS
resources or inserted into `scan_resources`.

## Lifecycle rules

Scan transitions are deliberately small:

```text
QUEUED -> RUNNING -> COMPLETED
                  -> FAILED
```

Only a `RUNNING` scan can complete. Completion validates the whole snapshot before writing and
persists resources plus finding changes in the caller's transaction. Invalid or partially
persisted completion attempts roll back. A failed collection or rule evaluation records `FAILED`
without changing resources or resolving findings.

Finding reconciliation follows these rules:

- A new control/resource failure creates one `OPEN` finding.
- The same failure on a later scan updates evidence, guidance, severity, `last_detected`, and its
  lifecycle timestamp without creating another row. `scan_id` continues to identify the scan that
  first created the finding.
- A previously `RESOLVED` finding that reappears is reopened and retains its original UUID and
  `first_detected` value.
- A finding is automatically resolved only after a successful scan evaluated that control in the
  same account and resource scope and no longer produced the candidate. `resolved_at` records the
  verified snapshot's observation time.
- `FALSE_POSITIVE` findings are not automatically changed by reconciliation.
- Regional scans cannot resolve findings in another region; global resources are reconciled for
  the same account.
- An older snapshot completing late cannot overwrite or resolve a newer finding observation.

The caller must pass the complete set of evaluated control IDs. Inferring this set from current
candidates would be unsafe because a passing control produces no candidates.

## Apply migrations

Set `DATABASE_URL`, then upgrade to the latest schema:

```powershell
alembic upgrade head
```

Inspect the current revision or roll back one revision during development:

```powershell
alembic current
alembic downgrade -1
```

Create future revisions only after importing all new models through `app.models`:

```powershell
alembic revision --autogenerate -m "describe schema change"
alembic check
```

Docker Compose runs the `migrate` service after PostgreSQL becomes healthy and starts the API only
after the migration succeeds.

## Run a persisted scan

After applying migrations and configuring read-only AWS credentials:

```powershell
python scripts/run_scan.py
```

The runner creates and starts a scan, obtains a complete inventory snapshot, evaluates the current
rule registry, and atomically persists the results. It prints only the scan UUID, status, and
aggregate counts; it does not print raw resource configuration or evidence.

Sprint 3 does not add REST endpoints, manual finding-status operations, remediation, Terraform,
authentication, a dashboard, or AWS mutations. Those concerns remain outside this persistence
boundary.
