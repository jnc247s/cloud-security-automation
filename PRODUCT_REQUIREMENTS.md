# Product requirements

## Product objective

Build a production-style AWS cloud security control plane that discovers AWS configuration,
collects structured evidence, evaluates deterministic technical controls, preserves historical
results, and exposes authorized machine-readable interfaces for security engineers.

The product performs **NIST CSF 2.0-aligned AWS technical security assessments**. It does not
provide NIST certification, determine every CSF outcome, or claim that one successful technical
check proves an organization-wide outcome.

Sprint progress and delivery sequence belong only in [ROADMAP.md](ROADMAP.md).

## Users and use cases

- Security engineers start scans and investigate exact findings, evidence, resource history, and
  framework context.
- Cloud administrators provide a least-privilege read-only workload identity and review required
  AWS permissions.
- Risk or control owners review technical results and explicit exceptions without rewriting the
  underlying evidence.
- Future dashboards, reports, and controlled tool adapters consume the service API rather than
  querying PostgreSQL directly.

## Core requirements

### Evidence collection

- Use the standard AWS credential provider chain and verify account identity with STS.
- Keep collector output fact-only, structured, JSON-safe, and traceable to account, Region,
  resource, source API, scan, and collection time.
- Represent requested scope and collector completeness explicitly. Do not duplicate global
  resources per Region or present partial collection as complete.
- Keep scanner permissions read-only and document every required AWS action.

### Deterministic assessment

- Evaluate normalized evidence without AWS or database calls from rules.
- Use stable, versioned control contracts and assessment profiles.
- Return `PASS`, `FAIL`, `INSUFFICIENT_EVIDENCE`, or `NOT_APPLICABLE` explicitly.
- Never convert unavailable or malformed required evidence into `PASS`.
- Keep severity and organization policy separate from external framework metadata.

### Framework alignment

- Map internal controls to version-bound NIST CSF 2.0 Subcategories only with rationale and
  authoritative source provenance.
- Validate framework hierarchy, references, versions, duplicate mappings, and source checksums.
- Treat mappings as reporting context, not technical evaluation logic or compliance claims.

### History and governance

- Separate stable resource identity from immutable per-scan observations.
- Persist scan scope, collection outcomes, profile/catalog/framework versions, assessments,
  evidence, findings, occurrences, exceptions, and audit events transactionally.
- Deduplicate findings by stable identity while retaining every occurrence.
- Allow resolution only from sufficient, explicit, later technical evidence.
- Keep exceptions and future remediation lifecycles distinct from technical results and findings.

### Service and API

- Keep domain behavior in focused services and HTTP concerns in thin FastAPI routes.
- Authenticate all versioned API operations and authorize explicit capabilities.
- Return stable IDs and structured assessment, evidence, occurrence, scope, and mapping data.
- Persist a scan ID before non-blocking execution and expose a pollable lifecycle.
- Preserve the executor interface so a future worker can replace the local implementation without
  moving business logic into routes.

## Security and quality requirements

- Fail closed when production authentication is incomplete or development authentication would
  be active outside an explicit local/test environment.
- Never commit or expose credentials, tokens, private keys, secrets, raw AWS errors, or sensitive
  evidence in logs.
- Maintain least privilege, bounded work submission, sanitized errors, auditable mutations,
  migration history, and protected historical records.
- Require targeted tests, full regression, relevant PostgreSQL/AWS/container validation,
  independent review, and current documentation for each completed sprint.
- Production changes and destructive actions always require explicit human authorization.

## v1 outcomes

The committed v1 sequence will expand evidence, add a polished production control catalog, expose
a dashboard and technical NIST posture, implement narrowly scoped human-approved remediation with
stale-state protection and rescan verification, validate scanner accuracy and application
security, and provide a production-style AWS deployment and technical assessment report.

Exact ordering and status remain authoritative in `ROADMAP.md`.

## Non-goals and deferred scope

- Organization-wide NIST compliance scoring or certification
- Security decisions made by an LLM
- Autonomous remediation or arbitrary AWS/boto3/shell execution
- Password storage or an in-application identity provider
- Kubernetes, multi-cloud, broad AWS Organizations orchestration, or speculative distributed
  infrastructure before demonstrated need
- Additional compliance frameworks before separate approval

An optional post-v1 investigation agent may eventually receive controlled `READ` and `PROPOSE`
interfaces. It must not decide deterministic results, official mappings, evidence sufficiency,
approval, execution, or remediation success.
