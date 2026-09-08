# Repository operating guide

This file contains permanent engineering rules for Codex and other contributors. Keep it concise;
put project state in [ROADMAP.md](ROADMAP.md), current design in
[ARCHITECTURE.md](ARCHITECTURE.md), security policy in [SECURITY.md](SECURITY.md), and detailed
work in `docs/`.

## Start here

1. Read `ROADMAP.md` and the current file in `docs/exec-plans/active/`.
2. Confirm those sources agree, inspect `git status`, and identify the current branch.
3. Read `ARCHITECTURE.md`, `SECURITY.md`, relevant `THREAT_MODEL.md` sections, and the documents
   linked by the active plan.
4. For substantial future work, perform an analysis-only preflight: inspect integration
   contracts, callers, tests, risks, and the proposed implementation, then stop until
   implementation is requested.

`ROADMAP.md` is the canonical source of project progress. Never infer sprint state from previous
chats, old prompts, memory, or branch names. If the roadmap and active plans disagree, stop and
resolve the inconsistency before implementation.

When correctness, security, and efficiency conflict, correctness and security win. Never reduce
validation, weaken security boundaries, bypass architecture, disable tests, or introduce unsafe
defaults merely to save time or usage.

When requirements conflict, prioritize: correctness, security, preservation of accepted behavior,
data integrity, testability, auditability, maintainability, architecture consistency, efficiency,
then speed.

## Source-of-truth hierarchy

- `AGENTS.md` owns permanent working and safety rules.
- `ROADMAP.md` alone owns sprint status; the matching active plan owns approved task detail.
- `PRODUCT_REQUIREMENTS.md` owns stable product outcomes and non-goals.
- `ARCHITECTURE.md`, `SECURITY.md`, and `THREAT_MODEL.md` own accepted design and security
  boundaries.
- `docs/api.md`, `docs/controls/`, `docs/frameworks/`, and `docs/operations/` own their named
  interfaces and domains.
- Code, migrations, and tests are evidence of implemented behavior, not authority to silently
  change intent or sprint state.

If documents disagree with implemented reality, stop, report the discrepancy, and reconcile the
authoritative documents without inventing behavior.

## Protected baseline

Sprints 0 through 4 are accepted contracts. Preserve application startup and health, AWS
authentication and fact-only inventory, deterministic assessment, assessment/profile/framework
contracts, historical persistence, evidence and finding integrity, exceptions and audit,
services, authentication and authorization, API schemas, scan execution, and machine-readable
identifiers.

Before changing an established interface:

1. search all callers and tests;
2. identify API, persistence, security, and documentation implications;
3. determine backward compatibility and explain why the change is required;
4. update all dependencies atomically; and
5. run targeted tests and the complete regression suite.

Never casually change enum values, constructors, ORM relationships, API response fields, service
interfaces, authentication behavior, or control IDs.

## Architecture invariants

- Collectors call AWS and collect facts only. They do not assign severity, decide assessment or
  framework status, manage findings, or remediate.
- Rules consume normalized evidence and never call AWS directly.
- The assessment path is `AWS evidence -> internal deterministic control -> technical assessment`.
  NIST mappings are parallel reporting metadata and never determine `PASS` or `FAIL`.
- Missing required evidence is `INSUFFICIENT_EVIDENCE`, never `PASS`.
- Keep stable `Resource` identity separate from immutable per-scan `ResourceSnapshot` history.
- An exception changes operational handling; it never rewrites `FAIL` to `PASS`.
- Finding lifecycle and remediation lifecycle remain separate.
- Preserve stable IDs, structured evidence, provenance, and every version that affects an
  assessment.
- Canonical S3 IDs `S3-001` through `S3-004` are reserved as documented in
  `docs/controls/catalog.md`; never restore the obsolete `S3-002` encryption prototype.
- Keep the generic service layer. Do not create one route or service per control.

## Security and production boundaries

- Never commit or log AWS keys, session credentials, JWT/OIDC secrets, database passwords,
  private keys, tokens, or API secrets.
- Preserve fail-closed production authentication and the `READ`, `PROPOSE`, `APPROVE`, and
  `EXECUTE` capability separation.
- Keep scanner credentials read-only. Future remediation uses a separate, narrowly scoped write
  identity and explicit handlers.
- Development authentication must remain explicit, local/test-only, and impossible to enable
  silently in production.
- Treat normalized configuration, evidence, findings, audit metadata, and database backups as
  sensitive security data. Keep logs and API errors sanitized.
- Maintain separate development, test, staging, and production configuration.

Production deployment, destructive AWS actions, production Terraform apply, production database
mutation, credential rotation, IAM modification, secret changes, and remediation execution
require explicit human authorization. Permission to implement code is not authorization to
execute production changes.

## Development and Git workflow

- Do not develop directly on `main`. Start from an up-to-date, clean `main` and use a scoped
  feature branch.
- Preserve unrelated user work. Never discard, overwrite, or include it in a task commit.
- Keep commits logical and reviewable. Do not force-push or merge without explicit approval.
- Implement only the requested sprint or slice. Do not silently add future-sprint behavior.
- Use Alembic for every schema change. Never rewrite an established migration; add a reviewed
  migration and validate its upgrade path.
- Prefer small slices that reuse the accepted abstractions. Avoid speculative infrastructure.

## Validation

Every implementation slice runs targeted tests first, then:

```text
python -m ruff check .
python -m ruff format --check .
python -m pytest
```

When persistence changes, run the PostgreSQL integration suite with an explicitly configured,
disposable `TEST_DATABASE_URL`. When runtime/container behavior changes, validate Docker Compose
and the image. Never point tests or migrations at production.

Do not delete valid failing tests, weaken assertions, add unjustified skips, suppress real errors,
or bypass authentication/authorization to obtain a green result. A sprint is not complete until
implementation, targeted tests, full regression, relevant integration/security/acceptance
validation, independent review, documentation, and required merge approval have succeeded.

## Documentation ownership

- Sprint state: `ROADMAP.md` and `docs/exec-plans/`
- Product requirements: `PRODUCT_REQUIREMENTS.md`
- Current architecture: `ARCHITECTURE.md`; durable decisions: `docs/design-decisions/`
- API contract: `docs/api.md`
- Security policy and threats: `SECURITY.md` and `THREAT_MODEL.md`
- Controls and mappings: `docs/controls/` and `docs/frameworks/`
- Operations: `docs/operations/`
- Released history: `CHANGELOG.md`

Update the corresponding owner whenever sprint state, architecture, API, security boundaries,
controls, framework mappings, or deployment behavior changes. Move a completed active plan to
`docs/exec-plans/completed/` without rewriting its original predictions; record material
implemented differences.

End implementation reports with scope, changes, architecture, compatibility, exact tests,
security, documentation, Git state, limitations, and confirmation that later-sprint work was not
started.
