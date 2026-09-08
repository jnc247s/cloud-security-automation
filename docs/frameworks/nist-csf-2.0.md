# NIST CSF 2.0 framework mapping

This is the authoritative repository document for the bundled NIST Cybersecurity Framework 2.0
subset and its internal-control mappings. Generic technical assessment semantics are documented
in `docs/assessment-framework.md`.

## Scope and claim boundary

The application performs NIST CSF 2.0-aligned AWS technical security assessment. A mapping says
that evidence from an internal technical control contributes context to a CSF outcome. It does not
make the internal control equivalent to the entire outcome, prove organization-wide satisfaction,
set severity, or determine `PASS`/`FAIL`.

The permanent direction is:

```text
AWS evidence
    -> deterministic internal control
    -> technical assessment
    -> mapped NIST context for reporting
```

Removing every mapping must leave technical control behavior unchanged.

## Bundled source

| Field | Value |
| --- | --- |
| Framework key | `nist-csf` |
| Version | `2.0` |
| Authoritative source | `https://doi.org/10.6028/NIST.CSWP.29` |
| Local subset | `app/assessment/data/nist_csf_2_0_core_subset.json` |
| Source manifest | `app/assessment/data/nist_csf_2_0_source_manifest.json` |
| Manifest retrieval timestamp | `2026-09-03T00:00:00-05:00` |
| Reviewed subset SHA-256 | `5aee46d2e18b1b655a1fe86cb749c87d033068c01c3bda0c5d1d4177c3b54d60` |

The subset contains the `Protect` Function and the Categories/Subcategories currently referenced
by implemented controls. It is not represented as the complete CSF Core.

The loader hashes the exact subset bytes and compares them with the manifest before validation.
It then enforces Function -> Category -> Subcategory parent links, framework/version binding,
existing Subcategory targets, and unique mappings.

## Implemented mappings

Mapping definitions were verified on 2026-09-03 and use the official CSF 2.0 publication as both
mapping source and framework source.

| Internal control | CSF 2.0 Subcategory | Scoped relationship |
| --- | --- | --- |
| `IAM-001` | `PR.AA-03` | IAM-user MFA evidence contributes to user-authentication context; it does not cover every user, service, or device. |
| `LOG-001` | `PR.PS-04` | Active CloudTrail evidence contributes to log generation/availability; it does not prove coverage, retention, or monitoring. |
| `NET-001` | `PR.IR-01` | Public SSH testing contributes evidence about protection from unauthorized network access. |
| `NET-002` | `PR.IR-01` | Public RDP testing contributes evidence about protection from unauthorized network access. |
| `S3-900` | `PR.DS-01` | Explicit bucket-default configuration contributes data-at-rest context; it does not prove full CIA or KMS-policy compliance. |

Each persisted `ControlFrameworkMapping` retains control, framework/version, Subcategory,
rationale, source/source version, verification timestamp, and checksum. Mappings are versioned
separately from findings and assessments.

## Interpretation rules

- NIST metadata is never an input to a technical rule.
- One mapped control passing does not make a Subcategory `TECHNICAL_PASS`.
- A future aggregate can report technical coverage only against an explicit versioned profile and
  must distinguish partial, insufficient, manual, not-assessed, and not-applicable states.
- Do not publish a generic “NIST compliant percentage.”
- Organization thresholds such as stale-key days, tags, management CIDRs, and KMS requirements
  belong to assessment profiles, not universal NIST requirements.
- Framework mapping changes cannot rewrite historical assessment or finding results.

## Change protocol

Never silently refresh this data from upstream or reuse version `2.0` with different reviewed
content. A framework or mapping update must:

1. use an authoritative source and record its exact version/retrieval time;
2. add or deliberately update a reviewed local artifact and manifest checksum;
3. explain added, removed, or changed mapping rationale;
4. validate hierarchy, references, duplicates, and complete control/catalog coverage;
5. preserve older persisted versions and their historical mappings;
6. update control/framework documentation and API expectations; and
7. run the complete assessment, catalog, persistence, API, and regression suites.

Crosswalks and informative references may support rationale, but they are not proof of one-to-one
equivalence between an AWS technical check and a CSF outcome.
