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

### 6B.1 additional subset and mappings

Opt-in control catalog `0.3.0` retains the original `nist-csf/2.0` subset and all five existing
control mappings unchanged. Its four new mappings use separately identified local subset release
`nist-csf/2.0+subset.2`; the suffix is not an official NIST publication version. Mapping source
version remains official `2.0`, sourced from the same NIST CSWP 29, Appendix A, printed page 19.

The reviewed files are `app/assessment/data/nist_csf_2_0_subset_2.json` and
`app/assessment/data/nist_csf_2_0_subset_2_manifest.json`. SHA-256 of the new subset bytes is
`e855603bd666ef3f74af596560f353e61fb1a1af348b52276f39f41fb4c3b4c9`; source inspection time is
`2026-09-27T22:54:24Z`. Manifest version identifies the local subset release; each mapping's
`mapping_source_version` identifies official NIST `2.0`.

| Internal control | CSF reference | Scoped context |
| --- | --- | --- |
| IAM-002 | PR.AA-01 | Active-key age contributes credential-lifecycle evidence, not proof of safe distribution. |
| IAM-003 | PR.AA-01 | Recorded-use review contributes credential-lifecycle evidence, not proof of business need. |
| IAM-005 | PR.AA-01 | Root-key presence contributes privileged-credential management context, not coverage of all credentials. |
| IAM-006 | PR.AA-03 | Root MFA presence contributes authentication context, not hardware-only or organization-wide assurance. |

Complete approved rationale and guidance are in [6B.1 metadata](../controls/sprint-6b1-metadata.md).
These mappings do not determine thresholds, severity, or technical results.

### Common interpretation rules

Opt-in catalog `0.4.0` preserves both earlier subsets and adds separately identified local
`nist-csf/2.0+subset.3` for IAM-004 -> PR.AA-05. Source remains official NIST CSWP 29 version
`2.0`, Appendix A, printed page 20, inspected 2026-09-27. The subset and manifest are
`app/assessment/data/nist_csf_2_0_subset_3.json` and its `_manifest.json` companion, with SHA-256
`e43c585f8f5a012241b63f552fcd3d4546805993766c48f9dbd4b6544f2bf87f`.
This mapping supports permissions-policy/least-privilege review, not effective authorization,
complete authorization management, separation of duties or compliance. The subset suffix is a
local artifact release, not a new official NIST version. See [approved metadata](../controls/sprint-6b2-metadata.md).

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
