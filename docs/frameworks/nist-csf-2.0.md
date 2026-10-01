# NIST CSF 2.0 framework mapping

This is the authoritative repository document for the bundled NIST Cybersecurity Framework 2.0
subset and its internal-control mappings. Generic technical assessment semantics are documented
in `docs/assessment-framework.md`.

## Scope and claim boundary

Local 6F.2 catalog `0.12.0`, pending acceptance, adds LOG-004 -> PR.AA-05 in separate
subset `2.0+subset.11`. Source: official NIST CSWP 29 version 2.0, Appendix A printed page 20
(PDF index 24), inspected 2026-10-01. Artifact `app/assessment/data/nist_csf_2_0_subset_11.json`
and companion manifest have SHA-256
`2bb52393030d78513a656a806d37fe7ec44ad876112f1c18dd66b48e1133a782`.
This project inference contributes destination access-policy review context, not complete least
privilege or compliance. Earlier framework bytes and technical results remain independent.
See [6F.2 metadata](../controls/sprint-6f2-metadata.md).

Accepted 6F.1 catalog `0.11.0` adds LOG-002 -> PR.PS-04 and LOG-003 ->
PR.DS-01 in separately checksummed subset `2.0+subset.10`. Source: official NIST CSWP 29
version 2.0, Appendix A, inspected 2026-10-01. Files are
`app/assessment/data/nist_csf_2_0_subset_10.json` and its `_manifest.json` companion;
exact subset SHA-256 is `21a393bdce87a3417134a1c4b9cd9c0c2cc1d49ef2a41e0259d4ec39342e3282`.
Project mappings contribute management-log generation and integrity-setting context only,
not continuous monitoring, verified digests, complete data security or compliance.
Earlier framework bytes and technical results are independent. See
[6F.1 metadata](../controls/sprint-6f1-metadata.md).

6E.3 catalog `0.10.0` adds S3-004 -> PR.DS-01 in separately checksummed local subset
`2.0+subset.9`. Source: NIST CSWP 29 version 2.0, Appendix A, Protect / Data Security,
inspected 2026-09-30. Files are `app/assessment/data/nist_csf_2_0_subset_9.json` and its
`_manifest.json` companion; the reviewed subset SHA-256 is
`aa0182df9353da42065fbcab9cfae7a1342cb0c562b86e802df6beedcdbfda07`. This mapping contributes
sensitive-bucket default-KMS configuration evidence only, not existing-object protection,
key access/availability, organization-wide data security or compliance. Severity and technical
results are independent; earlier framework bytes remain unchanged. See
[approved 6E.3 metadata](../controls/sprint-6e3-metadata.md).

6E.2 catalog `0.9.0` adds S3-002 -> PR.AA-05 in separately checksummed subset `2.0+subset.8`,
reusing the same verified NIST CSWP 29 reference below. It contributes direct exposure
configuration evidence only, not full least privilege, actual access or compliance. Files are
`app/assessment/data/nist_csf_2_0_subset_8.json` and its `_manifest.json` companion; earlier
bytes are unchanged. See [6E.2 metadata](../controls/sprint-6e2-metadata.md).

6E.1 catalog `0.8.0` adds S3-001 -> PR.AA-05 and S3-003 -> PR.DS-02 in separately checksummed
local subset `2.0+subset.7`. Source: NIST CSWP 29 version 2.0, Appendix A printed page 20,
inspected 2026-09-29. Files are `app/assessment/data/nist_csf_2_0_subset_7.json` and its
`_manifest.json` companion. These mappings contribute only public-access safeguard and
transport-protection configuration evidence, not complete NIST outcomes. Severity and results
are independent; see [approved metadata](../controls/sprint-6e1-metadata.md).

6D.2 catalog `0.7.0` adds NET-006 -> PR.PS-04 in local subset `2.0+subset.6`, sourced from
NIST CSWP 29 version 2.0, Appendix A printed page 20, inspected 2026-09-28. The independently
checksummed `app/assessment/data/nist_csf_2_0_subset_6.json` and `_manifest.json` companion
preserve earlier releases. This mapping contributes log-generation configuration evidence only,
not delivery, retention or continuous-monitoring assurance. See
[approved metadata](../controls/sprint-6d2-metadata.md).

6D.1 catalog `0.6.0` adds NET-003/004/005 -> PR.IR-01 using separately checksummed local subset
`2.0+subset.5`. Source remains NIST CSWP 29 official version 2.0, Appendix A printed page 20,
inspected 2026-09-28. The subset and manifest are `app/assessment/data/nist_csf_2_0_subset_5.json`
and its `_manifest.json` companion. These project mappings contribute network-access protection
context only; severity, policy and technical results are independent. Earlier framework artifacts
and mappings are unchanged. See [approved metadata](../controls/sprint-6d1-metadata.md).

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

### 6C additional subset and mappings

Opt-in catalog `0.5.0` retains all earlier subset bytes and adds separately identified local
`nist-csf/2.0+subset.4`, sourced from NIST CSWP 29 version `2.0`, Appendix A, printed page 20,
inspected 2026-09-28. Its files are `app/assessment/data/nist_csf_2_0_subset_4.json` and
`app/assessment/data/nist_csf_2_0_subset_4_manifest.json`; the manifest binds the exact subset hash.
EC2-001 maps to PR.PS-01, EC2-002 to PR.IR-01, and EC2-003/004 to PR.DS-01 with the limited
rationales in [approved 6C metadata](../controls/sprint-6c-metadata.md). These project mappings
do not determine technical results or claim complete NIST outcomes. The suffix is a local release,
not an official NIST framework version.

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
