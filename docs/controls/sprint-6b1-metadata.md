# Sprint 6B.1 approved control metadata

Prepared and approved: 2026-09-27. Status: accepted in opt-in catalog `0.3.0`.
Sprint state belongs to [ROADMAP.md](../../ROADMAP.md); implementation scope belongs to the
[completed plan](../exec-plans/completed/sprint-6.md). The [canonical catalog](catalog.md) retains all
existing truth tables, evidence requirements, applicability, and limitations unchanged.

## Approved policy choices

- `max_unused_access_key_days = 90` is an explicit value in a new versioned deployment profile,
  not a universal default or a rule constant. Missing required policy must fail closed.
- IAM-002 and IAM-003 severity: MEDIUM. IAM-005 and IAM-006 severity: HIGH.
- IAM-002 continues to use `stale_key_days` without changing existing profile content or meaning.
- These are project policy choices, not AWS or NIST mandates.

## Approved technical metadata

Evaluation version: `1.0.0` for each of the four newly executable controls. Category: IDENTITY;
assessment type: automated. Existing IDs, titles, and assessment units remain canonical.
The impact and guidance below are reporting metadata, not remediation handlers or permission to
change AWS. Operational actions require separate human authorization and dependency checks.

| Control | Impact | Guidance |
| --- | --- | --- |
| IAM-002 | An active long-lived credential beyond the organization's allowed age can extend exposure if compromised; age alone does not prove compromise. | Prefer temporary role credentials. Where a long-term key is still necessary, review consumers and rotate it through an approved change before retiring the old key. |
| IAM-003 | An active credential without recent recorded use can retain unnecessary access and exposure; last-use evidence does not establish business need. | Confirm ownership, consumers, and business need. Through an approved change, deactivate an unnecessary key, verify dependencies, and retire it; prefer temporary credentials for remaining workloads. |
| IAM-005 | A root access key exposes highly privileged programmatic credentials; presence does not prove exposure or use. | Investigate dependencies and replace root-key use with appropriately scoped temporary access. Have an authorized operator remove root access keys through a controlled change. Do not create root keys for testing. |
| IAM-006 | Missing root MFA removes a second sign-in factor where root sign-in credentials exist, increasing account-takeover exposure. | Have an authorized operator review root access and enable MFA where root sign-in credentials are retained. For centrally managed member accounts with root credentials removed, verify that posture; do not recreate credentials merely to satisfy this presence-only control. |

IAM-006 remains the accepted account-summary presence check, not an organization-aware root-access
assessment. It does not gain a new exception, PASS, or N/A path for centralized root management.
Its existing limitation must remain visible; broader root-access evidence is outside this slice.

AWS guidance sources, inspected 2026-09-27:

- [IAM security best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html):
  temporary credentials, dependency-aware key updates, and review of unused credentials.
- [Root user best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html):
  root-key avoidance, MFA, and centralized removal of member-account root credentials.

These sources support the approved operator guidance; they do not prescribe the project's
90-day threshold or severities. Canonical API evidence contracts are not redefined here.

## Approved framework mappings

Source: [NIST CSF 2.0, Appendix A, printed page 19](https://doi.org/10.6028/NIST.CSWP.29),
published 2024-02-26. Source content inspected on 2026-09-27. The relationships below are project
interpretations of credential-management and authentication outcomes, not official NIST mappings
of these project control IDs. The user approved these mappings before executable registration.

| Control | CSF reference | Scoped rationale |
| --- | --- | --- |
| IAM-002 | PR.AA-01 | Comparing active-key age with explicit organization policy contributes credential-lifecycle evidence; it does not prove safe credential distribution or complete identity management. |
| IAM-003 | PR.AA-01 | Assessing active credentials against a last-use policy contributes credential-lifecycle review evidence; recorded use does not establish authorization or business necessity. |
| IAM-005 | PR.AA-01 | Root access-key presence contributes evidence about management of privileged credentials; it does not establish management of every identity or root credential type. |
| IAM-006 | PR.AA-03 | Root MFA presence contributes root-authentication context; it does not establish hardware-only MFA, device health, or authentication coverage for all users and services. |

Mappings never determine technical results. Follow the existing
[framework change protocol](../frameworks/nist-csf-2.0.md#change-protocol).

## Approved version and compatibility treatment

- Add explicit control catalog release `aws-cloud-security-controls/0.3.0` for the existing five
  controls plus these four. Retain resolver support for exact `0.2.1`; no default-catalog switch.
- Retain the original `nist-csf/2.0` artifact, manifest, mappings, and bytes unchanged. It lacks
  PR.AA-01. Add a separately identified local subset release `nist-csf/2.0+subset.2` with its own
  reviewed artifact and manifest, covering PR, PR.AA, PR.AA-01, and PR.AA-03 for the four new mappings.
  The suffix identifies a project subset release, not a new NIST publication; source version
  remains official `2.0`. Preserve original framework identities for the five existing controls.
- The new control catalog can retain both framework releases through the existing
  `framework_catalogs` collection. Store source, source version, actual timezone-aware verification
  timestamp, rationale, and checksums using existing mapping provenance fields.
- Explicitly select the new catalog and a new organization profile version through the accepted
  local policy-file mechanism. Never rewrite historical profiles or reuse their versions.
- The relationship-proof extension remains bounded to these controls and must preserve the
  accepted execution-contract schema's semantics; no general expression language is needed.

## Approval and stopping point

Impact/guidance, evaluation versions, scoped mappings, and additive release identities are
approved. The initial preparation changed documentation only; the accepted 6B.1 implementation
subsequently added these four controls in opt-in catalog `0.3.0`. Whole-6B independent review,
final CI, and human merge acceptance passed before 6C began. IAM-004 remained a separate 6B.2
slice and is available only in later opt-in catalog `0.4.0` or newer.
