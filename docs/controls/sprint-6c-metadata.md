# Sprint 6C approved control metadata

Approved 2026-09-28. State belongs to [ROADMAP.md](../../ROADMAP.md); scope belongs to the
[completed plan](../exec-plans/completed/sprint-6.md). Preserve the [canonical truth tables](catalog.md).

## Decisions

Opt-in catalog `0.5.0` adds EC2-001 through EC2-004 to `0.4.0`. Evaluation version is `1.0.0`.
Earlier releases, defaults, profile serializers/checksums and historical policy remain unchanged.
EC2-002 accepts only canonical stable resource UUID strings in `public_ec2_exceptions`, matched
against the existing provider/account/service/type/scope/Region/instance identity. Bare instance
IDs, ARNs, wildcards and malformed UUIDs are rejected when EC2-002 is enabled, before collection
and during recovery. An explicit empty tuple approves no public instance. Old profiles without
EC2-002 retain their exact content. This is assessment policy, not a Finding Exception.

| Control | Severity | Impact and approved-change guidance | Mapping and limited rationale |
| --- | --- | --- | --- |
| EC2-001 | HIGH | Optional metadata tokens lack the IMDSv2-only safeguard; this does not prove credential theft. Check application compatibility before an authorized operator requires IMDSv2. | PR.PS-01: metadata configuration contributes secure configuration-management evidence, not complete configuration management. |
| EC2-002 | MEDIUM | An unapproved public IPv4 assignment increases potential exposure, not proof of reachability. Review business need and network dependencies before removing public addressing or approving the exact resource identity. | PR.IR-01: public-address policy contributes network-exposure context, not end-to-end access protection. |
| EC2-003 | MEDIUM | Unencrypted volume data lacks the EBS encryption safeguard. Plan and test an authorized encrypted replacement/migration with backups; do not claim in-place conversion. | PR.DS-01: volume encryption contributes data-at-rest evidence, not full confidentiality, integrity and availability. |
| EC2-004 | MEDIUM | A disabled Regional default can allow new unencrypted volumes. Review workloads and key access before an authorized operator enables the default; existing volumes are unaffected. | PR.DS-01: Regional default configuration contributes protection context for future volumes, not proof of existing-volume encryption. |

These are project severities and scoped interpretations of
[NIST CSF 2.0 Appendix A, printed page 20](https://doi.org/10.6028/NIST.CSWP.29), inspected
2026-09-28, not official NIST assignments or compliance claims. Mapping metadata does not affect
technical results. Add a separately identified local framework subset `2.0+subset.4`; do not
change old subset bytes. No scanner write capability or remediation handler is authorized.

## Integration boundary

Reuse source-aware execution schema `1.0.0` and retained 5A evidence. Validate exact discovery,
resource admission and snapshot content, and the four controls' applicability at engine/storage
boundaries without altering legacy contracts. EC2-004 is a Regional assessment-only account target,
not a collector resource or graph endpoint. Optional KMS and contextual topology do not decide
the encryption boolean. Missing required evidence is insufficient, never PASS or empty N/A.
No collector, AWS permission, route, authentication or migration change is planned.
