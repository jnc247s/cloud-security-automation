# Sprint 6D.1 approved control metadata

Approved 2026-09-28. [ROADMAP.md](../../ROADMAP.md) owns state; the
[active plan](../exec-plans/active/sprint-6.md) owns scope. Preserve the
[canonical truth tables](catalog.md#net-003--security-group-permits-unrestricted-all-protocol-public-ingress).

Opt-in catalog `0.6.0` extends `0.5.0` with NET-003/004/005, evaluator `1.0.0`.
Earlier catalogs, framework bytes, default 0.2.1 and profile checksums remain unchanged.
NET-004 requires explicit versioned `high_risk_public_tcp_ports`; approved deployment values are
3306, 5432, 6379, 9200 and 27017. No code default is introduced. Explicit empty policy retains
canonical N/A; absent policy is rejected before collection and during recovery.

| Control | Severity | Impact and operator guidance | Mapping rationale |
| --- | --- | --- | --- |
| NET-003 | HIGH | All-protocol public ingress increases potential exposure. Review workload dependencies before an authorized change restricts public access. | PR.IR-01: broad-ingress configuration contributes network-access protection evidence, not reachability or full compliance. |
| NET-004 | HIGH | Public access to configured high-risk TCP ports increases potential exposure. Review workload dependencies before an authorized change restricts public access. | PR.IR-01: configured-port exposure contributes network-access protection evidence, not reachability or full compliance. |
| NET-005 | MEDIUM | Permissive default groups can allow unintended traffic. Review workload dependencies before an authorized change removes default-group ingress and egress rules. | PR.IR-01: default-group restrictions contribute network-access protection evidence, not proof of attachment or full compliance. |

These are project mappings/severities, not NIST assignments. Source:
[NIST CSF 2.0, Appendix A, printed page 20](https://doi.org/10.6028/NIST.CSWP.29), inspected
2026-09-28. Add separately identified local subset `2.0+subset.5` for PR.IR-01 and these mappings;
preserve every earlier framework artifact and mapping. Framework metadata never determines results.

Only facts from existing collectors are consumed. Same-scan owner/Region/provenance and required
VPC relationships must be proved. Unknown evidence is insufficient, never PASS or empty N/A.
The bounded proof uses execution schema `1.3.0`; earlier execution schemas retain their meaning.
NET-001/002 remain unchanged. No AWS calls, new permissions, collector changes, migrations,
remediation, frontend, deployment or NET-006 implementation are authorized.
