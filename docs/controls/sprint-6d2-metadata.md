# Sprint 6D.2 approved control metadata

Approved 2026-09-28. [ROADMAP.md](../../ROADMAP.md) owns state; the
[active plan](../exec-plans/active/sprint-6.md) owns the stacked workflow and scope.
The [NET-006 contract](catalog.md#net-006--required-vpc-flow-logs-are-missing) owns its truth table.

Opt-in catalog `0.7.0` extends `0.6.0` with NET-006, MEDIUM severity, evaluator `1.0.0`.
Use extended profile schema `2.0.0` with explicit nonempty values:

- `vpc_flow_log_required_environments`: `["production"]`
- `acceptable_vpc_flow_log_traffic_types`: `["REJECT", "ALL"]`

These are approved deployment choices, not code defaults. Environment key/value comparison is
case-sensitive. Missing policy is rejected before collection and on exact-profile recovery.
Earlier catalogs, framework artifacts and default catalog `0.2.1` are unchanged.

Missing required VPC Flow Log configuration reduces network-activity visibility. An authorized
operator should review dependencies and costs before enabling VPC Flow Logs. No AWS writes or
remediation execution are included. The PR.PS-04 project mapping contributes log-generation
configuration evidence only, not delivery, retention or continuous-monitoring assurance.
Source: [NIST CSF 2.0, Appendix A, printed page 20](https://doi.org/10.6028/NIST.CSWP.29),
inspected 2026-09-28. Independently checksummed local subset `2.0+subset.6` carries this mapping;
framework metadata never determines PASS or FAIL.

Execution schema `1.4.0` is restricted to the bounded VPC/Flow Log strategy. Complete populations,
source-bound facts and exact zero-or-more `HAS_FLOW_LOG` membership prove both presence and absence.
Missing edges for observed matching logs are insufficient, not a false FAIL. Non-VPC logs do not
satisfy coverage. Flow Log discovery covers the collection account; an external-owner VPC cannot
use it as proof of that owner's complete logging configuration and remains insufficient.

Existing collectors admit only ACTIVE Flow Logs; unsupported/transitional status remains incomplete
evidence rather than being reinterpreted as an empty result. Complete empty VPC discovery uses the
accepted account-fallback N/A contract. No collector, permission, migration, generic route,
authentication, default-policy or later-slice change is included.
