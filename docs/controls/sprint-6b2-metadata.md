# Approved 6B.2 metadata

Approved by the user on 2026-09-27. IAM-004 retains the exact
[canonical truth table](catalog.md#iam-004--iam-policy-grants-explicit-full-administrative-access).

- Severity: HIGH (project policy, not assigned by NIST).
- Evaluation version: `1.0.0`.
- Catalog: opt-in `0.4.0`; `0.2.1` remains default and `0.3.0` remains recoverable unchanged.
- Impact: literal unrestricted Allow statements can permit broad access when used as grants.
  A permissions boundary grants nothing; conditions and other policies can constrain access.
  This is a syntactic result, never proof of effective administrator access or compromise.
- Guidance: an authorized operator reviews usage and conditions, replaces unnecessary wildcards
  with narrowly scoped permissions through an approved change, and tests workload dependencies.
  The scanner performs no remediation.
- Mapping: NIST CSF 2.0 `PR.AA-05`, supporting least-privilege permissions-policy review only.
  It does not establish complete authorization management, separation of duties, or compliance.
  Source: [NIST CSWP 29](https://doi.org/10.6028/NIST.CSWP.29), Appendix A, printed page 20.
  A separately identified local framework subset preserves older reviewed artifact bytes.

No organization threshold is introduced. `enabled_controls` is the only profile input.
Incomplete evidence is never PASS. Conditions do not erase the literal match; NotAction and
NotResource do not substitute for Action and Resource. Boundary-only usage remains in scope.
