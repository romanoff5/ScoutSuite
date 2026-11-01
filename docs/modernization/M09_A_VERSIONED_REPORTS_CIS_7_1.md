# M09-A: deterministic, non-mutating AWS reports and CIS v7.1.0 crosswalk

**Date:** 2026-11-01. Scope: AWS result serialization/validation and opt-in profile.
Azure/GCP collectors, rules and SDKs are unchanged.

## RESULTS schema

- **Unversioned / legacy v0** JS and SQLite RESULTS remain readable, including existing finding IDs, exception keys, filters, navigation paths and report-compatible structures.
- **v1** emits the additive top-level integer `report_schema_version: 1` for RESULTS only. JSON-as-JavaScript and SQLite must yield the same sanitized data and deterministic key ordering. The legacy JS assignment prefix `scoutsuite_results =` is unchanged.
- Version is validated when loading RESULTS. Unsupported or malformed versions fail explicitly (`UnsupportedReportVersion`), not as an empty collection. EXCEPTIONS and ERRORS payloads remain unversioned.
- Provider objects are **not mutated**. Historical private attributes (`credentials`, `profile`, `metadata_path`, `services_config`) plus private SDK state are excluded from output snapshots, not deleted from the caller.
- Nested resource dictionaries keep existing report keys and exception paths. A future sanitization project must separately address untrusted/user-provided strings and browser DOM insertion (M09-B), without silently stripping finding evidence.
- HTML partial and summary concatenation uses sorted template filenames, reducing filesystem-order nondeterminism.

## CIS source basis and licensing

The maintainer-supplied **CIS Amazon Web Services Foundations Benchmark v7.1.0 (2026-10-02)** is the reference for the opt-in partial crosswalk.
Additional user-supplied reference editions are: **CIS AWS Compute Services v2.0.0 (2026-06-26)**, **Database Services v2.0.0 (2025-12-16)**, **Storage Services v1.0.0 (2024-07-03)** and **End User Compute Services v1.2.0 (2025-07-01)**.

CIS licenses and references apply. **Do not copy, embed, redistribute, or commit any source PDF or benchmark control text.** The fork contains only short control identifiers and independently authored implementation metadata, not a benchmark reproduction. For publishing verbatim control texts, obtain permission from CIS Legal.

## Deliberately partial Foundations v7.1.0 coverage

Opt-in ruleset: `ScoutSuite/providers/aws/rules/rulesets/cis-foundations-7.1.0-partial.json`.

| Foundations v7.1 control ID | Existing ScoutSuite finding ID | Evidence limitation |
| --- | --- | --- |
| 2.4 | `iam-root-account-with-active-keys` | IAM credential evidence only |
| 2.5 | `iam-root-account-no-mfa` | Credential report may be incomplete |
| 2.8 | `iam-password-policy-minimum-length` | IAM users; excludes federated IdP password settings |
| 2.9 | `iam-password-policy-reuse-enabled` | IAM users only |
| 2.14 | `iam-managed-policy-allows-full-privileges` | Static policy syntax is not effective/attached permission proof |
| 4.2 | `cloudtrail-no-log-file-validation` | Trail inventory and per-region completeness required |
| 4.3 | `config-recorder-not-configured` | Per-region coverage still needs scope verification |
| 4.5 | `cloudtrail-no-encryption-with-kms` | Requires complete CloudTrail collection |
| 4.6 | `kms-cmk-rotation-disabled` | Only eligible customer-managed symmetric keys |
| 6.5 | `ec2-default-security-group-with-rules` | Rule-level network-traffic coverage limitations |
| 6.7 | `ec2-instance-imdsv1-enabled` | Existing EC2 instance inventory, unknown on denied/missing metadata |

The 11 entries are **candidate crosswalks**, not 11 controls verified compliant. Other Foundations recommendations, including manual controls, are **unassessed**; do not compute or advertise CIS v7.1.0 compliance percentage. A finding carries `standard_mappings` with `coverage: candidate` and `compliance_verified: false`. Legacy `compliance` metadata from existing finding definitions is retained for report compatibility, not upgraded or reinterpreted.

Compute v2.0.0 also references IMDSv2 and Lambda runtime lifecycle topics, but those are different benchmark controls; no automatic equivalence with Foundations 6.7 is asserted. The other three supplied benchmarks are reference-only pending individual scoped mappings.

The original `cis-1.2.0.json` remains unchanged. The partial v7.1.0 profile is **explicit opt-in**, not the default. Example use: `scout aws --ruleset cis-foundations-7.1.0-partial --no-browser` with a separately authorized assessment or an existing local report, and with normal credential/network restrictions.

## Acceptance and rollback

Test synthetic AWS findings, JS and SQLite v0/v1 round trips, deterministic serialization, secret exclusions and retained in-memory provider fields. Validate unchanged Azure/GCP fixtures and the offline CI on Windows and Ubuntu. No customer scans or live cloud calls.

Rollback: revert this task's commits, or use the earlier unversioned reader for old v0 reports. **New v1 reports require this reader or deliberate removal/migration of the additive schema metadata**; old readers may ignore the added key but cannot be guaranteed for all integrations.
