# Ridgepay RC1 field feedback — anonymized regression record (2026-11-02)

The private read-only RC1 report is **not** committed or uploaded here.
This document contains only aggregate observations and rule names.

## Analyzed real-run evidence

- 42 service objects in the result; 207 rules, 1,523 checked
  rule/resource pairs; 36 triggered rules, 120 flagged pairs.
- Exit code 0 with explicit `collection_status.complete=false`,
  40 recorded issues, and 80 rule assessments labeled incomplete.
- Installed scanner reports the previously merged RC1 runtime hotfix.
  The original failures `Unsupported rule evidence policy` and
  `Unsafe collection issue metadata` did not appear in this result.
- **Confirmed code defect:** `ecr-registry-not-enhanced-scanning`
  evaluated one BASIC scan configuration as insecure in
  `evaluation_summary` but returned `flagged_items=0`. The finding
  condition used a nonexistent `basic_scanning` field instead of the
  collected `scan_type`. The rule now compares `scan_type=BASIC`.
- The offline `tools/audit_scan_evidence.py` tool detects mismatches
  without printing account IDs, source paths, ARNs or resource data.
  It never reads AWS credentials or initiates cloud calls.
- Other recorded incompleteness came predominantly from AWS API denial
  or unavailable control-plane scope: Organizations, Macie, Identity
  Center, SSM baseline detail, Backup, Security Hub, S3 directory access
  points, Bedrock and Inspector coverage statistics. A successful
  process exit is **not** evidence of all-account coverage.
- One manually repeated S3 MRAP call from the scanned Region yielded
  `PermanentRedirect`; the integrated collector already uses the
  required `us-west-2` control-plane endpoint. No change to the
  collector is warranted by this follow-up.
- Inspector coverage statistics reported malformed/partial in the
  scanner while account enrollment was disabled and coverage enumeration
  was empty. The retry archive did **not** include a raw
  `ListCoverageStatistics` response, so no undocumented response shape
  should be inferred or simulated as a confirmed AWS defect.

## Acceptance

1. Synthetic ECR rule engine produces exactly one flagged item for
   BASIC, no flagged item for ENHANCED, and UNKNOWN evidence remains
   incomplete. Preserve the rule ID and old report schema.
2. Postscan verifier reproduces the report's count drift from a
   synthetic fixture, reports only rule identifiers and aggregate counts,
   and fails closed on malformed report.
3. Re-run Windows/Ubuntu Python 3.11/3.14 guarded CI. Do not use
   customer data or credentials in CI.
4. Treat published RC2 assets as immutable; any corrected wheel must
   receive a distinct version/build tag and checksum.
