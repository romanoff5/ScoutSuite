# ScoutSuite fork RC3 — field-tested evidence consistency (2026-11-02)

Fork: romanoff5/ScoutSuite
Tag: fork-v5.14.0-m10-rc3
Version: 5.14.0+romanoff5.m10rc3

## Fixes relative to immutable RC2

- Corrects a confirmed real-scan false negative in the
  `ecr-registry-not-enhanced-scanning` rule: the original condition
  queried nonexistent `basic_scanning`; the ECR collector and evidence
  evaluator use `scan_type`, so BASIC was classified insecure without
  generating the expected finding. RC3 aligns the rule with `scan_type=BASIC`.
  Rule filename/ID, severity, default enablement and report schema remain
  unchanged. ENHANCED is not flagged; missing evidence remains unknown.
- Adds `tools/audit_scan_evidence.py`: a read-only, JSON-only parser of
  local ScoutSuite RESULTS (.js/.json) to detect divergent evidence-vs-finding
  counts. Prints only rule keys and aggregate counts, never account IDs,
  ARNs, resource names or raw report payloads. Optional
  `--fail-on-discrepancy` returns exit code 3 on inconsistency.
- Corrects the CloudTrail trail-absence finding's misleading rationale:
  recent API management events can still appear in Event History without
  an independently configured durable trail. The original rule ID and
  detection condition are unchanged; organization-wide visibility still
  requires separate evidence.
- Adds synthetic regression tests reproducing the real ECR false negative,
  clean/enhanced/unknown rule states and safe offline diagnostics.
- Retains all RC2 runtime stability, operational AWS evidence fail-closed
  behavior, 42-service default inventory, HTML/SQLite report protection,
  pinned runtime dependency closure and Windows installed-wheel gate.
- Windows RC3 installs side-by-side in `.venv-scout-fork-rc3`. The prior
  RC2 (`.venv-scout-fork-rc2`) and RC1/hotfix
  (`.venv-scout-fork`) can still be selected explicitly for rollback.
  Stable `.venv-scout` untouched.

## Evidence limitations and safety

The private customer archive was analyzed locally; no raw reports, credentials,
account IDs, resource names, internal IPs or ARNs were uploaded to GitHub or
baked into tests. Only synthetic equivalents are committed.

A real assessment exited 0 but was explicitly partial due to denied/unsupported
AWS API calls and incomplete Inspector statistics. No assertion of
organization-wide coverage, continuous RPO, successful ECR scanning of every
image, WAF effectiveness or compliance is made. Run the new offline evidence
audit after each read-only scan; it does not replace independent security
verification or eliminate genuine AWS permissions gaps.

No real client AWS scanning is performed by CI or installer. No container image
is published. Azure/GCP SDK modernization remains deferred. Stable .venv-scout
untouched. Public checksums are integrity evidence, not signed provenance.

## Acceptance and installation

RC3 can publish only after all Windows/Ubuntu Python 3.11/3.14 offline CI
jobs pass on the merged master SHA, including installed wheel, reporting/XSS
and Windows launcher smoke. A separate release workflow performs wheel/sdist,
installed distribution integrity, SBOM, manifest and checksum checks.
Read-only Ridgepay production preflight and coverage validation remain
separate authorized user actions.

See [installation, preflight and rollback](TASK14_INSTALL.md), and
[anonymized RC1 field evidence](RIDGEPAY_RC1_FIELD_FEEDBACK.md).
