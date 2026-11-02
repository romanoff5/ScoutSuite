# M11 — Zero-warning modernization of GCP KMS, GCP Monitoring, and Azure SQL

Status: isolated migration branch created; implementation and CI verification pending. Do not merge to master on dependency changes alone.

## Verified starting point (2026-11-02)

- Master baseline: `5e09393fa50d12148d2d354ff92fbba35031acce`.
- Legacy pinned dependencies: `google-cloud-kms==1.3.0`, `google-cloud-monitoring==1.1.0`, `azure-mgmt-sql==1.0.0`.
- The documented warning budget totals 156 after 50 first-party regex warnings were fixed.
- Ubuntu and Windows baseline jobs completed successfully with the vendor-warning budget, NOT with zero warnings.
- `tests/test_m07_deferred_provider_preservation.py` blocks changes to all Azure/GCP providers and their dependency declarations. This must be adjusted deliberately, not removed.

## Implementation scope and compatibility contract

1. Upgrade the three SDKs and their compatible protobuf/Google namespace dependencies together. Resolve transitive requirements using a clean Python 3.11 environment on Ubuntu and Windows; produce a reviewed exact constraints snapshot. Do not manually guess a resolved dependency graph.
2. **KMS:** migrate old `google.cloud.kms` methods `location_path`, `key_ring_path`, `crypto_key_path`, and positional `list_key_rings` to supported `google.cloud.kms_v1` request contracts, while preserving existing discovery API operations for locations, keys and IAM policies, including pagination. Keep key ID, rotation period, purpose and IAM members unchanged.
3. **Monitoring:** migrate `google.cloud.monitoring` clients to `monitoring_v3`, use current request envelopes for `list_uptime_check_configs` and `list_alert_policies`, and handle proto-plus boolean values without assuming `.enabled.value`. Preserve alert conditions, monitored resources and report IDs.
4. **Azure SQL:** migrate `azure-mgmt-sql` to a supported release and verify *every* operation group invoked by `facade/sqldatabase.py`. In particular, check renamed database threat-detection/security-alert APIs, Entra ID administrators, auditing, vulnerability assessment, TDE, firewall rules and replication. Ensure the existing rule/parser fields are preserved or deliberately updated with tests.
5. Update M07 preservation only for explicitly approved changed provider paths and the three SDK declarations; retain original hashes in a migration ledger. All unrelated Azure/GCP provider files, default rules, templates and AWS code must remain protected.
6. Add credential-free real-SDK compatibility tests: constructor signatures and operation groups, request argument shapes, paged responses, missing permissions, absent data, false/true conditions, resource ID and report fields. Use strict mocks for transports, no live cloud calls, no reduction in test coverage.
7. Remove `LEGACY_VENDOR_WARNING_BUDGET` only after the upgraded dependencies prove clean. Require empty structured warning manifest, with warnings fully visible and without blanket suppression.

## Required acceptance gates before merge

- Fresh wheelhouse and dependency resolution on **Ubuntu 24.04 / Python 3.11.18** and **Windows 2022 / Python 3.11.9**.
- Full guarded offline suite, AWS/Azure/GCP preservation and characterization, SQLite HTTP, XSS browser tests, packaging, lint and dependency checks.
- CI logs show **0 warnings on both OSes** for the exact candidate SHA.
- No skipped tests, fake stub-only API checks, hidden SDK exceptions or silent false-clean results.
- Fast-forward to personal fork master only after both CI jobs pass; no upstream pull request.

## Risks detected in review

The existing M07 snapshot is an intentional immutability gate, not obsolete dead code. Removing it wholesale would weaken cross-provider regression control. In Azure SQL, successful SDK import does not establish that old operation groups remain callable, or that newer model fields can still be parsed by existing rule resources. New Google proto-plus types similarly require actual parser checks. These are acceptance blockers, not warning-filter issues.

## Implementation evidence (2026-11-02)

- Updated Cloud KMS to 3.17.0, Monitoring to 2.31.0 and Azure SQL to 4.0.0.
- Required Google Cloud Resource Manager 1.19.0 (1.14.0 required protobuf <6), protobuf 6.33.5,
  grpc-google-iam-v1 0.14.6, google-api-core 2.43.2 and grpcio-status 1.85.1.
  All versions were resolved in actual CI and are pinned in combined constraints.
- Frozen M07 hashes remain unchanged; the preservation test permits only six named provider
  paths plus three original SDK declarations. Compatibility tests run against installed SDKs.
- Removed CI's vendor warning budget: any warning now fails the structured warning gate.
- CI #41417478498 passed on Ubuntu Python 3.11.18 and Windows Python 3.11.9:
  **496 passed, 34 subtests passed, zero warnings** on the combined M10/M11 code;
  also lint, dependencies, real SQLite HTTP, XSS browser, packaging and preservation gates.
  Both jobs succeeded before the final Azure SQL signature-contract expansion.
- Subsequent compatibility hardening binds each of the 12 Azure SQL facade operations
  to the installed SDK's real callable signature with credentials and network disabled.
  The strict acceptance gate is the latest branch SHA, not merely this earlier successful run.
- No master merge before both Ubuntu/Windows runs pass at the final SHA.
