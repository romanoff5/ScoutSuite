# AWS evidence completeness and coverage matrix

Scout Suite writes a versioned `collection_status.coverage_matrix` into its
normal AWS RESULTS file and displays it in **Execution Details** in the HTML
report. The matrix is deliberately **not** a compliance score.

## Row identity and interpretation

Each row corresponds to an AWS service and a Region. Global services use
`global`; when regional discovery is incomplete, `undetermined` or the
explicitly selected Region is preserved. Explicitly requested Regions not
returned by discovery are shown as `UNKNOWN`; `--excluded-regions` entries
are shown as `SKIPPED` rather than silently disappearing. Services omitted by `--services` or
`--skip-services` are visible as `SKIPPED` when rules exist for them.

| Status | Meaning |
| --- | --- |
| `OBSERVED_COMPLETE` | Observed SDK responses succeeded and at least one evidence-policy resource was evaluated without a recorded gap; not a complete AWS control audit |
| `PARTIAL` | Collection issue, denied/failed API among successful calls, explicit collector gap, or unknown evidence |
| `DENIED` | Access denied and no independently observed successful API/evidence in that Region |
| `UNKNOWN` | No complete API evidence (including missing or failed region discovery) |
| `NOT_ASSESSED` | APIs returned data but no evidence-policy resource evaluation was observed |
| `SKIPPED` | Service was not selected for the scan |

`zero_findings_interpretation=NOT_VERIFIED_CLEAN` when a row with no findings
is not `OBSERVED_COMPLETE`. Even on `OBSERVED_COMPLETE`,
`compliance_verified=false` and `clean_result_verified=false`.

## Counting and provenance

- `inventory_records_observed` is the sum of available resource-type counters
  in the report. It is **not** a deduplicated asset count and may be null.
- `checked_resources` counts distinct paths actually processed by
  evidence-policy classifiers; rules without evidence policies are not included.
- `unknown_resources` counts distinct paths that received an unknown evidence
  classification; checked/unknown counts can overlap when different policies
  evaluated the same path.
- `flagged_rule_items` counts matched rule instances in that Region, not
  distinct attack paths.
- `api.success` counts observed successful Botocore responses, not logical
  operations, unique resources, or fully fetched paginated inventories.
- `api.absent` counts narrowly recognized, expected negative configuration
  answers (e.g., an absent S3 encryption configuration). It is not a failure.
- `api.denied`, `failed`, and `unsupported` retain distinct outcomes.
- `api_operations` records only SDK operation names and numeric counters:
  no arguments, credentials, resource IDs, or response bodies are serialized.
- `skipped_checks` counts enabled rules belonging to unselected services.
- `collector_gaps` represents explicit collection/inventory partial status
  fields from the regional resource tree.
- `collection_issues` retains safe diagnostic reason codes. Legacy collectors
  without Region metadata conservatively degrade every Region for their
  service and mark `issues_without_region=true`.

## Known boundaries

An API response can succeed while a downstream collector drops a resource.
The matrix therefore combines API observations with collector gap signals and
rule-evidence UNKNOWN. It cannot guarantee that every AWS API and resource type
was enumerated, especially for legacy collectors, clients not created through
`AWSFacadeUtils.get_client`, or missing permissions that prevented an API
call from being attempted.

After an incomplete Region, the service-wide dashboard and zero-finding rules
are marked incomplete rather than green. Existing findings remain visible.
`--strict-completeness` can reject such reports; a non-strict scan still
produces the JSON/HTML report with the explicit limitations.

All counters and issue attribution are per assessment RunContext. Local offline
replay retains the saved matrix, rather than inventing new live AWS API results.
