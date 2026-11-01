# M04-B — additive completeness metadata and per-run errors

Base: `be2db62de0fba04dda64fa38602b20dd710f93af`. Scope: no change to Azure/GCP collectors or rule catalogs.

The new serialized provider `collection_status` field contains:
`version`, `status`, `complete`, `checked_items`,
`evidence_evaluated`, `compliance_verified` and a list of sanitized
`issues` (`status`, `scope`, `reason_code`). Zero evaluated checks
never mean verified compliance. Known denied, unsupported, timeout and
malformed AWS pagination responses are recorded as incomplete. A rule
evaluation exception marks the affected finding as `assessment_status:
incomplete` rather than silently reporting zero flagged resources.

Legacy finding fields and default exit codes remain unchanged. Runtime
errors are scoped to the active RunContext; legacy global ERRORS_LIST
remains the fallback for standalone calls. The existing HTML viewer does
not yet display a dedicated completeness banner. This metadata is
machine-readable in RESULTS but presentation work belongs to M09.

Pending: bounded work and SDK timeout policy, fake-clock throttling/backoff,
explicit strict-completeness exit switch, and full report UX. Do not
interpret this increment as complete M04 until those gates pass.
