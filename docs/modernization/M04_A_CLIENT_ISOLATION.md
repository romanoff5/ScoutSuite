# M04-A — scoped SDK client lifetime (2026-11-01)

Base: `15bcb1bc8301d82f48ab413d1a9e65cab8f3217f`. Scope: AWS client cache only, with shared-core
context propagation and lifecycle cleanup. Azure/GCP adapters and security rules
are unchanged.

- The old `AWSFacadeUtils._clients` process-global dictionary was keyed only by
  service and region, allowing clients from different accounts to be reused.
  `setdefault()` also eagerly built a new SDK client on every cache hit.
- The replacement caches a client inside the active `RunContext`, keyed by the
  identity of the actual session, service and region. A lock ensures the first
  construction is single-flight even when workers run in parallel.
- The executor propagates ContextVars into SDK worker threads.
- Context cleanup closes cached clients. Without a managed context clients
  are constructed afresh, not cached across accounts.
- Tests use mock sessions only; there is no credential discovery or real API call.

Remaining M04: structured collection completeness in findings/reports; retry limits,
bounded queues and finite SDK timeouts; per-run errors and cancellation evidence.
These are *not* complete or implied by this commit.

Verification: GitHub Actions offline CI on Windows and Ubuntu must pass before
integration; record the run and its SHA in the final integration receipt.
