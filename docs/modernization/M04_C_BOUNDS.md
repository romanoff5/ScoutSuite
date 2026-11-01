# M04-C — bounded work and explicit throttle retries

Base: `74b96c123a0f3a45a4ec77c5a2f927b4f032b3d7`. Shared-runtime change; AWS, Azure and GCP preservation
tests must pass.

- `get_and_set_concurrently` and `map_concurrently` use a fixed number of
  worker tasks instead of one task for every resource. The number of queued
  work items can be large, but the scheduler does not allocate an asyncio
  task per item; its queue is a lazy iterator.
- `run_concurrently` limits SDK operations in flight with the per-run
  `asyncio.Semaphore` in RunContext. ThreadPoolExecutor remains bounded by
  max_workers.
- Existing botocore SDK retries are not multiplied: application-level
  retries default to **one attempt**, even on throttling. Explicit
  `max_attempts` (1..10) uses exponential backoff capped at 60 seconds
  before jitter, limited to recognized throttling. Cancellation is not
  retried.
- Child task failures record a sanitized `ChildTaskError` and preserve
  incomplete collection status instead of silently disappearing.
- Fake-clock and bounded-queue tests use synthetic callbacks only.

Remaining: enforce botocore per-client finite connect/read timeouts and
max_attempts in service adapters (M04-D); opt-in strict exit codes and
viewer completeness banner (M04/M09), cross-cloud real environment
characterization. These remain unverified.
