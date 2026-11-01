# M03 final and M04 incremental acceptance evidence

Date: 2026-11-01. Fork: `romanoff5/ScoutSuite`. Starting base:
`15bcb1bc8301d82f48ab413d1a9e65cab8f3217f`.

## Implemented increments

- M04-A `be2db62`: AWS SDK client isolation by live run and session;
  cache hits do not create another client; disposal on cleanup.
- M04-B `74b96c1`: structured collection issues (denied,
  unsupported, failed, partial), scoped errors, incomplete findings
  and additive `collection_status` in RESULTS. Legacy fields remain.
- M04-C `63ed73a`: bounded async worker tasks and in-flight API calls.
  Explicit max retry count, backoff with jitter, cancellation preservation.
  Application retries disabled by default to avoid multiplying SDK retries.
- M04-D `87ba3f9`: optional `--strict-completeness` exit 201 when
  missing evidence or incomplete status; finite AWS SDK connect/read waits.
- M04 acceptance tests: report JSON serialization and direct CLI
  strict-exit behavior; synthetic timeout and unsupported pagination.

## Gates and explicitly unverified scope

All tests are offline under M01 protection. Each increment must pass
Windows Python 3.11.9 and Ubuntu Python 3.11.18 CI. Previous M03
Python 3.14 local regression required an external `pkg_resources`
compatibility path; updated M04 code has not been validated under 3.14.

Not yet completed: dedicated HTML completeness banner (M09);
full adapter-by-adapter timeout and pagination inventory (M05/M06);
cross-account real AWS runs; concurrent production scale tests;
strict-exit contract for every provider and unsupported SDK family.
No live credentials or customer reports were used.
