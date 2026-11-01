# M07 — deferred Azure/GCP preservation gate

Date: 2026-11-01. Baseline source: `612b9ab3f83021107563f2669efd7182f398ca7f`.

## Scope decision

M07 is **deferred**, not an Azure/GCP modernization milestone in this
AWS-only project. This change implements the roadmap's *lightweight
existing-interface/assets preservation* acceptance criterion only.
No Azure/GCP provider, SDK, collection, resource, rule or rendering
implementation changed; no default security findings or severity
definitions were modified.

The preservation snapshot is
[`tests/data/m07-provider-preservation.json`](../../tests/data/m07-provider-preservation.json).
It captures the existing repository Git blob IDs (with LF-normalized text)
for **193 Azure** and **213 GCP** Python/JSON assets. Of those, **81 Azure**
and **119 GCP** files are finding-rule definitions. It also records the
26 declared GCP/Azure dependency lines in the combined
`requirements.txt` without changing any SDK version.

The guarded offline suite now executes
[`tests/test_m07_deferred_provider_preservation.py`](../../tests/test_m07_deferred_provider_preservation.py)
which fails for an unexpectedly removed/added/edited provider file or
an SDK declaration change. Paths and hashes are checked from installed
test source data on both Linux and Windows; the test performs no cloud
SDK construction, authentication, subprocess or network call.

## Existing behavior verification

These **pre-existing** offline tests provide behavior evidence separate
from the snapshot:

- `tests/test_provider_catalogs.py`: imports and structural metadata,
  default rules and templates.
- `tests/test_characterization.py`: an actual Azure Storage and GCP
  Cloud Storage synthetic facade/resource/rule/report path, with safe
  and unsafe fixture cases and stable result IDs.
- `tests/test_azure_provider.py`: existing stubbed authentication modes.

These characterization samples are not complete Azure/GCP functional
coverage. Many rules have only catalog/parse coverage, not verified
secure/insecure cases. The manifest is a **drift detector**, not a
cryptographic supply-chain attestation, SDK security support claim or
cloud compatibility certification.

## Deliberate changes and rollback

A future separately authorized Azure/GCP modernization must name the
SDK, affected files and rule semantics, provide concrete compatibility
tests, and deliberately update affected snapshot entries. Do not run an
automatic rebaseline simply to make tests green. This gate remains
independent of subsequent AWS M08/M09/M10 work.

To revert M07, revert the manifest, preservation test and this note.
There are no scanner runtime changes to undo.

## Verification gate

Required: Windows Python 3.11.9 and Ubuntu Python 3.11.18 guarded offline
CI for the exact branch SHA, with provider characterization and installed
wheel/sdist packaging checks. Record the result before fast-forward merge
into the fork's `master`. Python 3.14, real Azure and GCP access, and
end-to-end full-cloud coverage are **not** asserted by this snapshot.
