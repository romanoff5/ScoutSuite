# Task 12 / M09-B — offline viewer and local report trust boundary

Date: 2026-11-01. Scope: local report assets, AWS-facing report rendering sinks and the optional SQLite local API. No cloud credential use, live AWS calls, Azure/GCP collector changes or upstream PRs.

## Shipped changes, separate slices

**Slice 1 — locally reproducible assets.** The existing vendored binary `includes.zip` remains pinned by the repository revision and is never downloaded at report-viewing time. Entries are checked before extraction: only known vendor roots, no absolute/traversal, backslash, drive/colon, symlink, duplicate, oversize or corrupt files. Required local dependencies must exist. The generated JSON report uses relative local JS/CSS/fonts; the historical Font Awesome CDN fallback and legacy IE CDN references were removed. A restrictive meta CSP blocks network asset origins, embeds and forms, while permitting legacy inline registration/handlers. License/provenance attributions are documented in `M09_B_OFFLINE_ASSETS.md`.

**Slice 2 — contextual data handling.** The AWS account/provider header is constructed with text nodes for untrusted account labels; no dynamic `innerHTML` there. The IAM `displayPolicy` helper uses Handlebars HTML escaping for arbitrary policy keys, statements and strings while retaining only static formatting tags. `eval(JSON.stringify(entities))` is replaced with ordinary array copies. Display-only JSON rule helpers do not mutate the original report. Findings CSV exports prefix spreadsheet formula-like values with a literal quote to inhibit formula execution on opening. Legacy Handlebars templates and static routing/filtering remain in place.

**Slice 3 — local SQLite API.** It is no longer suitable as an anonymously readable HTTP endpoint: only `127.0.0.1:8000` is accepted; ZIP-independent SQLite header and file bounds are checked, symlinks rejected, the SQLite database is opened read-only, and JSON query paths/pagination/response sizes are bounded. The `Origin` check rejects remote web origins, and `Origin: null` is allowed only with a per-start unpredictable token required in `X-Scout-Viewer-Token`. A local `scoutsuite-results/scoutsuite_viewer_session.js` file is written on local server startup, and referenced only by the SQLite viewer. Cross-origin preflight does not itself disclose report contents. Standard JSON report mode never uses a server.

## Security limitations and compatibility

- CSP necessarily retains `script-src 'unsafe-inline'` for old inline Handlebars partial registration scripts and legacy event handlers. A full migration to event delegation and strict CSP with hashes/nonces is still needed. **This is not a claim of global XSS elimination**.
- Some existing report templates still use inline `javascript:` navigation and HTML string assembly. This task mitigates the identified high-risk untrusted account/policy injection paths and tests those precisely; all legacy templates are not yet independently audited.
- We have not reproduced a real-world browser exploit. Hostile synthetic policy/label payloads are for regression prevention only.
- Generated JSON reports should open from disk offline using bundled assets. SQLite reports require the explicit localhost API and a locally generated session file. Opening historical SQLite HTML directly without starting the authenticated API will fail closed; the legacy anonymous API is intentionally not supported. The current viewer API is fixed to port 8000. The token file must not be published with reports.
- The existing prebuilt `includes.zip` retains historical vendor versions. Dependencies and source hashes were not updated or re-vendored, and no byte-for-byte upstream reconstruction is asserted.
- Full real-browser navigation, mobile/offline rendering and CSP coverage across every cloud template require additional browser automation. The existing Azure/GCP report characterization and packaging tests still run, but are **not** equivalent to cross-cloud UI security verification.
- The local SQLite API is not a general HTTP data service and must not be exposed behind a reverse proxy or bound to a LAN interface. Report files and local output folders contain sensitive assessment evidence. Access control remains the responsibility of the local filesystem and operator.

## Validation criteria

Guarded Windows (Python 3.11.9) and Ubuntu (Python 3.11.18) offline CI, full preserved AWS/Azure/GCP report characterization, archive extraction and path traversal negatives, synthetic malicious policy/account strings, JS runtime with Node.js where available, read-only SQLite API navigation and pagination, disallowed CORS-origin and missing-token checks, packaging/inventory and independent remote branch verification.

No protected benchmark PDF or customer evidence should be committed. If required guards or changed-feature tests fail, keep the feature on this branch rather than merging into `master`.
