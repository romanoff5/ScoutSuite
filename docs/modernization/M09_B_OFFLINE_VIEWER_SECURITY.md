# M09-B: offline report viewer and read-only local API hardening

Source branch: `modernization/m09b-offline-viewer-security`.
Scope: shared report presentation and local SQLite report API; no AWS network actions, no Azure/GCP collector or rule changes.

## Security controls implemented

- HTML report template no longer references external Font Awesome fallback or deprecated remote IE shims. Its CSS/JS asset paths remain local.
- ZIP contents are verified before extraction: approved report prefixes, no absolute/parent path segments, backslash traversal, symlink/special-file entries or preexisting symlink targets. Entry count and declared uncompressed bytes are capped. The extraction is restricted to report assets.
- Dynamic EC2 traversals use `slice()`, not `eval`. The account label is assigned with `textContent`, not `innerHTML`. Dynamic template identifiers are validated before use. IAM-policy and rule helpers avoid deleting fields on shared result objects.
- The CherryPy API no longer installs permissive CORS. Read-only SQLite opens with `flag='r'`; the API restricts numeric pagination, nesting, keys, prototype-like path segments, and missing paths. The socket is loopback-only and browser Host/Origin checks reject cross-origin accesses. Errors are explicit rather than being interpreted as empty or compliant.
- An HTTP same-origin viewer endpoint is available at `http://127.0.0.1:8000/api/<report-filename>.html`, after starting the existing SQLite report server. The viewer serves only HTML and allowlisted static assets from the report directory, not `.db` or unrelated files. The SQLite client uses the current HTTP origin, not an unrestricted cross-origin localhost URL.

**Compatibility change:** opening a SQLite-backed report directly through `file://` is no longer supported. Serve it from the loopback API as described. Standalone JSON/JS HTML reports remain file-based. Existing finding IDs, standard mappings and report schema v0/v1 are unchanged.

## Validation and limitations

Run `python -m pytest -q tests/test_m09b_security.py`, existing guarded offline suite, lint and packaging on Windows and Ubuntu; test malicious ZIP entries, path and pagination inputs, default viewer exposure, no network asset requests, and preserved report objects.

This improves specific unsafe sinks, not a complete browser XSS proof: older legacy templates and inline JavaScript links still require systematic review. A local report viewer should only open data from trusted assessments, with no remote cloud credentials. Security fixes to shared report assets may affect deferred Azure/GCP visual templates; smoke checks are required before integration. Do not claim all browser execution paths safe without a full adversarial browser run.
