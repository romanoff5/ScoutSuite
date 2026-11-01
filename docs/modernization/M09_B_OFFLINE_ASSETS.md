# M09-B / slice 1 — offline viewer asset provenance

All runtime assets are packaged under `ScoutSuite/output/data` and copied to each generated report. **No CDN, remote CSS, remote scripts, remote fonts or runtime dependency acquisition** is required for JSON reports. The stock `includes.zip` is treated as a version-controlled, locally delivered vendor input. ZIP entry names are prevalidated before extraction; report and results files cannot be overwritten by an unexpected archive member. A member-based SHA-256 inventory may be generated during packaging to make archive contents auditable without live downloads.

## Third-party attributions and license review

- **Bootstrap** — bundled CSS/JS; upstream https://getbootstrap.com/ (MIT license).
- **jQuery** — bundled `jquery-3.3.1.min.js`; upstream https://jquery.com/ (MIT license).
- **Handlebars** — bundled `handlebars-v3.0.0.js`; upstream https://handlebarsjs.com/ (MIT license).
- **Font Awesome** — bundled fonts/icons/CSS; upstream https://fontawesome.com/license/free (code MIT, fonts SIL OFL 1.1, icons CC BY 4.0 depending on version). Verify the specific archived files before relicensing or repackaging.

These are attribution and license links in source documentation only, **not URLs accessed by the report viewer**. The existing historical binary vendor archive is retained intact for compatibility; this task does not assert that it was rebuilt bit-for-bit from audited original distribution artifacts. Full re-vendoring with verified upstream checksums is a follow-up. Do not remove required copyright/license notices when replacing libraries.

## Browser security boundary

A local Content Security Policy blocks remote active resources and object embeddings, but must retain `'unsafe-inline'` for the existing legacy inline Handlebars registration scripts and HTML event handlers. Therefore CSP is **defense in depth, not a complete XSS guarantee**. HTML escaping fixes are tested separately. For SQLite viewers the legacy client uses the local `127.0.0.1:8000` API; remote CORS access is blocked server-side.

Offline rendering is a browser/file-scheme behavior and cannot be inferred solely from a source-level no-CDN test. Missing full browser automation remains explicitly unverified.
