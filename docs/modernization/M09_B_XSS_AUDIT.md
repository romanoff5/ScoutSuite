# M09-B continuation: legacy Handlebars and DOM-XSS security audit

**Scope reviewed:** every one of the 225 checked-in `.html` files under
`ScoutSuite/output/data/html/`, plus all six first-party
`ScoutSuite/output/data/inc-scoutsuite/*.js` scripts, HTML-report
serialization and the M09-B offline viewer. AWS, Azure, GCP, Kubernetes,
OCI, Aliyun and DigitalOcean report templates were considered as **view
surfaces**; collectors and cloud permissions were not changed.

**Threat model:** all report values and optional/custom ruleset text are
untrusted for HTML rendering, including cloud resource names, IDs, routes,
tags, descriptions, references, rich findings, Kubernetes YAML/JSON and
previously saved local reports. The HTML wrapper and locally bundled third-
party JavaScript are trusted application code. Attacker-supplied report data
must not be able to execute JavaScript or fetch arbitrary resources when a
user opens the viewer.

## Findings and security changes

| Attack surface | Evidence in legacy templates | Remediation |
| --- | --- | --- |
| Unescaped rich text in dashboard | `{{{rationale}}}`, `{{{remediation}}}` rendered arbitrary rule text as markup | Converted to escaped `{{rationale}}` / `{{remediation}}` |
| Untrusted reference URL | Dashboard `href="{{this}}"`; Kubernetes role and owner reference `href="{{...}}"` | `safe_report_href` helper, strict URL protocol/path validation, second validation at DOM insertion |
| Resource IDs inside JavaScript URLs | `javascript:showObject('...{{id}}')`, `hideList`, `updateHash`, etc., across legacy provider templates | At the shared rendering boundary, strictly parse a finite allowlist of function names and string arguments; translate validated actions into delegated click handlers without `eval`; reject code expressions, escapes and quote breaking |
| Active HTML and DOM insertion | `processTemplate()` used raw compiled `innerHTML`; modal functions used raw jQuery `.html()` | Sanitize each compiled HTML fragment and modal before injection; strip scripts, frames, active external resources, inline event handlers, unsafe links and dangerous style constructs |
| Kubernetes code copy handler | Inline `onclick="copyCode('{{id_prefix}}')"` | Replaced with `data-scout-copy-code` + delegated static event listener |
| Hand-built Handlebars partial selector | Dynamic `template.innerHTML` | Use `textContent` after existing identifier validation |
| Side effects during viewing | `showObject`, `showIAMManagedPolicy`, `showIAMInlinePolicy`, `showS3Object` and ACL detail popup augmented saved objects | Use shallow display-context copies rather than adding keys to saved evidence |
| Historical intentional HTML | `{{{good_bad_icon ...}}}` produces an icon helper's fixed `<i>` element | Retained under a narrowly validated, static `SafeString` exception. The helper strips unsafe class-name characters |

## Browser boundary and design decisions

`inc-scoutsuite/report_sanitizer.js` is loaded before `scoutsuite.js`.
It parses rendered report fragments in an inert `<template>` element,
removes active content and unsafe attributes, and serializes only the
sanitized markup into the real DOM. Dynamic `javascript:` anchors are
never used as browser-executable URLs; the sanitizer rejects arbitrary
scripts and reconstructs allowlisted navigation as data-driven click
events. A malicious resource name containing a quote, backslash, JS
expression, newline or control character cannot escape a quoted argument:
the link is disabled rather than attempting lossy JavaScript escaping.
Navigation may therefore be disabled for unusual identifiers; the
underlying finding data is still visible.

Untrusted URLs are never rendered as arbitrary `javascript:` or `data:`
schemes. Explicit http/https references are user-clickable links, not
automatically fetched assets. Executable assets loaded from report data
are restricted to local `inc-*/` paths. External CDN fallbacks remain
removed by the initial M09-B change. `target=_blank` adds `noopener
noreferrer`.

The original report HTML contains static trusted inline JavaScript; a
strict `script-src` CSP without `unsafe-inline` requires a separate
migration of historical template bootstrap scripts and is **not** claimed.
This is a report-data XSS boundary, not a proof that the user may safely
run an intentionally modified malicious HTML application.

## Automated checks

`tests/test_m09b_xss_audit.py` checks the entire 225-template inventory
for new triple-mustache interpolation, executable-script interpolation,
unapproved data-controlled URL attributes and dynamic inline handlers.
It checks the central sinks and runs a Node-based adversarial parser
corpus, rejecting executable `javascript:` URLs, quote-breaking
payloads and hostile URL schemes. Where Chromium is available it launches
a headless, offline DOM test with injected `onerror`, `svg onload`,
`javascript:`, and `data:` payloads; it also asserts a valid navigation
action still works. Browser tests **explicitly skip** if Chromium is not
available; do not equate a skip with browser validation.

The full guarded offline CI and AWS/Azure/GCP preservation tests are
required on Windows and Ubuntu before integrating into `master`.
No live cloud calls or customer reports are involved.

## Scope limits and lifecycle

This audit is source-wide for the checked-in templates, not exhaustive
fuzzing of every possible cloud object, browser vendor/version, third-
party JavaScript dependency or plugin. In particular, some legacy
static report-template `onclick` handlers remain trusted bootstrap code
and a CSP refactor would require explicit compatibility testing.

**Previously exported reports are not retroactively patched.** Regenerate
HTML and re-export local assets using an updated ScoutSuite build before
opening old untrusted report files. The versioned RESULTS schema (v0/v1),
finding IDs, paths, and CIS 7.1.0 candidate mappings are unchanged.
Rollback by reverting the relevant feature commits on the fork; do not
rewrite shared `master` history.
