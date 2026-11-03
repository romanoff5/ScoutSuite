# ScoutSuite fork RC9: evidence gaps found in the RC8 field run

**Version:** `5.14.0+romanoff5.m10rc9`
**Tag:** `fork-v5.14.0-m10-rc9`
**Scope:** the `romanoff5/ScoutSuite` fork only. Nothing goes upstream or to
PyPI, and no production cloud resource is changed.

## Changes since RC8

RC9 closes the gaps that the RC8 field review turned up. The fix tip is
`e7f40d528e7ff94e1b9d5ae934a103d20b25e28f`.

- **"Not in use" and Lambda.** A service whose inventory was fully collected
  and is empty now shows "Not in use", even when it has no rules. In RC8,
  Lambda, CodeBuild, DynamoDB, ElastiCache, EMR and Direct Connect showed
  "Not assessed". Failed or unsupported collection still shows
  "Incomplete"/"Not assessed".
  - The deprecated-runtime rule addressed `lambda.` instead of the report key
    `awslambda.`, so it never ran. A new test checks that every AWS rule path
    starts with a report service key.
  - Inventory-listing failures in CodeBuild, Direct Connect, DynamoDB, EMR and
    Lambda are now recorded as collection issues.
  - CodeBuild `ListProjects` is paginated; it used to stop at 100 projects.
- **Secrets Manager.** Four new rules: rotation disabled, secret not accessed
  for 90 days, resource policy open to any principal, and cross-account
  policy.
  - Denied `DescribeSecret`/`GetResourcePolicy` calls are recorded and make the
    affected evidence UNKNOWN. Before, a denied policy read looked like "no
    policy".
  - `GetSecretValue` is never called.
- **Secrets in configuration.** EC2 reports no longer store raw user data, and
  `user_data_secrets` no longer holds the matched values, which included whole
  private-key blocks. Lambda reports no longer store environment variable
  values.
  - A shared detector keeps only the type, the line or variable name, and a
    masked preview. AWS access key IDs are kept in full, because they are
    identifiers.
  - New rules: `awslambda-function-env-secrets` and
    `ecs-task-definition-environment-secrets`.
  - Lambda environments are read from `ListFunctions`, so one
    `GetFunctionConfiguration` call per function is gone.
- **WAF on internet-facing ALBs.** New `wafv2:GetWebACLForResource` evidence
  per ALB. Security groups now keep their `PrefixListIds`.
  - Rule `elbv2-internet-facing-alb-without-waf` flags only an ALB with no AWS
    WAF whose listener ports are open to `0.0.0.0/0` or `::/0`; any external
    WAF in front of such an ALB can be bypassed.
  - ALBs restricted to CloudFront's prefix list or to catalogued
    Cloudflare/Fastly/Akamai/Imperva/Gcore ranges are reported as "external
    WAF likely" and not flagged.
  - At start-up the scanner refreshes the providers' published range lists
    over HTTPS with strict validation. If the refresh fails, it prints a
    warning and uses the bundled ranges; the scan does not stop.
    `--no-cdn-range-update` disables the refresh.
- **Opt-in external WAF check through public DNS.** `--external-waf-dns` and
  `--waf-domains` resolve ACM and explicitly listed domains with the system
  resolver only. They report whether each domain goes through a CDN/WAF,
  points straight at an ALB, points elsewhere, or does not resolve, and list
  every checked domain.
- The report E2E gate now also covers the new Secrets Manager, Lambda
  environment, ALB WAF and DNS views with hostile strings, and checks that a
  planted secret value is absent from the page and from the report data files.
- Compatibility:
  - Fields are additive, and existing rule IDs are unchanged. The EC2
    user-data rule keeps its ID and `id_suffix`, so existing exceptions still
    match.
  - The meaning of three fields changes: `user_data_secrets` is now a list of
    masked detections, `env_variables` now holds names mapped to redacted
    stand-ins, and the legacy `rotation` boolean is `true` only when rotation
    is verified as enabled.
  - Old reports with raw user data or environment values show a re-scan note
    instead of the values.
- `ForkRc8` through `ForkRc1` and `Stable` remain explicit rollback choices.
  The published RC8 release is kept immutable.

## Release and acceptance gates

- All four exact-commit Offline CI jobs pass: Ubuntu and Windows, Python 3.11
  and 3.14. They run the AWS/Azure/GCP synthetic contracts, XSS, SQLite and
  report checks, and the Windows installer/selection tests.
- The Playwright E2E gate still skips Windows/Python 3.11 under the narrow,
  documented exception. The same interpreter passes locally, which points at
  the runner image. The root cause is still open and is now targeted for
  RC10.
- The wheel and sdist are built independently from the final `master` SHA.
  The release also gets an installed smoke test, distribution-byte
  verification, an SBOM/manifest and verified SHA256SUMS.
- The release workflow refuses a SHA that does not include the RC7, RC8 and
  RC9 fix commits. The GitHub prerelease is never overwritten.
- The client field gate is separate: a new authorized single-account,
  single-Region scan. Compared with RC8, expect:
  - empty, fully collected services shown as "Not in use";
  - Secrets Manager findings where rotation is off;
  - `elbv2-internet-facing-alb-without-waf` where an internet-facing ALB has no
    AWS WAF and is open to the world;
  - no raw user data or environment values in the report files.
  No real client AWS scanning is performed by CI or installer.
- Incomplete, denied or unsupported evidence never becomes a clean PASS. "External WAF likely" is an
  inference from source ranges, not a verified WAF policy. DNS observations are informational.
- CIS AWS Foundations v7.1.0 is a partial candidate mapping, not
  certification. Azure/GCP SDK modernization remains deferred.
  No container image is published. Stable .venv-scout untouched.
- SHA256SUMS and the manifest are integrity metadata hosted in the same
  place, not independent cryptographic signatures.

See [installation and rollback](TASK14_INSTALL.md). The release contains no
confidential customer reports, AWS account IDs or credentials.
