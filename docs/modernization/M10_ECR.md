# M10-E — Public ECR private-repository inventory (opt-in)

Select `--services ecr` explicitly. Core default service selection is
unchanged. Public ECR support is available without the optional private
provider modules. When a separately installed proprietary ECR extension
exists, it retains its historical precedence.

## API and completeness

Only `ecr:DescribeRepositories`, scoped by `registryId` to the
authenticated twelve-digit AWS account ID. Existing region discovery may
call `ec2:DescribeRegions`. At most 100 pages of 100 repositories each
are collected (10,000 records per region). A missing/invalid token,
unexpected registry, duplicate ARN, malformed response, access denial or
page/record limit is recorded as a collection issue; returned evidence is
not silently treated as complete. No cloud writes, image layers, image
contents, credentials, container source code, or vulnerability findings
are accessed.

Full repository ARN, name, registry ID, URI, creation time, encryption
configuration including KMS key, image scanning configuration, mutability
mode and its exception filters are preserved for actionable reporting.
This vertical slice does not call `GetRegistryScanningConfiguration`
or collect repository image lists. ScanOnPush alone does not establish
vulnerability scanning coverage: ECR enhanced scanning is configured at
the registry level, and image vulnerabilities are outside this slice.

## Rule / evidence

`ecr-repository-tags-mutable` flags only the confirmed plain `MUTABLE`
state. `IMMUTABLE` is secure only with respect to this *configuration*
check. `MUTABLE_WITH_EXCLUSION`, `IMMUTABLE_WITH_EXCLUSION`, absent and
unrecognized modes remain unknown, not compliant. Mutability can be
intentional for pull-through caches; findings require workflow context.
No CIS benchmark certification or comprehensive ECR security score.

## Verification and rollback

Synthetic Botocore Stubber, boundaries, error, partial, ordering,
account-scoping and rule-engine tests; actual offline HTML parser/browser,
packaging, Windows/Ubuntu tests and Azure/GCP preservation are required
before merging. No live AWS scan is claimed.

Revert this service slice to roll back. Omit `--services ecr` to avoid
new collection API calls.
