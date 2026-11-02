# M10: evidence depth — Identity Center, SCP, Backup, Macie

Scope: read-only AWS configuration and metadata during the normal AWS scan. No mutations, secret values, object contents, Macie findings or sensitive occurrence retrieval.

## IAM Identity Center and Organizations

Collect permission sets, inline/managed/customer-managed references, permissions boundaries, account assignments and Identity Store principal e-mails. For each account, collect the SCP inheritance chain (account → OU → root) and attached policy documents via `organizations:ListParents`, `ListPoliciesForTarget`, `DescribePolicy`. Missing access, invalid documents, missing roots or depth limits produce `partial`. Policy identifiers, ARNs, account contacts and other remediation evidence are retained untruncated.

`admin_candidate` and `broad_permissions_candidate` are **not** proof of effective permissions. SCPs impose constraints but do not grant privileges. Fully effective access also depends on provisioned AWSReservedSSO roles, identity-based policies, permissions boundaries, session/resource policies, conditions, explicit denies, RCPs where applicable, and resource/action context. Cross-account policies cannot be proven from an organization management account using read-only SSO inventory alone. `effective_permissions_verified` therefore remains `false`; the report exposes the collected SCP evidence and the missing proof.

Additional read-only permission requirements: `organizations:ListParents`, `organizations:ListPoliciesForTarget`, `organizations:DescribePolicy` in the Organizations management/delegated account, with appropriate organization visibility.

## AWS Backup tag-based selections

Evaluate `ListOfTags` with OR and `Conditions` with AND, including `StringEquals`, `StringLike`, `StringNotEquals`, `StringNotLike`, against verified tags of **observed protected resources** and separately discovered tagged resource candidates. Respect `NotResources` exclusions and resource patterns. `Resources` and `ListOfTags` are combined using OR; `Conditions` constrain the result using AND. Missing tag evidence still produces `unknown` unless an ARN branch independently establishes a match. The match is observational, never proof that the plan ran successfully for every possible resource.

Use `resourcegroupstaggingapi:GetResources` with `ResourceARNList` in batches of at most 100 ARNs. AWS does not return untagged/unsupported resources; absence of a returned ARN is **not** proof of empty tags. The collection explicitly records unknown ARNs, failed calls, and unresolved selection matches. `ListProtectedResources` and completed `ListBackupJobs` are independent observations with their own history/coverage limits. For each tag key used by a selection, perform bounded and paginated `GetResources(TagFilters=[{'Key': key}])` discovery. Match candidate ARNs against selection expressions and correlate with protected-resource inventory. Emit possible gaps for tag-selected resources with no reported recovery point only when the protected inventory is complete; do not claim they are definitely required to be protected without verifying AWS Backup resource-type support and opt-in. Untagged resources and unsupported Tagging API types remain outside this discovery scope.

Additional read-only permission requirement: `tag:GetResources`. Some AWS services need service-specific tag APIs for authoritative absence-of-tags verification; this is not implemented here.

## Amazon Macie job execution

`DescribeClassificationJob` exposes status, last execution, last-run access error state, number of runs and approximate objects remaining. A completed one-time job (`COMPLETE`) or finished recurring run (`IDLE`) with recorded execution, at least one run and `lastRunErrorStatus.code=NONE` is marked as a completed execution without reported access errors. It is **not** evidence that all objects in a particular bucket were classified, nor that sensitive data was absent.

Link S3 bucket inventory's `lastJobId` to known jobs when available. Never infer per-object classification success from job state alone. `classification_results_verified` stays `false`; the report keeps full relevant identifiers, timestamps, errors and status. Do not call `GetFindings`, `GetSensitiveDataOccurrences`, S3 `GetObject` or `GetResourceProfile` as part of this metadata-only implementation.

## Validation / release gates

- Tests: `tests/test_m10_evidence_depth.py`, plus the existing M10 Identity Center, Organizations, Backup and Macie suites.
- Run offline CI on Ubuntu/Python 3.11 and Windows/Python 3.11 before merge.
- Unknown/denied/partial collection must never be reported as clean or compliant.
- Keep reports offline, escaped, no raw HTML insertion, no truncation of identifiers or diagnostic e-mails.
